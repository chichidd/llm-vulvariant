from pathlib import Path
from types import SimpleNamespace

import scanner.agent.finder as finder_module


class DummyLLM:
    def __init__(self):
        self.config = SimpleNamespace(max_tokens=128)
        self.context_limit = 4096
        self.token_compute = SimpleNamespace(apply_chat_template_len=lambda messages: 10)

    def chat(self, *args, **kwargs):
        raise RuntimeError("not expected")


class DummyToolkit:
    def __init__(self, repo_path, **kwargs):
        self.repo_path = repo_path

    def set_memory_manager(self, memory):
        self.memory = memory

    def set_software_profile(self, software_profile):
        self.software_profile = software_profile

    def get_available_tools(self):
        return []


class DummyMemory:
    def __init__(self):
        self.summary_called = False
        self.markdown_called = False

    def generate_summary(self):
        self.summary_called = True

    def save_markdown(self):
        self.markdown_called = True

    def get_progress(self):
        return {
            "completed": 1,
            "total_files": 2,
            "findings": 0,
            "priority_1": {"completed": 1, "total": 1},
        }

    def is_critical_complete(self):
        return True



def _make_finder(monkeypatch, tmp_path=None):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    llm = DummyLLM()
    software_profile = SimpleNamespace(version="target123", modules=[])
    vuln_profile = SimpleNamespace(cve_id="CVE-2025-0001", to_dict=lambda: {"cve_id": "CVE-2025-0001"})
    return finder_module.AgenticVulnFinder(
        llm_client=llm,
        repo_path=Path("/tmp/demo"),
        software_profile=software_profile,
        vulnerability_profile=vuln_profile,
        max_iterations=5,
        verbose=False,
        output_dir=tmp_path,
    )


def test_extract_complementary_summary_structured(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    summarized = {
        "content": {
            "summary": "checked key path",
            "reasoning": {
                "motivation": "high-risk module",
                "analysis": "user input reaches sink",
                "conclusions": ["possible vuln"],
            },
            "failed_attempts": [{"what": "path A", "why_failed": "sanitized"}],
            "next_step_insights": ["inspect parser"],
        }
    }

    text = finder._extract_complementary_summary(summarized)

    assert "Summary" in text
    assert "Reasoning" in text
    assert "Failed Attempts" in text
    assert "Next Steps" in text


def test_extract_complementary_summary_non_dict_fallback(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    assert finder._extract_complementary_summary({"content": "plain text"}) == "plain text"


def test_get_user_message_iteration_uses_progress_context(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    captured = {}

    def fake_build_intermediate_user_message(scanned_files, findings, progress_info):
        captured["scanned_files"] = scanned_files
        captured["findings"] = findings
        captured["progress_info"] = progress_info
        return "intermediate"

    finder.memory = SimpleNamespace(
        get_progress=lambda: {
            "completed": 3,
            "total_files": 10,
            "findings": 1,
            "priority_1": {"completed": 1, "total": 2},
            "priority_2": {"completed": 1, "total": 3},
        },
        get_pending_files=lambda max_priority=2: ["a.py", "b.py"],
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [{"file": "x.py", "type": "cmd", "confidence": "high"}],
    )

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    msg = finder._get_user_message(iteration=1)

    assert msg == "intermediate"
    assert captured["scanned_files"] == ["done.py"]
    assert captured["findings"][0]["type"] == "cmd"
    assert "3/10 files scanned" in captured["progress_info"]


def test_run_stops_when_assistant_says_analysis_complete(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "Analysis complete"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 1
    assert result["vulnerabilities"] == []


def test_run_hits_max_iterations_without_stop(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_iterations = 2

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 2


def test_finalize_memory_triggers_summary_and_markdown(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    memory = DummyMemory()
    finder.memory = memory

    finder._finalize_memory()

    assert memory.summary_called is True
    assert memory.markdown_called is True
