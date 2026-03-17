from pathlib import Path
from types import SimpleNamespace

import scanner.agent.finder as finder_module


class DummyLLM:
    def __init__(self):
        self.config = SimpleNamespace(max_tokens=128)
        self.context_limit = 4096
        self._last_usage_summary = {}

    def chat(self, *args, **kwargs):
        raise RuntimeError("not expected")

    def get_last_usage_summary(self):
        return dict(self._last_usage_summary)


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

    def format_progress_info(self):
        progress = self.get_progress()
        return (
            f"{progress['completed']}/{progress['total_files']} files scanned, "
            f"{progress['findings']} findings. "
            f"Priority-1: {progress['priority_1']['completed']}/{progress['priority_1']['total']}, "
            f"Priority-2: {progress.get('priority_2', {}).get('completed', 0)}/"
            f"{progress.get('priority_2', {}).get('total', 0)}."
        )

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
        format_progress_info=lambda: (
            "3/10 files scanned, 1 findings. "
            "Priority-1: 1/2, Priority-2: 1/3."
        ),
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


def test_run_stops_when_assistant_emits_completion_json(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    def fake_run_turn(iteration):
        finder.conversation_history.append(
            {
                "role": "assistant",
                "content": (
                    "{\"analysis_complete\": false, \"summary\": \"partial\"}\n"
                    "{\"analysis_complete\": true, \"summary\": \"scope done\"}"
                ),
            }
        )
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


class _ToolAwareToolkit:
    def __init__(self):
        self.executed = []

    def get_available_tools(self):
        return [{"type": "function", "function": {"name": "mock_tool"}}]

    def execute_tool(self, tool_name, parameters):
        self.executed.append((tool_name, parameters))
        return SimpleNamespace(success=True, content='{"status":"ok"}', error=None)


class _UsageDrivenLLM:
    def __init__(self, responses, input_tokens, *, context_limit=4096, max_tokens=256):
        self._responses = list(responses)
        self._input_tokens = list(input_tokens)
        self._response_index = 0
        self._last_usage_summary = {}
        self.context_limit = context_limit
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.chat_calls = 0

    def chat(self, messages, tools=None, **kwargs):
        _ = messages
        _ = tools
        _ = kwargs
        self.chat_calls += 1
        response = self._responses[self._response_index]
        input_tokens = self._input_tokens[self._response_index]
        self._response_index += 1
        self._last_usage_summary = {
            "selected_model_usage": {
                "input_tokens": input_tokens,
                "output_tokens": 11,
                "context_window": self.context_limit,
            }
        }
        if isinstance(response, Exception):
            raise response
        return response

    def get_last_usage_summary(self):
        return dict(self._last_usage_summary)

    def get_last_request_input_tokens(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("input_tokens", 0)

    def get_last_request_output_tokens(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("output_tokens", 0)

    def get_last_request_context_limit(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("context_window", 0)


def _tool_call(name="mock_tool", arguments="{}"):
    return SimpleNamespace(
        id="tool_1",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def test_run_turn_uses_api_usage_to_stop_before_next_request(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert finder.llm_client.chat_calls == 1
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2].content == "need tool"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_reserves_completion_budget_when_context_limit_matches_max_tokens(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 65536
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            )
        ],
        input_tokens=[128],
        context_limit=65536,
        max_tokens=65536,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert finder.llm_client.chat_calls == 1
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2].content == "need tool"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_commits_progress_when_next_request_hits_context_limit(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            RuntimeError("maximum context length exceeded"),
        ],
        input_tokens=[1200, 0],
        context_limit=4096,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 2
    assert finder.llm_client.chat_calls == 2
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2].content == "need tool"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_treats_empty_tool_calls_as_completed_turn(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="Analysis complete",
                reasoning_content=None,
                tool_calls=[],
            )
        ],
        input_tokens=[512],
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert finder.llm_client.chat_calls == 1
    assert finder.toolkit.executed == []
    assert finder.conversation_history[-1].content == "Analysis complete"


def test_run_invalid_critical_stop_mode_falls_back_to_min(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="unexpected",
        verbose=False,
        output_dir=None,
    )
    finder.memory = DummyMemory()

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert finder.critical_stop_mode == "min"
    assert result["iterations"] == 1
