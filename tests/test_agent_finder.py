import json
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
        self.completed = []

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

    def mark_file_completed(self, file_path: str, reason: str = ""):
        self.completed.append((file_path, reason))


class _CaptureScanSignatureMemory:
    def __init__(self, output_dir, llm_client=None):
        self.output_dir = output_dir
        self.llm_client = llm_client
        self.initialize_kwargs = None
        self.memory = SimpleNamespace(file_status={})

    def initialize(self, **kwargs):
        self.initialize_kwargs = dict(kwargs)
        return False


class _LLMWithFullConfig:
    def __init__(self):
        self.config = SimpleNamespace(
            provider="provider-x",
            model="model-x",
            base_url="https://api.example.com",
            temperature=0.2,
            top_p=0.9,
            max_tokens=1536,
            enable_thinking=True,
        )



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


def test_finder_defaults_max_tokens_from_llm_client(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    assert finder.max_tokens == 128


def test_init_memory_tracks_scan_signature(monkeypatch, tmp_path):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    monkeypatch.setattr(finder_module, "AgentMemoryManager", _CaptureScanSignatureMemory)
    monkeypatch.setattr(
        finder_module,
        "embedding_model_artifact_signature",
        lambda model_name: {
            "resolved_model_path": f"/models/{model_name or 'default'}",
            "artifact_hash": "artifact-hash",
        },
    )
    monkeypatch.setitem(
        finder_module._scanner_config["module_similarity"],
        "threshold",
        0.8,
    )

    finder = finder_module.AgenticVulnFinder(
        llm_client=_LLMWithFullConfig(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=12,
        stop_when_critical_complete=True,
        critical_stop_mode="min",
        critical_stop_max_priority=1,
        verbose=False,
        output_dir=tmp_path,
        languages=["python", "java"],
        codeql_database_names={"python": "db-py", "java": "db-java"},
    )

    signature = finder.memory.initialize_kwargs["scan_signature"]
    scan_config = signature["scan_config"]
    llm_config = signature["llm"]

    assert scan_config["max_iterations"] == 12
    assert scan_config["stop_when_critical_complete"] is True
    assert scan_config["critical_stop_mode"] == "min"
    assert scan_config["critical_stop_max_priority"] == 1
    assert set(scan_config["scan_languages"]) == {"python", "java"}
    assert scan_config["codeql_database_names"] == {
        "python": "db-py",
        "java": "db-java",
    }
    assert scan_config["shared_public_memory"] == {
        "enabled": False,
        "root_hash": "",
        "scope_key": "",
        "state_hash": "",
    }
    assert scan_config["module_similarity"] == {
        "threshold": 0.8,
        "model_name": "jinaai--jina-code-embeddings-1.5b",
        "device": "cpu",
        "resolved_model_path": "/models/jinaai--jina-code-embeddings-1.5b",
        "artifact_hash": "artifact-hash",
    }
    assert "scanner/similarity/retriever.py" in signature["source_hashes"]
    assert "scanner/similarity/embedding.py" in signature["source_hashes"]
    assert "scanner/agent/utils.py" in signature["source_hashes"]
    assert "config.py" in signature["source_hashes"]
    assert "utils/codeql_native.py" in signature["source_hashes"]
    assert llm_config["provider"] == "provider-x"
    assert llm_config["model"] == "model-x"
    assert llm_config["base_url"] == "https://api.example.com"
    assert llm_config["temperature"] == 0.2


def test_init_without_output_dir_still_calculates_module_priorities(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    captured = {}

    def fake_calculate_module_priorities(software_profile, vulnerability_profile):
        captured["software_profile"] = software_profile
        captured["vulnerability_profile"] = vulnerability_profile
        return {"cliui": 1}, {"cli.py": "cliui"}

    monkeypatch.setattr(finder_module, "calculate_module_priorities", fake_calculate_module_priorities)

    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(cve_id="CVE-2025-0001"),
        verbose=False,
        output_dir=None,
    )

    assert captured["software_profile"] is finder.software_profile
    assert captured["vulnerability_profile"] is finder.vulnerability_profile
    assert finder.module_priorities == {"cliui": 1}
    assert finder.file_to_module == {"cli.py": "cliui"}
    assert finder.memory is None


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
            "shared_memory_hits": ["query=os.system hit src/api.py"],
            "rejected_hypotheses": ["subprocess path is sanitized"],
            "next_best_queries": ["shell=True"],
            "evidence_gaps": ["need source-to-sink trace"],
            "files_completed_this_iteration": ["src/api.py"],
        }
    }

    text = finder._extract_complementary_summary(summarized)

    assert "Summary" in text
    assert "Reasoning" in text
    assert "Shared Memory Hits" in text
    assert "query=os.system hit src/api.py" in text
    assert "Rejected Hypotheses" in text
    assert "subprocess path is sanitized" in text
    assert "Next Best Queries" in text
    assert "shell=True" in text
    assert "Evidence Gaps" in text
    assert "need source-to-sink trace" in text
    assert "Files Completed This Iteration" in text
    assert "src/api.py" in text


def test_extract_complementary_summary_non_dict_fallback(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    assert finder._extract_complementary_summary({"content": "plain text"}) == "plain text"


def test_get_user_message_iteration_uses_progress_context(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1
    finder.shared_public_memory_scope = {"observation_count": 4}

    captured = {}
    pending_priorities = []

    def fake_get_pending_files(max_priority=2):
        pending_priorities.append(max_priority)
        return ["a.py", "b.py"]

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
    ):
        captured["scanned_files"] = scanned_files
        captured["findings"] = findings
        captured["progress_info"] = progress_info
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["shared_observation_count"] = shared_observation_count
        captured["has_priority_one"] = has_priority_one
        captured["has_related"] = has_related
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
        get_pending_files=fake_get_pending_files,
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [{"file": "x.py", "type": "cmd", "confidence": "high"}],
    )

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    msg = finder._get_user_message(iteration=1)

    assert msg == "intermediate"
    assert captured["scanned_files"] == ["done.py"]
    assert captured["findings"][0]["type"] == "cmd"
    assert captured["critical_stop_max_priority"] == 1
    assert captured["shared_observation_count"] == 4
    assert captured["has_priority_one"] is False
    assert captured["has_related"] is False
    assert "3/10 files scanned" in captured["progress_info"]
    assert "Critical scope: priority-1 modules only" in captured["progress_info"]
    assert pending_priorities == [1]


def test_get_user_message_iteration_skips_priority_one_progress_prefix_when_no_priority_one_pending(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1

    captured = {}

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
    ):
        captured["progress_info"] = progress_info
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["has_priority_one"] = has_priority_one
        captured["has_related"] = has_related
        return "intermediate"

    finder.memory = SimpleNamespace(
        format_progress_info=lambda: "3/10 files scanned, 1 findings. Priority-1: 0/0, Priority-2: 1/3.",
        get_pending_files=lambda max_priority=2: [],
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [],
    )

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    msg = finder._get_user_message(iteration=1)

    assert msg == "intermediate"
    assert captured["critical_stop_max_priority"] == 1
    assert captured["has_priority_one"] is False
    assert captured["has_related"] is False
    assert "Critical scope: priority-1 modules only" not in captured["progress_info"]


def test_get_user_message_initial_passes_critical_stop_priority(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1
    finder.shared_public_memory_scope = {"observation_count": 2}
    captured = {}

    def fake_build_initial_user_message(
        software_profile,
        module_priorities,
        critical_stop_max_priority=2,
        shared_observation_count=0,
    ):
        captured["software_profile"] = software_profile
        captured["module_priorities"] = module_priorities
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["shared_observation_count"] = shared_observation_count
        return "initial"

    monkeypatch.setattr(finder_module, "build_initial_user_message", fake_build_initial_user_message)

    msg = finder._get_user_message(iteration=0)

    assert msg == "initial"
    assert captured["software_profile"] is finder.software_profile
    assert captured["module_priorities"] == finder.module_priorities
    assert captured["critical_stop_max_priority"] == 1
    assert captured["shared_observation_count"] == 2


def test_get_user_message_initial_includes_structured_vulnerability_guidance(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.vulnerability_profile = SimpleNamespace(
        to_dict=lambda: {
            "query_terms": ["os.system", "request.args"],
            "dangerous_apis": ["os.system"],
            "source_indicators": ["request.args.get"],
            "sink_indicators": ["os.system(cmd)"],
            "negative_constraints": ["feature flag disabled"],
            "scan_start_points": ["src/api.py:entry"],
            "variant_hypotheses": ["subprocess.run(..., shell=True)"],
            "likely_false_positive_patterns": ["fixed literal command"],
        }
    )

    message = finder._get_user_message(iteration=0)

    assert "Structured Vulnerability Guidance" in message
    assert '"query_terms": [' in message
    assert '"scan_start_points": [' in message
    assert "subprocess.run(..., shell=True)" in message


def test_get_user_message_iteration_does_not_repeat_structured_vulnerability_guidance(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.vulnerability_profile = SimpleNamespace(
        to_dict=lambda: {
            "query_terms": ["pickle.loads"],
            "dangerous_apis": ["pickle.loads"],
            "scan_start_points": ["src/api.py:load_model"],
        }
    )
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [],
        format_progress_info=lambda: "1/3 files scanned, 0 findings. Priority-1: 0/0, Priority-2: 0/0.",
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [],
    )

    message = finder._get_user_message(iteration=1)

    assert "Structured Vulnerability Guidance" not in message
    assert '"query_terms": [' not in message
    assert '"scan_start_points": [' not in message
    assert "Continue your vulnerability analysis:" in message


def test_run_passes_shared_observation_count_to_system_prompt(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.shared_public_memory_scope = {"observation_count": 6}
    captured = {}

    def fake_build_system_prompt(vulnerability_profile, toolkit, shared_observation_count=0):
        captured["vulnerability_profile"] = vulnerability_profile
        captured["toolkit"] = toolkit
        captured["shared_observation_count"] = shared_observation_count
        return "system"

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "analysis complete"})
        return 1

    monkeypatch.setattr(finder_module, "build_system_prompt", fake_build_system_prompt)
    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    finder.run()

    assert captured["vulnerability_profile"] is finder.vulnerability_profile
    assert captured["toolkit"] is finder.toolkit
    assert captured["shared_observation_count"] == 6


def test_run_stops_when_assistant_says_analysis_complete(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "Analysis complete"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 1
    assert result["vulnerabilities"] == []


def test_run_ignores_previous_turn_completion_when_current_turn_has_no_assistant(
    monkeypatch,
    tmp_path,
):
    finder = _make_finder(monkeypatch, tmp_path=tmp_path)
    finder.max_iterations = 3
    finder.stop_when_critical_complete = False

    def fake_run_turn(iteration):
        if iteration == 0:
            finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    def fake_compress(*args, **kwargs):
        _ = args
        _ = kwargs
        return {"content": {"summary": "analysis complete"}}

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)
    monkeypatch.setattr(finder_module, "compress_iteration_conversation", fake_compress)

    result = finder.run()

    assert result["iterations"] == 3


def test_run_trims_iteration_history_when_compression_fails(monkeypatch, tmp_path):
    finder = _make_finder(monkeypatch, tmp_path=tmp_path)
    finder.max_iterations = 1
    finder.stop_when_critical_complete = False

    def fake_run_turn(iteration):
        _ = iteration
        finder.conversation_history.extend(
            [
                {"role": "assistant", "content": "investigating"},
                {"role": "tool", "content": "tool output"},
            ]
        )
        return 1

    def fake_compress(*args, **kwargs):
        _ = args
        _ = kwargs
        return {
            "iteration_number": 0,
            "error": "boom",
            "summary": "Compression failed",
            "raw_message_count": 2,
        }

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)
    monkeypatch.setattr(finder_module, "compress_iteration_conversation", fake_compress)

    result = finder.run()

    assert result["iterations"] == 1
    assert all(message.get("role") != "tool" for message in finder.conversation_history)
    assert finder.conversation_history[-1] == {
        "role": "assistant",
        "content": "**Summary**: Compression failed",
    }


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
        return SimpleNamespace(success=True, content=json.dumps(parameters), error=None)


class _LargeToolAwareToolkit(_ToolAwareToolkit):
    def execute_tool(self, tool_name, parameters):
        self.executed.append((tool_name, parameters))
        return SimpleNamespace(success=True, content="X" * (600 * 1024), error=None)


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


class _SequencedLLM:
    def __init__(self, responses, *, context_limit=4096, max_tokens=256):
        self._responses = list(responses)
        self._response_index = 0
        self.chat_calls = 0
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.context_limit = context_limit

    def chat(self, messages, tools=None, **kwargs):
        _ = messages
        _ = tools
        _ = kwargs
        self.chat_calls += 1
        response = self._responses[self._response_index]
        if self._response_index < len(self._responses) - 1:
            self._response_index += 1
        return response

    def get_last_usage_summary(self):
        return {}

    def get_last_request_input_tokens(self) -> int:
        return 0

    def get_last_request_output_tokens(self) -> int:
        return 0

    def get_last_request_context_limit(self) -> int:
        return self.context_limit


class _RecordingLLM:
    def __init__(self, response, *, context_limit=4096, max_tokens=256):
        self._response = response
        self.context_limit = context_limit
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.chat_calls = []

    def chat(self, messages, tools=None, **kwargs):
        self.chat_calls.append(
            {
                "messages": list(messages),
                "tools": list(tools) if isinstance(tools, list) else tools,
                "kwargs": kwargs,
            }
        )
        return self._response

    def get_last_usage_summary(self):
        return {}

    def get_last_request_input_tokens(self) -> int:
        return 0

    def get_last_request_output_tokens(self) -> int:
        return 0

    def get_last_request_context_limit(self) -> int:
        return self.context_limit


def test_run_turn_stops_on_invalid_model_message(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    bad_llm = _SequencedLLM(
        [
            SimpleNamespace(content=None, tool_calls=None, reasoning_content=None),
            SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        ]
    )
    finder.llm_client = bad_llm

    result = finder._run_turn(iteration=0)

    assert result == 1
    assert bad_llm.chat_calls == 1


def test_run_turn_compacts_history_and_current_user_before_query(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    llm = _RecordingLLM(
        SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        context_limit=4096,
        max_tokens=256,
    )
    finder.llm_client = llm
    finder.max_tokens = 256
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [f"pending_{idx}.py" for idx in range(100)],
        format_progress_info=lambda: "10/200 files scanned, 1 findings.",
        get_scanned_files=lambda: [f"scanned_{idx}.py" for idx in range(500)],
        get_findings_summary=lambda: [
            {"file": f"finding_{idx}.py", "type": "cmd", "confidence": "high"}
            for idx in range(20)
        ],
    )

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
        compact=False,
    ):
        _ = (
            scanned_files,
            findings,
            progress_info,
            critical_stop_max_priority,
            shared_observation_count,
            has_priority_one,
            has_related,
        )
        return "COMPACT USER" if compact else "FULL USER"

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "old user"},
        {"role": "assistant", "content": "X" * 120_000},
        {"role": "user", "content": "FULL USER " + ("Y" * 30_000)},
    ]

    sub_turns = finder._run_turn(iteration=1)

    assert sub_turns == 1
    assert len(llm.chat_calls) == 1
    sent_messages = llm.chat_calls[0]["messages"]
    assert sent_messages[-1]["content"] == "COMPACT USER"
    assert all(message.get("content") != "X" * 120_000 for message in sent_messages if isinstance(message, dict))


def test_run_stops_on_completion_after_preflight_compaction(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _SequencedLLM(
        [
            SimpleNamespace(role="assistant", content="large intermediate " + ("X" * 120_000), tool_calls=None, reasoning_content=None),
            SimpleNamespace(role="assistant", content="analysis complete", tool_calls=None, reasoning_content=None),
        ],
        context_limit=4096,
        max_tokens=256,
    )

    finder.run()

    assert finder.llm_client.chat_calls == 2


def test_run_turn_skips_query_when_preflight_budget_still_exceeded_after_compaction(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    llm = _RecordingLLM(
        SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        context_limit=2048,
        max_tokens=512,
    )
    finder.llm_client = llm
    finder.max_tokens = 512
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [],
        format_progress_info=lambda: "progress",
        get_scanned_files=lambda: [],
        get_findings_summary=lambda: [],
    )

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
        compact=False,
    ):
        _ = (
            scanned_files,
            findings,
            progress_info,
            critical_stop_max_priority,
            shared_observation_count,
            has_priority_one,
            has_related,
        )
        if compact:
            return "Y" * 50_000
        return "FULL USER"

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "assistant", "content": "X" * 80_000},
        {"role": "user", "content": "FULL USER " + ("Z" * 50_000)},
    ]

    sub_turns = finder._run_turn(iteration=1)

    assert sub_turns == 1
    assert llm.chat_calls == []


def _tool_call(name="mock_tool", arguments="{}"):
    return SimpleNamespace(
        id="tool_1",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def test_run_turn_rejects_malformed_tool_arguments_without_executing_tool(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments='{"file_path":',
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed == []
    assert finder.found_vulnerabilities == []
    assert finder.conversation_history[-1]["role"] == "tool"
    assert "Failed to parse tool arguments" in finder.conversation_history[-1]["content"]


def test_run_turn_accepts_dict_tool_arguments(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments={
                            "file_path": "app.py",
                            "vulnerability_type": "cmd-injection",
                            "description": "desc",
                            "evidence": "evidence",
                            "similarity_to_known": "same sink",
                            "confidence": "high",
                        },
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed and toolkit.executed[0][0] == "report_vulnerability"
    assert finder.found_vulnerabilities[0]["file_path"] == "app.py"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_rejects_mismatched_vulnerability_type(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.vulnerability_profile = SimpleNamespace(
        cve_id="CVE-2025-0001",
        to_dict=lambda: {"cve_id": "CVE-2025-0001", "sink_features": {"type": "command_injection"}},
    )
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments={
                            "file_path": "app.py",
                            "vulnerability_type": "code_injection",
                            "description": "desc",
                            "evidence": "evidence",
                            "similarity_to_known": "same impact but different sink type",
                            "confidence": "medium",
                        },
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed and toolkit.executed[0][0] == "report_vulnerability"
    assert finder.found_vulnerabilities == []
    assert finder.conversation_history[-1]["role"] == "tool"
    assert "same vulnerability type" in finder.conversation_history[-1]["content"]


def test_get_user_message_does_not_rescan_related_scope_when_no_related_files_pending(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.module_priorities = {"p2": 2}
    finder.file_to_module = {"b.py": "p2"}

    class _Memory:
        def get_pending_files(self, max_priority=None):
            assert max_priority == 2
            return []

        def format_progress_info(self):
            return "1/1 files scanned, 0 findings. Priority-1: 0/0, Priority-2: 1/1."

        def get_scanned_files(self):
            return ["b.py"]

        def get_findings_summary(self):
            return []

    finder.memory = _Memory()

    message = finder._get_user_message(iteration=1)

    assert "scan ALL files in 🟡 RELATED modules before any repo-wide widening" not in message
    assert "Priority-2: 1/1" in message


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


def test_run_turn_continues_when_actual_usage_is_well_below_context_limit(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            SimpleNamespace(
                content="done",
                reasoning_content=None,
                tool_calls=None,
            ),
        ],
        input_tokens=[128, 192],
        context_limit=65536,
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
    assert finder.conversation_history[-2]["role"] == "tool"
    assert finder.conversation_history[-1].content == "done"


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


def test_run_turn_ignores_request_size_soft_limit_and_continues_to_second_request(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    monkeypatch.setattr(finder_module, "_REQUEST_SIZE_SOFT_LIMIT_BYTES", 8 * 1024, raising=False)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            SimpleNamespace(
                content="done",
                reasoning_content=None,
                tool_calls=None,
            ),
        ],
        input_tokens=[1200, 100],
        context_limit=65536,
        max_tokens=256,
    )
    finder.toolkit = _LargeToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 2
    assert finder.llm_client.chat_calls == 2
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2]["role"] == "tool"
    assert finder.conversation_history[-1].content == "done"


def test_run_turn_stops_after_max_sub_turns(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_sub_turns = 3
    finder.max_tokens = 256
    finder.llm_client = _SequencedLLM(
        [
            SimpleNamespace(content="need tool", reasoning_content=None, tool_calls=[_tool_call()]),
        ],
        context_limit=65536,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 3
    assert finder.llm_client.chat_calls == 3
    assert finder.toolkit.executed == [
        ("mock_tool", {}),
        ("mock_tool", {}),
        ("mock_tool", {}),
    ]
    assert finder.conversation_history[-1]["role"] == "tool"


def test_is_context_limit_error_does_not_match_413_entity_too_large(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    assert not finder._is_context_limit_error(RuntimeError("413 Request Entity Too Large"))
    assert not finder._is_context_limit_error(RuntimeError("APIStatusError: entity too large"))


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


def test_run_invalid_critical_stop_mode_falls_back_to_max(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=1,
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

    assert finder.critical_stop_mode == "max"
    assert result["iterations"] == 1


def test_run_ignores_analysis_complete_until_critical_scope_finishes(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.stop_when_critical_complete = True
    finder.critical_stop_mode = "min"

    class ToggleMemory:
        def __init__(self):
            self.complete = False

        def is_critical_complete(self):
            return self.complete

        def get_pending_files(self, max_priority=2):
            return ["a.py"] if not self.complete else []

        def format_progress_info(self):
            return "pending critical scope"

        def get_scanned_files(self):
            return []

        def get_findings_summary(self):
            return []

        def get_progress(self):
            return {
                "completed": 1 if self.complete else 0,
                "total_files": 1,
                "findings": 0,
                "priority_1": {"completed": 1 if self.complete else 0, "total": 1},
                "priority_2": {"completed": 0, "total": 0},
            }

    memory = ToggleMemory()
    finder.memory = memory
    turn_count = {"value": 0}

    def fake_run_turn(iteration):
        turn_count["value"] += 1
        finder.conversation_history.append({"role": "assistant", "content": "Analysis complete"})
        if turn_count["value"] >= 2:
            memory.complete = True
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 2


def test_finalize_iteration_progress_does_not_auto_complete_whole_file_reads(monkeypatch):
    class TrackingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self._touched = []

        def consume_tracked_files(self):
            touched = list(self._touched)
            self._touched = []
            return touched

    monkeypatch.setattr(finder_module, "AgenticToolkit", TrackingToolkit)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=1,
        verbose=False,
        output_dir=None,
    )

    class MemoryWithStatus(DummyMemory):
        def __init__(self):
            super().__init__()
            self.memory = SimpleNamespace(file_status={"a.py": "pending", "b.py": "completed"})

    memory = MemoryWithStatus()
    finder.memory = memory
    finder.toolkit._touched = ["a.py", "b.py"]

    finder._finalize_iteration_progress(0)

    assert memory.completed == []
    assert finder.toolkit.consume_tracked_files() == []
