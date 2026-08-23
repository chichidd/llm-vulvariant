import json
from types import SimpleNamespace

import pytest

import scanner.agent.toolkit_codeql as toolkit_codeql_module
import scanner.agent.toolkit_fs as toolkit_fs_module
from scanner.agent import toolkit as toolkit_module
from profiler.software.module_analyzer.toolkit import ModuleAnalyzerToolkit


class _FakeCodeQLAnalyzer:
    def __init__(self, *args, **kwargs):
        self.is_available = True


def test_agentic_toolkit_reexports_fs_methods_from_split_module():
    assert (
        toolkit_module.AgenticToolkit._get_function_code
        is toolkit_fs_module.ToolkitFSMixin._get_function_code
    )
    assert toolkit_module.AgenticToolkit._read_file is toolkit_fs_module.ToolkitFSMixin._read_file


def test_agentic_toolkit_reexports_codeql_methods_from_split_module():
    assert (
        toolkit_module.AgenticToolkit._run_codeql_query
        is toolkit_codeql_module.ToolkitCodeQLMixin._run_codeql_query
    )
    assert (
        toolkit_module.AgenticToolkit._setup_query_dir
        is toolkit_codeql_module.ToolkitCodeQLMixin._setup_query_dir
    )


def test_agentic_toolkit_reexports_reporting_methods_from_split_module():
    import scanner.agent.toolkit_reporting as toolkit_reporting_module

    assert (
        toolkit_module.AgenticToolkit._report_vulnerability
        is toolkit_reporting_module.ToolkitReportingMixin._report_vulnerability
    )
    assert (
        toolkit_module.AgenticToolkit._mark_file_completed
        is toolkit_reporting_module.ToolkitReportingMixin._mark_file_completed
    )


def test_agentic_toolkit_reexports_profile_methods_from_split_module():
    import scanner.agent.toolkit_profile as toolkit_profile_module

    assert (
        toolkit_module.AgenticToolkit._get_module_call_relationships
        is toolkit_profile_module.ToolkitProfileMixin._get_module_call_relationships
    )
    assert (
        toolkit_module.AgenticToolkit._get_related_files
        is toolkit_profile_module.ToolkitProfileMixin._get_related_files
    )


def test_set_software_profile_replaces_cached_profile_entries(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    profile_a = {
        "modules": [
            {
                "name": "module_a",
                "category": "service",
                "files": ["src/a.py"],
            }
        ]
    }
    profile_b = {
        "modules": [
            {
                "name": "module_b",
                "category": "service",
                "files": ["src/b.py"],
            }
        ]
    }

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.set_software_profile(profile_a)
    toolkit.set_software_profile(profile_b)

    assert toolkit._module_cache == {
        "module_b": {
            "name": "module_b",
            "category": "service",
            "files": ["src/b.py"],
        }
    }
    assert toolkit._file_to_module_cache == {"src/b.py": "module_b"}


def test_set_software_profile_clears_relationship_caches_for_empty_profile(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    profile_a = {
        "repo_info": {
            "repo_analysis": {
                "call_graph_edges": [
                    {
                        "caller_file": "src/router.py",
                        "callee_file": "src/api.py",
                    }
                ]
            }
        }
    }

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.set_software_profile(profile_a)

    assert (
        toolkit._call_graph_edges,
        toolkit._file_callers,
        toolkit._file_callees,
    ) == (
        [{"caller_file": "src/router.py", "callee_file": "src/api.py"}],
        {"src/api.py": {"src/router.py"}},
        {"src/router.py": {"src/api.py"}},
    )

    toolkit.set_software_profile(None)

    assert (
        toolkit._call_graph_edges,
        toolkit._file_callers,
        toolkit._file_callees,
    ) == ([], {}, {})


@pytest.mark.parametrize("suffix", [".mts", ".cts"])
def test_get_imports_supports_new_typescript_module_suffixes(tmp_path, monkeypatch, suffix):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    source_file = repo_path / f"entry{suffix}"
    source_file.write_text(
        "\n".join(
            [
                'import { parse } from "pkg-a";',
                'export { stringify } from "pkg-b";',
                'const legacy = require("pkg-c");',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["javascript"])
    result = toolkit._get_imports(source_file.name)

    assert result.success is True
    assert result.content.splitlines() == [
        'import { parse } from "pkg-a"',
        'export { stringify } from "pkg-b"',
        'const legacy = require("pkg-c")',
    ]


def test_mark_file_completed_persists_memory_to_disk(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    output_dir = tmp_path / "scan-output"
    saved_states = []

    class _MemoryManager:
        def __init__(self):
            self.output_dir = output_dir
            self.memory = SimpleNamespace(
                file_status={"app.py": "pending"},
                file_completion_reasons={},
            )

        def save(self):
            saved_states.append(
                (
                    dict(self.memory.file_status),
                    dict(self.memory.file_completion_reasons),
                )
            )

    toolkit = toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        memory_manager=_MemoryManager(),
        languages=["python"],
    )

    result = toolkit._mark_file_completed("app.py", reason="inspected")

    assert result.success is True
    assert saved_states == [({"app.py": "completed"}, {"app.py": "inspected"})]


def test_mark_file_completed_normalizes_repo_relative_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    output_dir = tmp_path / "scan-output"
    saved_states = []

    class _MemoryManager:
        def __init__(self):
            self.output_dir = output_dir
            self.memory = SimpleNamespace(
                file_status={"app.py": "pending"},
                file_completion_reasons={},
            )

        def save(self):
            saved_states.append(
                (
                    dict(self.memory.file_status),
                    dict(self.memory.file_completion_reasons),
                )
            )

    toolkit = toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        memory_manager=_MemoryManager(),
        languages=["python"],
    )

    result = toolkit._mark_file_completed("./app.py", reason="inspected")

    assert result.success is True
    assert saved_states == [({"app.py": "completed"}, {"app.py": "inspected"})]


def test_mark_file_completed_fails_for_untracked_repo_file(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    saved_states = []

    class _MemoryManager:
        def __init__(self):
            self.output_dir = tmp_path / "scan-output"
            self.memory = SimpleNamespace(
                file_status={},
                file_completion_reasons={},
            )

        def save(self):
            saved_states.append(True)

    toolkit = toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        memory_manager=_MemoryManager(),
        languages=["python"],
    )

    result = toolkit._mark_file_completed("app.py", reason="inspected")

    assert result.success is False
    assert result.error == "File is not tracked in scan memory: app.py"
    assert saved_states == []


def test_execute_tool_tracks_direct_file_inspection_per_iteration(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.start_iteration_tracking()

    result = toolkit.execute_tool("read_file", {"file_path": "./app.py"})

    assert result.success is True
    assert toolkit.consume_tracked_files() == ["app.py"]
    assert toolkit.consume_tracked_files() == []


def test_execute_tool_does_not_track_partial_file_reads(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.start_iteration_tracking()

    partial_read = toolkit.execute_tool(
        "read_file",
        {"file_path": "app.py", "start_line": 1, "end_line": 1},
    )
    search_result = toolkit.execute_tool(
        "search_in_file",
        {"file_path": "app.py", "pattern": "print"},
    )

    assert partial_read.success is True
    assert search_result.success is True
    assert toolkit.consume_tracked_files() == []


def test_execute_tool_does_not_track_truncated_full_file_reads(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "large.py"
    source_file.write_text(("x = 'payload'\n" * 800), encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.start_iteration_tracking()

    result = toolkit.execute_tool("read_file", {"file_path": "large.py"})

    assert result.success is True
    assert result.truncated is True
    assert toolkit.consume_tracked_files() == []


def test_read_file_rejects_repo_escape_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    outside_file = tmp_path / "outside.py"
    outside_file.write_text("print('outside')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    result = toolkit._read_file("../outside.py")

    assert result.success is False
    assert "escapes repository root" in (result.error or "")


def test_get_module_call_relationships_rejects_ambiguous_basename_matches(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit._software_profile = object()
    toolkit._file_to_module_cache = {
        "src/config.py": "src",
        "tests/config.py": "tests",
    }

    result = toolkit._get_module_call_relationships(file_path="config.py")

    assert result.success is False
    assert "Ambiguous file path 'config.py'" in (result.error or "")


def test_get_related_files_normalizes_repo_relative_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    (repo_path / "src").mkdir(parents=True)

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit._software_profile = object()
    toolkit._file_callers = {"src/api.py": {"src/router.py"}}
    toolkit._file_callees = {"src/api.py": {"src/core.py"}}
    toolkit._call_graph_edges = [
        {
            "caller_file": "src/router.py",
            "caller": "route",
            "callee_file": "src/api.py",
            "callee": "handle",
            "call_site_line": 12,
        }
    ]

    result = toolkit._get_related_files("./src/api.py", "caller")

    assert result.success is True
    payload = json.loads(result.content)
    assert payload["matched_file"] == "src/api.py"
    assert payload["files"] == ["src/router.py"]
    assert payload["call_edges"][0]["caller_file"] == "src/router.py"


def test_check_file_status_normalizes_repo_relative_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.py"
    source_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    toolkit.set_memory_manager(
        SimpleNamespace(
            memory=SimpleNamespace(file_status={"app.py": "completed"}),
            summarize_statuses=lambda result: f"{len(result)} file(s)",
        )
    )

    result = toolkit._check_file_status(["./app.py"])
    payload = json.loads(result.content)

    assert result.success is True
    assert payload["files"] == {"app.py": "completed"}


def test_analyze_data_flow_is_python_only(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_file = repo_path / "app.js"
    source_file.write_text("function main() { return 1; }\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["javascript"])
    tools = toolkit.get_available_tools()
    analyze_tool = next(tool for tool in tools if tool["function"]["name"] == "analyze_data_flow")

    result = toolkit._analyze_data_flow("app.js", "main")

    assert "Python function" in analyze_tool["function"]["description"]
    assert result.success is False
    assert "only supports Python" in (result.error or "")


def test_list_files_rejects_folder_escape_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    result = toolkit._list_files_in_folder("../")

    assert result.success is False
    assert "escapes repository root" in (result.error or "")


def test_module_analyzer_read_file_rejects_ambiguous_suffix_matches(tmp_path):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    toolkit = ModuleAnalyzerToolkit(
        repo_path=repo_path,
        file_list=["src/api.py", "tests/api.py"],
    )

    result = toolkit._read_file(["api.py"])

    assert result.success is True
    assert "Ambiguous file path 'api.py'" in result.content


def test_report_vulnerability_normalizes_repo_relative_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    result = toolkit._report_vulnerability(
        file_path="./app.py",
        vulnerability_type="cmd",
        description="desc",
        evidence="evidence",
        similarity_to_known="same",
        confidence="high",
        attack_scenario="attacker-controlled source crosses a trust boundary to the sink",
    )

    assert result.success is True
    payload = json.loads(result.content)
    assert payload["file_path"] == "app.py"


def test_report_vulnerability_rejects_repo_escape_paths(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (tmp_path / "outside.py").write_text("print('outside')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    toolkit = toolkit_module.AgenticToolkit(repo_path=repo_path, languages=["python"])
    result = toolkit._report_vulnerability(
        file_path="../outside.py",
        vulnerability_type="cmd",
        description="desc",
        evidence="evidence",
        similarity_to_known="same",
        confidence="high",
        attack_scenario="attacker-controlled source crosses a trust boundary to the sink",
    )

    assert result.success is False
    assert "escapes repository root" in (result.error or "")


def test_memory_ablation_hides_llm_facing_history_tools(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    toolkit = toolkit_module.AgenticToolkit(
        repo_path=tmp_path,
        languages=[],
        memory_guidance_enabled=False,
    )

    tool_names = {
        tool["function"]["name"]
        for tool in toolkit.get_available_tools()
    }

    assert "check_file_status" not in tool_names
    assert "read_shared_public_memory" not in tool_names
    assert "read_file" in tool_names
    assert "report_vulnerability" in tool_names

def test_verifier_ablation_makes_attack_scenario_optional_in_schema_and_runtime(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    (tmp_path / "app.py").write_text("print(1)", encoding="utf-8")
    toolkit = toolkit_module.AgenticToolkit(
        repo_path=tmp_path, languages=["python"], verifier_enabled=False
    )
    report_tool = next(
        tool for tool in toolkit.get_available_tools()
        if tool["function"]["name"] == "report_vulnerability"
    )
    assert "attack_scenario" not in report_tool["function"]["parameters"]["required"]
    result = toolkit._report_vulnerability(
        file_path="app.py", vulnerability_type="command_injection",
        description="desc", evidence="evidence", similarity_to_known="same",
        confidence="high",
    )
    assert result.success is True
    default_toolkit = toolkit_module.AgenticToolkit(repo_path=tmp_path, languages=["python"])
    default_result = default_toolkit._report_vulnerability(
        file_path="app.py", vulnerability_type="command_injection",
        description="desc", evidence="evidence", similarity_to_known="same",
        confidence="high",
    )
    assert default_result.success is False
    assert default_result.error == "attack_scenario is required"


def test_frozen_file_order_controls_folder_truncation_and_first_touch(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    (tmp_path / "a.py").write_text("needle = 1", encoding="utf-8")
    (tmp_path / "b.py").write_text("needle = 2", encoding="utf-8")
    toolkit = toolkit_module.AgenticToolkit(repo_path=tmp_path, languages=["python"])
    with pytest.raises(ValueError, match="missing"):
        toolkit.set_file_enumeration_order(["missing.py"])
    toolkit.set_file_enumeration_order(["b.py", "a.py"])
    toolkit.set_active_file_window(["b.py", "a.py"], cursor=0)
    search_result = toolkit.execute_tool(
        "search_in_folder",
        {"folder_path": ".", "pattern": "needle", "max_results": 1},
    )
    assert search_result.success is True
    assert search_result.metadata["matches"][0]["file_path"] == "b.py"
    assert toolkit.get_observed_first_touches() == ["b.py"]
    assert toolkit.execute_tool("read_file", {"file_path": "a.py"}).success is True
    assert toolkit.get_observed_first_touches() == ["b.py", "a.py"]


def test_scheduled_mark_completion_tracks_original_path_before_redaction(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")

    class _MemoryManager:
        def __init__(self):
            self.output_dir = tmp_path / "scan-output"
            self.memory = SimpleNamespace(
                file_status={"app.py": "pending"},
                file_completion_reasons={},
            )

        def save(self):
            return None

    memory = _MemoryManager()
    toolkit = toolkit_module.AgenticToolkit(
        repo_path=tmp_path,
        languages=["python"],
        memory_manager=memory,
    )
    toolkit.set_file_enumeration_order(["app.py"])
    toolkit.set_active_file_window(["app.py"], cursor=0)

    result = toolkit.execute_tool(
        "mark_file_completed",
        {"file_path": "app.py", "reason": "inspected"},
    )

    assert result.success is True
    assert memory.memory.file_status == {"app.py": "completed"}
    assert toolkit.get_observed_first_touches() == ["app.py"]
    assert "<inactive-schedule-path>" in result.content


def test_frozen_global_schedule_controls_all_filesystem_enumerations(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    schedule = ["b/z.py", "a/shared.py", "a/a.py", "b/b.py"]
    for relative_path in [*schedule, "unscheduled.py"]:
        source_file = tmp_path / relative_path
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("needle = 1\n", encoding="utf-8")

    toolkit = toolkit_module.AgenticToolkit(repo_path=tmp_path, languages=["python"])
    with pytest.raises(ValueError, match="Invalid, missing, or duplicate"):
        toolkit.set_file_enumeration_order(["./b/z.py", "a/shared.py"])
    (tmp_path / "alias.py").symlink_to(tmp_path / "a" / "a.py")
    with pytest.raises(ValueError, match="Invalid, missing, or duplicate"):
        toolkit.set_file_enumeration_order(["alias.py", "a/shared.py"])
    toolkit.set_file_enumeration_order(schedule)
    toolkit.set_active_file_window(schedule, cursor=0)

    assert toolkit.order_repo_relative_paths(
        ["a/a.py", "unscheduled.py", "b/z.py", "b/z.py"]
    ) == ["b/z.py", "a/a.py"]

    listing = toolkit.execute_tool(
        "list_files_in_folder",
        {"folder_path": ".", "recursive": True},
    )
    assert listing.success is True
    assert listing.metadata == {"files": schedule}
    assert [listing.content.index(path) for path in schedule] == sorted(
        listing.content.index(path) for path in schedule
    )
    assert all(listing.content.count(path) == 1 for path in schedule)
    assert "unscheduled.py" not in listing.content
    assert toolkit.get_observed_first_touches() == schedule

    search = toolkit.execute_tool(
        "search_in_folder",
        {"folder_path": ".", "pattern": "needle", "max_results": 10},
    )
    assert search.success is True
    assert search.metadata["files"] == schedule
    assert [search.content.index(path) for path in schedule] == sorted(
        search.content.index(path) for path in schedule
    )
    assert all(search.content.count(path) == 1 for path in schedule)
    assert "unscheduled.py" not in search.content

    rejected_read = toolkit.execute_tool(
        "read_file",
        {"file_path": "unscheduled.py"},
    )
    assert rejected_read.success is False
    assert rejected_read.error == (
        "File is unavailable in the active frozen schedule window: unscheduled.py"
    )

    statuses = toolkit.execute_tool(
        "check_file_status",
        {"file_paths": ["a/a.py", "b/z.py", "a/a.py", "b/b.py"]},
    )
    assert statuses.success is True
    assert list(json.loads(statuses.content)["files"]) == [
        "b/z.py",
        "a/a.py",
        "b/b.py",
    ]
    rejected_status = toolkit.execute_tool(
        "check_file_status",
        {"file_paths": ["a/a.py", "unscheduled.py"]},
    )
    assert rejected_status.success is False
    assert rejected_status.error == (
        "File is unavailable in the active frozen schedule window: unscheduled.py"
    )


def test_frozen_global_schedule_flattens_overlapping_profile_relationships(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    schedule = ["b/z.py", "a/shared.py", "a/a.py", "b/b.py"]
    for relative_path in [*schedule, "unscheduled.py"]:
        source_file = tmp_path / relative_path
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("pass\n", encoding="utf-8")

    profile = {
        "modules": [
            {
                "name": "alpha",
                "category": "service",
                "files": ["a/a.py", "a/shared.py"],
                "called_by_modules": ["beta"],
                "calls_modules": ["gamma"],
            },
            {
                "name": "beta",
                "category": "caller",
                "files": ["b/b.py", "a/shared.py", "unscheduled.py"],
            },
            {
                "name": "gamma",
                "category": "callee",
                "files": ["a/a.py", "b/z.py"],
            },
        ],
        "repo_info": {
            "repo_analysis": {
                "call_graph_edges": [
                    {"caller_file": "b/b.py", "callee_file": "a/shared.py"},
                    {"caller_file": "b/z.py", "callee_file": "a/shared.py"},
                    {"caller_file": "unscheduled.py", "callee_file": "a/shared.py"},
                ]
            }
        },
    }
    toolkit = toolkit_module.AgenticToolkit(repo_path=tmp_path, languages=["python"])
    toolkit.set_software_profile(profile)
    toolkit.set_file_enumeration_order(schedule)
    toolkit.set_active_file_window(schedule, cursor=0)

    available_tools = {
        tool["function"]["name"]: tool["function"]
        for tool in toolkit.get_available_tools()
    }
    assert "get_module_call_relationships" not in available_tools
    assert "module" not in available_tools["get_related_files"]["description"].lower()
    rejected_module_tool = toolkit.execute_tool(
        "get_module_call_relationships",
        {"module_name": "alpha"},
    )
    assert rejected_module_tool.success is False
    assert "unavailable" in rejected_module_tool.error

    relationships = toolkit._get_module_call_relationships(module_name="alpha")
    assert relationships.success is True
    relationship_payload = json.loads(relationships.content)
    assert relationship_payload["files"] == schedule
    assert relationship_payload["total_files"] == len(schedule)
    assert relationship_payload["schedule_scope"] == "frozen_global_unique"
    assert set(relationship_payload) == {
        "schedule_scope",
        "total_files",
        "files",
    }

    related = toolkit.execute_tool(
        "get_related_files",
        {"file_path": "./a/shared.py", "query_type": "caller"},
    )
    assert related.success is True
    related_payload = json.loads(related.content)
    assert related_payload["files"] == ["b/z.py", "b/b.py"]
    assert related_payload["total_files"] == 2
    assert set(related_payload) == {
        "query_type",
        "schedule_scope",
        "total_files",
        "files",
    }
    assert "unscheduled.py" not in related.content

    missing = toolkit._get_module_call_relationships(module_name="missing")
    assert missing.success is True
    assert "available_modules" not in json.loads(missing.content)


def test_frozen_global_schedule_projects_shared_memory_once_per_file(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    schedule = ["b/z.py", "a/shared.py", "a/a.py"]
    for relative_path in schedule:
        source_file = tmp_path / relative_path
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("pass\n", encoding="utf-8")

    class _SharedMemoryManager:
        @staticmethod
        def read_observations(query, limit):
            assert query == "needle"
            assert limit is None
            return {
                "total": 2,
                "observations": [
                    {
                        "tool_name": "search_in_folder",
                        "query": {
                            "file_path": "unscheduled.py",
                            "pattern": "needle",
                        },
                        "summary": {
                            "note": "flow reaches a/a.py:9",
                            "files": ["a/shared.py", "unscheduled.py"],
                            "matches": [
                                {
                                    "file_path": "a/shared.py",
                                    "line_number": 1,
                                },
                                {
                                    "file_path": "a/shared.py",
                                    "line_number": 2,
                                },
                                {
                                    "file_path": "unscheduled.py",
                                    "line_number": 3,
                                },
                            ],
                        },
                    },
                    {
                        "tool_name": "read_file",
                        "query": {"file_path": "b/z.py"},
                        "summary": {"file_path": "b/z.py"},
                    },
                ],
            }

    toolkit = toolkit_module.AgenticToolkit(
        repo_path=tmp_path,
        languages=["python"],
        shared_public_memory_manager=_SharedMemoryManager(),
    )
    toolkit.set_file_enumeration_order(schedule)
    toolkit.set_active_file_window(schedule, cursor=0, completed_files=["a/a.py"])

    result = toolkit._read_shared_public_memory(query="needle", limit=10)
    assert result.success is True
    payload = json.loads(result.content)
    assert [row["file"] for row in payload["files"]] == [
        "b/z.py",
        "a/shared.py",
    ]
    assert payload["total_files"] == 2
    assert payload["returned_observations"] == 2
    assert payload["returned_files"] == 2
    assert payload["schedule_scope"] == "frozen_global_unique"
    assert "observations" not in payload
    assert "unscheduled.py" not in result.content
    assert result.content.count('"b/z.py"') == 1
    assert result.content.count('"a/shared.py"') == 1
    assert "flow reaches <inactive-schedule-path>:9" in result.content
    assert "flow reaches a/a.py:9" not in result.content


def test_scheduled_codeql_redaction_uses_path_token_boundaries():
    active_path = "src/use-document-actions.spec.tsx"
    inactive_prefix_path = "src/use-document-actions.spec.ts"
    toolkit = object.__new__(toolkit_module.AgenticToolkit)
    toolkit._scheduled_mode = True
    toolkit._file_enumeration_order = (active_path, inactive_prefix_path)
    toolkit._file_enumeration_rank = {
        active_path: 0,
        inactive_prefix_path: 1,
    }
    toolkit._scheduled_path_token_pattern = (
        toolkit._compile_scheduled_path_token_pattern(toolkit._file_enumeration_order)
    )
    toolkit._active_file_window_order = (active_path,)
    toolkit._active_file_window_rank = {active_path: 0}

    visible = toolkit._scheduled_codeql_findings(
        [
            {
                "file": active_path,
                "message": (
                    f"flow reaches {inactive_prefix_path}:17 while inspecting "
                    f"{active_path}"
                    f" via /repo/{inactive_prefix_path} and ./{inactive_prefix_path}"
                ),
                "snippet": f"load({inactive_prefix_path})",
            },
            {
                "file": inactive_prefix_path,
                "message": "future finding",
                "snippet": "future snippet",
            },
        ]
    )

    assert len(visible) == 1
    assert visible[0]["file"] == active_path
    assert visible[0]["message"] == (
        "flow reaches <inactive-schedule-path>:17 while inspecting "
        f"{active_path}"
        f" via /repo/<inactive-schedule-path> and ./<inactive-schedule-path>"
    )
    assert visible[0]["snippet"] == "load(<inactive-schedule-path>)"


def test_scheduled_redaction_protects_active_longer_path_from_inactive_suffix():
    active_path = "dir/a.py"
    inactive_suffix_path = "a.py"
    toolkit = object.__new__(toolkit_module.AgenticToolkit)
    toolkit._scheduled_mode = True
    toolkit._file_enumeration_order = (active_path, inactive_suffix_path)
    toolkit._file_enumeration_rank = {active_path: 0, inactive_suffix_path: 1}
    toolkit._scheduled_path_token_pattern = (
        toolkit._compile_scheduled_path_token_pattern(toolkit._file_enumeration_order)
    )
    toolkit._active_file_window_order = (active_path,)
    toolkit._active_file_window_rank = {active_path: 0}

    sanitized = toolkit._sanitize_scheduled_structured_value(
        {
            "message": (
                f"inspect {active_path}; reject /repo/{inactive_suffix_path}; "
                f"reject ./{inactive_suffix_path}; leave not-{inactive_suffix_path} alone"
            )
        }
    )

    assert sanitized == {
        "message": (
            f"inspect {active_path}; reject /repo/<inactive-schedule-path>; "
            "reject ./<inactive-schedule-path>; leave not-a.py alone"
        )
    }


def test_scheduled_dispatch_failures_never_echo_inactive_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(toolkit_module.AgenticToolkit, "_init_codeql", lambda self: None)
    active_path = "src/active.py"
    inactive_path = "src/future.py"
    for relative_path in (active_path, inactive_path):
        source_file = tmp_path / relative_path
        source_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text("pass\n", encoding="utf-8")

    class _ExplodingSharedMemory:
        @staticmethod
        def read_observations(*, query="", limit=10):
            del query, limit
            raise RuntimeError(f"shared read failed at /repo/{inactive_path}")

        @staticmethod
        def record_observation(tool_name, parameters, summary):
            del tool_name, parameters, summary

    toolkit = toolkit_module.AgenticToolkit(
        repo_path=tmp_path,
        languages=["python"],
        shared_public_memory_manager=_ExplodingSharedMemory(),
    )
    toolkit.set_file_enumeration_order([active_path, inactive_path])
    toolkit.set_active_file_window(
        [active_path, inactive_path],
        cursor=0,
        completed_files=[inactive_path],
    )

    monkeypatch.setattr(
        toolkit,
        "_read_file",
        lambda **kwargs: toolkit_fs_module.ToolResult(
            success=True,
            content="active content",
            metadata={"files": [inactive_path]},
        ),
    )
    indirect = toolkit.execute_tool("read_file", {"file_path": active_path})
    assert indirect.success is False
    assert inactive_path not in indirect.content
    assert inactive_path not in str(indirect.error)
    assert indirect.error == (
        "Successful tool result exposed a path outside the active frozen schedule window"
    )

    monkeypatch.setattr(
        toolkit,
        "_run_codeql_query",
        lambda **kwargs: toolkit_fs_module.ToolResult(
            success=False,
            content=f"query failed near {inactive_path}",
            error=f"analyzer failed at /repo/{inactive_path}",
            metadata={"files": [inactive_path]},
        ),
    )
    codeql_failure = toolkit.execute_tool(
        "run_codeql_query",
        {"query": "from File f select f", "query_name": "hostile"},
    )
    serialized_failure = json.dumps(
        {
            "content": codeql_failure.content,
            "error": codeql_failure.error,
            "metadata": codeql_failure.metadata,
        }
    )
    assert codeql_failure.success is False
    assert inactive_path not in serialized_failure
    assert "<inactive-schedule-path>" in serialized_failure

    shared_exception = toolkit.execute_tool("read_shared_public_memory", {})
    assert shared_exception.success is False
    assert inactive_path not in shared_exception.content
    assert inactive_path not in str(shared_exception.error)
    assert "<inactive-schedule-path>" in str(shared_exception.error)



def test_invariant_projection_v2_boundary_and_longest_match_golden():
    toolkit = object.__new__(toolkit_module.AgenticToolkit)
    frozen_paths = ("dir/a.py", "dir/a.ts", "dir/a.tsx")
    toolkit._model_path_projection_order = frozen_paths
    toolkit._model_path_projection_pattern = (
        toolkit._compile_model_path_projection_pattern(frozen_paths)
    )
    alpha = "\N{GREEK SMALL LETTER ALPHA}"

    projected = toolkit.sanitize_invariant_model_value(
        {
            "bare": "dir/a.py",
            "dot": "./dir/a.py",
            "absolute_suffix": "/repo/dir/a.py",
            "unicode_left": alpha + "dir/a.py",
            "tilde_blocked": "~dir/a.py",
            "tilde_slash": "~/dir/a.py",
            "longest": "dir/a.tsx",
            "hyphen_blocked": "not-dir/a.py",
        }
    )

    assert projected == {
        "absolute_suffix": "/repo/<TARGET_PATH>",
        "bare": "<TARGET_PATH>",
        "dot": "./<TARGET_PATH>",
        "hyphen_blocked": "not-dir/a.py",
        "longest": "<TARGET_PATH>",
        "tilde_blocked": "~dir/a.py",
        "tilde_slash": "~/<TARGET_PATH>",
        "unicode_left": alpha + "<TARGET_PATH>",
    }


def test_invariant_projection_v2_mapping_collision_golden_preserves_all_children():
    toolkit = object.__new__(toolkit_module.AgenticToolkit)
    future_a = "src/future-a.py"
    future_b = "src/future-b.py"
    frozen_paths = (future_a, future_b)
    toolkit._model_path_projection_order = frozen_paths
    toolkit._model_path_projection_pattern = (
        toolkit._compile_model_path_projection_pattern(frozen_paths)
    )
    hostile = {
        future_b: 2,
        "<TARGET_PATH>#2": 4,
        future_a: {"v": future_a},
        "<TARGET_PATH>": 3,
    }

    projected = toolkit.sanitize_invariant_model_value(hostile)

    assert list(projected) == [
        "<TARGET_PATH>",
        "<TARGET_PATH>#2",
        "<TARGET_PATH>#3",
        "<TARGET_PATH>#4",
    ]
    assert projected == {
        "<TARGET_PATH>": 3,
        "<TARGET_PATH>#2": 4,
        "<TARGET_PATH>#3": {"v": "<TARGET_PATH>"},
        "<TARGET_PATH>#4": 2,
    }


def test_scheduled_tool_result_preserves_success_active_metadata_and_truncated():
    toolkit = object.__new__(toolkit_module.AgenticToolkit)
    active_path = "src/active.py"
    future_path = "src/future.py"
    frozen_paths = (active_path, future_path)
    toolkit._scheduled_mode = True
    toolkit._scheduled_path_token_pattern = (
        toolkit._compile_scheduled_path_token_pattern(frozen_paths)
    )
    toolkit._active_file_window_rank = {active_path: 0}

    projected = toolkit._sanitize_scheduled_tool_result(
        toolkit_fs_module.ToolResult(
            success=True,
            content=f"active={active_path}; future={future_path}",
            error=f"diagnostic /repo/{future_path}",
            truncated=True,
            metadata={
                "active": {"file": active_path},
                future_path: {"nested": future_path},
            },
        )
    )

    assert projected.success is True
    assert projected.truncated is True
    assert active_path in projected.content
    assert active_path in json.dumps(projected.metadata, sort_keys=True)
    serialized = json.dumps(
        {
            "content": projected.content,
            "error": projected.error,
            "metadata": projected.metadata,
        },
        sort_keys=True,
    )
    assert future_path not in serialized
    assert serialized.count("<inactive-schedule-path>") >= 3
