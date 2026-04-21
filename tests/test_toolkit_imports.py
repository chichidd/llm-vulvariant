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
