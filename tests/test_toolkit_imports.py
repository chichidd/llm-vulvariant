from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.agent import toolkit as toolkit_module
from profiler.software.module_analyzer.toolkit import ModuleAnalyzerToolkit


class _FakeCodeQLAnalyzer:
    def __init__(self, *args, **kwargs):
        self.is_available = True


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
