from pathlib import Path

import pytest

from scanner.agent import toolkit as toolkit_module


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
