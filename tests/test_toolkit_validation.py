from pathlib import Path

from scanner.agent import toolkit as toolkit_module


class _FakeCodeQLAnalyzer:
    def __init__(self, *args, **kwargs):
        self.is_available = True


def _make_toolkit(tmp_path: Path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql_dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    return toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        languages=["python"],
    )


def test_execute_tool_rejects_read_file_invalid_lines(tmp_path, monkeypatch):
    toolkit = _make_toolkit(tmp_path, monkeypatch)

    result = toolkit.execute_tool("read_file", {"file_path": "app.py", "start_line": 0})
    assert result.success is False
    assert "start_line" in result.error
    assert "minimum" in result.error

    result = toolkit.execute_tool("read_file", {"file_path": "app.py", "start_line": 10, "end_line": 5})
    assert result.success is False
    assert "end_line must be greater than or equal to start_line" in result.error


def test_execute_tool_rejects_report_vulnerability_invalid_confidence(tmp_path, monkeypatch):
    toolkit = _make_toolkit(tmp_path, monkeypatch)

    result = toolkit.execute_tool(
        "report_vulnerability",
        {
            "file_path": "app.py",
            "vulnerability_type": "INJECTION",
            "description": "possible sink",
            "evidence": "source_code",
            "similarity_to_known": "matches example",
            "confidence": "critical",
        },
    )

    assert result.success is False
    assert "expected one of" in result.error


def test_execute_tool_rejects_check_file_status_empty_list(tmp_path, monkeypatch):
    toolkit = _make_toolkit(tmp_path, monkeypatch)

    result = toolkit.execute_tool("check_file_status", {"file_paths": []})
    assert result.success is False
    assert "minimum length" in result.error


def test_execute_tool_rejects_read_codeql_results_negative_offset(tmp_path, monkeypatch):
    toolkit = _make_toolkit(tmp_path, monkeypatch)

    result = toolkit.execute_tool("read_codeql_results", {"query_name": "demo", "offset": -1})
    assert result.success is False
    assert ">= 0" in result.error
