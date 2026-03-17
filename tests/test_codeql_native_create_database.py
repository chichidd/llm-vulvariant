from pathlib import Path
from unittest.mock import MagicMock

from utils.codeql_native import CodeQLAnalyzer


def _build_analyzer(tmp_path: Path, run_codeql_impl):
    analyzer = CodeQLAnalyzer.__new__(CodeQLAnalyzer)
    analyzer.config = {
        "database_dir": str(tmp_path / "dbs"),
        "threads": 0,
        "timeout": 30,
    }
    analyzer._codeql_cmd = "codeql"
    analyzer._run_codeql = run_codeql_impl
    return analyzer


def test_cpp_without_build_system_uses_buildless_mode_first(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()

    calls = []

    def fake_run(args, timeout=None):
        calls.append(list(args))
        return True, "", ""

    analyzer = _build_analyzer(tmp_path, fake_run)
    ok, db_path = analyzer.create_database(
        source_path=str(source),
        language="cpp",
        database_name="demo-cpp",
        overwrite=True,
    )

    assert ok is True
    assert db_path.endswith("demo-cpp")
    assert len(calls) == 1
    assert "--build-mode=none" in calls[0]


def test_cpp_with_build_system_keeps_default_then_fallback(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")

    calls = []

    def fake_run(args, timeout=None):
        calls.append(list(args))
        if "--build-mode=none" in args:
            return True, "", ""
        return False, "", "autobuild failed"

    analyzer = _build_analyzer(tmp_path, fake_run)
    ok, _ = analyzer.create_database(
        source_path=str(source),
        language="cpp",
        database_name="demo-cpp",
        overwrite=True,
    )

    assert ok is True
    assert len(calls) == 2
    assert "--build-mode=none" not in calls[0]
    assert "--build-mode=none" in calls[1]


def test_cpp_without_build_system_falls_back_to_default_when_buildless_fails(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()

    calls = []

    def fake_run(args, timeout=None):
        calls.append(list(args))
        if "--build-mode=none" in args:
            return False, "", "buildless failed"
        return True, "", ""

    analyzer = _build_analyzer(tmp_path, fake_run)
    ok, _ = analyzer.create_database(
        source_path=str(source),
        language="cpp",
        database_name="demo-cpp",
        overwrite=True,
    )

    assert ok is True
    assert len(calls) == 2
    assert "--build-mode=none" in calls[0]
    assert "--build-mode=none" not in calls[1]


def test_create_database_rejects_unsupported_language(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()

    calls = []

    def fake_run(args, timeout=None):
        calls.append(list(args))
        return True, "", ""

    analyzer = _build_analyzer(tmp_path, fake_run)
    ok, message = analyzer.create_database(
        source_path=str(source),
        language="fortran",
        database_name="demo-csharp",
        overwrite=True,
    )

    assert ok is False
    assert message == "Unsupported language: fortran"
    assert calls == []


def test_run_codeql_defaults_to_inherit_caller_cwd(tmp_path, monkeypatch):
    analyzer = CodeQLAnalyzer.__new__(CodeQLAnalyzer)
    analyzer.config = {
        "database_dir": str(tmp_path / "dbs"),
        "threads": 0,
        "timeout": 30,
    }
    analyzer._codeql_cmd = "codeql"
    captured = {}

    def fake_run(cmd, capture_output=None, text=None, timeout=None, **kwargs):
        captured.update(kwargs)
        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = ""
        fake_result.stderr = ""
        return fake_result

    monkeypatch.setattr("utils.codeql_native.subprocess.run", fake_run)
    success, _, _ = analyzer._run_codeql(["version", "--format=json"], timeout=10)

    assert success is True
    assert "cwd" not in captured


def test_run_codeql_uses_configured_working_dir(tmp_path, monkeypatch):
    working_dir = tmp_path / "custom"
    working_dir.mkdir()
    analyzer = CodeQLAnalyzer.__new__(CodeQLAnalyzer)
    analyzer.config = {
        "database_dir": str(tmp_path / "dbs"),
        "threads": 0,
        "timeout": 30,
        "working_dir": str(working_dir),
    }
    analyzer._codeql_cmd = "codeql"
    captured = {}

    def fake_run(cmd, capture_output=None, text=None, timeout=None, **kwargs):
        captured.update(kwargs)
        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = ""
        fake_result.stderr = ""
        return fake_result

    monkeypatch.setattr("utils.codeql_native.subprocess.run", fake_run)
    success, _, _ = analyzer._run_codeql(["version", "--format=json"], timeout=10)

    assert success is True
    assert captured["cwd"] == str(working_dir)
