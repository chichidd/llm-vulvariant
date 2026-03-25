from pathlib import Path
import hashlib

import pytest

from utils.codeql_native import CodeQLAnalyzer, load_codeql_config


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


def test_cpp_without_build_system_tries_buildless_mode_first(tmp_path):
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


def test_cpp_with_nested_build_system_keeps_default_mode_first(tmp_path):
    source = tmp_path / "repo"
    (source / "subproj").mkdir(parents=True)
    (source / "subproj" / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n",
        encoding="utf-8",
    )

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
    assert "--build-mode=none" not in calls[0]


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


def test_create_database_default_name_includes_source_path_hash(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()

    calls = []

    def fake_run(args, timeout=None):
        calls.append(list(args))
        return True, "", ""

    analyzer = _build_analyzer(tmp_path, fake_run)
    ok, db_path = analyzer.create_database(
        source_path=str(source),
        language="python",
        overwrite=True,
    )

    expected_hash = hashlib.sha1(str(source.resolve()).encode("utf-8")).hexdigest()[:12]
    assert ok is True
    assert db_path.endswith(f"repo-{expected_hash}-python")
    assert calls[0][2].endswith(f"repo-{expected_hash}-python")


def test_load_codeql_config_raises_on_invalid_yaml(tmp_path):
    config_path = tmp_path / "codeql_config.yaml"
    config_path.write_text("codeql_cli: [", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Failed to load CodeQL config"):
        load_codeql_config(config_path)


def test_is_complete_database_rejects_unreadable_metadata(tmp_path):
    db_path = tmp_path / "db"
    db_path.mkdir()
    (db_path / "codeql-database.yml").write_text("primaryLanguage: [", encoding="utf-8")

    assert CodeQLAnalyzer._is_complete_database(str(db_path)) is False


def test_run_query_returns_text_for_csv_output(tmp_path):
    db_path = tmp_path / "db"
    db_path.mkdir()
    csv_output = "name,line\nissue,12\n"

    def fake_run(args, timeout=None):
        del timeout
        output_arg = next(arg for arg in args if arg.startswith("--output="))
        Path(output_arg.split("=", 1)[1]).write_text(csv_output, encoding="utf-8")
        return True, "", ""

    analyzer = _build_analyzer(
        tmp_path,
        fake_run,
    )

    ok, result = analyzer.run_query(str(db_path), "query.ql", output_format="csv")

    assert ok is True
    assert result == csv_output
