from pathlib import Path

from profiler.software import repo_analyzer as repo_analyzer_mod
from profiler.software.repo_analyzer import RepoAnalyzer
from utils.codeql_native import CallGraphEdge


class _FakeCodeQLAnalyzer:
    SUPPORTED_LANGUAGES = {
        "python": ["python", "py"],
        "javascript": ["javascript", "js", "typescript", "ts"],
    }

    def __init__(self, config=None):
        self.config = config or {}
        self.is_available = True
        self.version = "fake-codeql"

    def create_database(self, source_path, language, database_name, overwrite=False):
        return True, str(Path(source_path) / f".fake-db-{language}-{database_name}")

    def _build_call_graph(self, database_path, language):
        if language == "python":
            return [
                CallGraphEdge(
                    caller_name="py_entry",
                    caller_file="backend/app.py",
                    caller_line=10,
                    callee_name="py_sink",
                    callee_file="backend/core.py",
                    callee_line=20,
                    call_site_line=11,
                )
            ]
        if language == "javascript":
            return [
                CallGraphEdge(
                    caller_name="ts_entry",
                    caller_file="web/app.ts",
                    caller_line=5,
                    callee_name="ts_sink",
                    callee_file="web/util.ts",
                    callee_line=8,
                    call_site_line=6,
                )
            ]
        return []


class _FakeCodeQLAnalyzerWithCpp:
    SUPPORTED_LANGUAGES = {
        "python": ["python", "py"],
        "cpp": ["cpp", "c++", "c"],
    }

    def __init__(self, config=None):
        self.config = config or {}
        self.is_available = True
        self.version = "fake-codeql"
        self.create_calls = []

    def create_database(self, source_path, language, database_name, overwrite=False):
        self.create_calls.append(language)
        return True, str(Path(source_path) / f".fake-db-{language}-{database_name}")

    def _build_call_graph(self, database_path, language):
        if language == "python":
            return [
                CallGraphEdge(
                    caller_name="entry",
                    caller_file="app.py",
                    caller_line=1,
                    callee_name="sink",
                    callee_file="app.py",
                    callee_line=2,
                    call_site_line=1,
                )
            ]
        return []


def test_repo_analyzer_merges_multi_language_call_graph_and_dependencies(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "backend").mkdir(parents=True)
    (repo / "web").mkdir(parents=True)
    (repo / "backend" / "app.py").write_text("import os\n", encoding="utf-8")
    (repo / "backend" / "core.py").write_text("def py_sink():\n    pass\n", encoding="utf-8")
    (repo / "web" / "app.ts").write_text('import React from "react";\n', encoding="utf-8")
    (repo / "web" / "util.ts").write_text("export const x = 1;\n", encoding="utf-8")

    monkeypatch.setattr(repo_analyzer_mod, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)
    monkeypatch.setattr(repo_analyzer_mod, "load_codeql_config", lambda: {"queries_path": str(tmp_path)})
    monkeypatch.setattr(repo_analyzer_mod, "get_git_commit", lambda _repo: "0123456789abcdef")

    analyzer = RepoAnalyzer(
        repo_path=str(repo),
        languages=["python", "javascript"],
        cache_dir=str(tmp_path / "cache"),
        rebuild_cache=True,
    )
    info = analyzer.get_info()

    assert analyzer.languages == ["python", "javascript"]
    assert info["languages"] == ["python", "javascript"]
    assert len(info["call_graph_edges"]) == 2

    dep_names = {dep["name"] for dep in info["dependencies"]}
    assert "os" in dep_names
    assert "react" in dep_names


def test_resolve_languages_supports_auto_and_explicit_lists():
    analyzer = RepoAnalyzer.__new__(RepoAnalyzer)
    analyzer._detect_languages = lambda: ["javascript", "python"]  # type: ignore[attr-defined]

    assert analyzer._resolve_languages(languages="auto") == ["javascript", "python"]
    assert analyzer._resolve_languages(languages=["auto"]) == ["javascript", "python"]
    assert analyzer._resolve_languages(languages=["python", "javascript"]) == [
        "python",
        "javascript",
    ]


def test_repo_analyzer_skips_cpp_codeql_when_only_headers_exist(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "include").mkdir(parents=True)
    (repo / "app.py").write_text("def entry():\n    pass\n", encoding="utf-8")
    (repo / "include" / "only_header.h").write_text("// header only\n", encoding="utf-8")

    monkeypatch.setattr(repo_analyzer_mod, "CodeQLAnalyzer", _FakeCodeQLAnalyzerWithCpp)
    monkeypatch.setattr(repo_analyzer_mod, "load_codeql_config", lambda: {"queries_path": str(tmp_path)})
    monkeypatch.setattr(repo_analyzer_mod, "get_git_commit", lambda _repo: "fedcba9876543210")

    analyzer = RepoAnalyzer(
        repo_path=str(repo),
        languages=["python", "cpp"],
        cache_dir=str(tmp_path / "cache"),
        rebuild_cache=True,
    )

    assert analyzer.languages == ["python", "cpp"]
    assert analyzer.codeql_languages == ["python"]
    assert analyzer.codeql_analyzer.create_calls == ["python"]


def test_repo_analyzer_auto_detects_mts_files_and_scans_dependencies(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    (repo / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
    (repo / "main.mts").write_text('import React from "react";\n', encoding="utf-8")

    monkeypatch.setattr(repo_analyzer_mod, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)
    monkeypatch.setattr(repo_analyzer_mod, "load_codeql_config", lambda: {"queries_path": str(tmp_path)})
    monkeypatch.setattr(repo_analyzer_mod, "get_git_commit", lambda _repo: "1111222233334444")

    analyzer = RepoAnalyzer(
        repo_path=str(repo),
        languages="auto",
        cache_dir=str(tmp_path / "cache"),
        rebuild_cache=True,
    )
    info = analyzer.get_info()

    assert analyzer.languages == ["javascript"]
    assert analyzer.codeql_languages == ["javascript"]
    dep_names = {dep["name"] for dep in info["dependencies"]}
    assert "react" in dep_names


def test_repo_analyzer_auto_detects_cuda_translation_units_for_cpp_codeql(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "cuda").mkdir(parents=True)
    (repo / "cuda" / "op.cu").write_text('#include "op.cuh"\n', encoding="utf-8")
    (repo / "cuda" / "op.cuh").write_text("#pragma once\n", encoding="utf-8")

    monkeypatch.setattr(repo_analyzer_mod, "CodeQLAnalyzer", _FakeCodeQLAnalyzerWithCpp)
    monkeypatch.setattr(repo_analyzer_mod, "load_codeql_config", lambda: {"queries_path": str(tmp_path)})
    monkeypatch.setattr(repo_analyzer_mod, "get_git_commit", lambda _repo: "9999aaaabbbbcccc")

    analyzer = RepoAnalyzer(
        repo_path=str(repo),
        languages="auto",
        cache_dir=str(tmp_path / "cache"),
        rebuild_cache=True,
    )

    assert analyzer.languages == ["cpp"]
    assert analyzer.codeql_languages == ["cpp"]
    assert analyzer.codeql_analyzer.create_calls == ["cpp"]
