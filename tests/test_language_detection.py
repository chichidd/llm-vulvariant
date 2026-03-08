from pathlib import Path

from utils.language import detect_language, detect_languages


def test_detect_languages_returns_ranked_multilanguage_list(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    # Indicator files
    (repo / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    # Source files (JS count > Python count)
    for idx in range(4):
        (repo / f"web_{idx}.ts").write_text("export const x = 1;\n", encoding="utf-8")
    for idx in range(2):
        (repo / f"svc_{idx}.py").write_text("def run():\n    pass\n", encoding="utf-8")

    ranked = detect_languages(repo)
    assert ranked[0] == "javascript"
    assert "python" in ranked
    assert detect_language(repo) == "javascript"


def test_detect_languages_falls_back_to_python_for_empty_repo(tmp_path):
    repo = tmp_path / "empty"
    repo.mkdir()
    assert detect_languages(repo) == ["python"]
    assert detect_languages(repo, limit=1) == ["python"]
    assert detect_language(repo) == "python"


def test_detect_languages_recognizes_new_typescript_extensions(tmp_path):
    repo = tmp_path / "ts-only"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
    (repo / "server.mts").write_text('import "reflect-metadata";\n', encoding="utf-8")
    (repo / "worker.cts").write_text("export const ready = true;\n", encoding="utf-8")

    assert detect_languages(repo) == ["javascript"]
    assert detect_language(repo) == "javascript"


def test_detect_languages_recognizes_new_cpp_header_extensions(tmp_path):
    repo = tmp_path / "cpp-headers"
    repo.mkdir()
    (repo / "include").mkdir()
    (repo / "include" / "kernel.hxx").write_text("#pragma once\n", encoding="utf-8")
    (repo / "include" / "kernel.cuh").write_text("#pragma once\n", encoding="utf-8")

    assert detect_languages(repo) == ["cpp"]
    assert detect_language(repo) == "cpp"


def test_detect_languages_returns_empty_for_removed_csharp_support(tmp_path):
    repo = tmp_path / "csharp-only"
    repo.mkdir()
    (repo / "Program.cs").write_text("public class Program {}\n", encoding="utf-8")

    assert detect_languages(repo) == []
    assert detect_language(repo) == "unknown"
