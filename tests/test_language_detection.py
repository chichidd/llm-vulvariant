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


def test_detect_languages_returns_empty_for_removed_csharp_support(tmp_path):
    repo = tmp_path / "csharp-only"
    repo.mkdir()
    (repo / "Program.cs").write_text("public class Program {}\n", encoding="utf-8")

    assert detect_languages(repo) == []
    assert detect_language(repo) == "unknown"
