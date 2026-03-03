from pathlib import Path

from profiler.software.repo_analyzer import CodeLocation, DependencyInfo, RepoAnalyzer


def _build_analyzer(repo_path: Path) -> RepoAnalyzer:
    analyzer = RepoAnalyzer.__new__(RepoAnalyzer)
    analyzer.repo_path = repo_path
    analyzer.language = "python"
    analyzer._dependencies = {}
    return analyzer


def test_analyze_dependencies_resets_previous_dependency_state(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\n", encoding="utf-8")

    analyzer = _build_analyzer(repo)
    analyzer._dependencies = {
        "stale_dependency": DependencyInfo(
            name="stale_dependency",
            import_locations=[CodeLocation(file="legacy.py", line=99)],
        )
    }

    analyzer._analyze_dependencies()

    assert "stale_dependency" not in analyzer._dependencies
    assert "os" in analyzer._dependencies
    assert len(analyzer._dependencies["os"].import_locations) == 1


def test_analyze_dependencies_is_stable_across_repeated_runs(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\n", encoding="utf-8")

    analyzer = _build_analyzer(repo)
    analyzer._analyze_dependencies()
    first_count = len(analyzer._dependencies["os"].import_locations)

    analyzer._analyze_dependencies()
    second_count = len(analyzer._dependencies["os"].import_locations)

    assert first_count == 1
    assert second_count == 1
