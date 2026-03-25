from pathlib import Path

import pytest

from profiler.software.repo_analyzer import RepoAnalyzer


def _build_analyzer(repo_path: Path) -> RepoAnalyzer:
    analyzer = RepoAnalyzer.__new__(RepoAnalyzer)
    analyzer.repo_path = repo_path
    analyzer.languages = ["python"]
    analyzer._call_graph_edges = []
    analyzer._functions = {}
    analyzer._function_key_index = {}
    analyzer._dependencies = {}
    return analyzer


def test_extract_functions_discovers_leaf_python_functions_without_call_graph_edges(tmp_path: Path) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text(
        "\n".join(
            [
                "def entry():",
                "    helper()",
                "",
                "def helper():",
                "    return 1",
            ]
        ),
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo_path)

    analyzer._extract_functions()

    function_names = {func.name for func in analyzer._functions.values()}
    assert {"entry", "helper"} <= function_names
    assert all(func.file == "app.py" for func in analyzer._functions.values())


@pytest.mark.parametrize("suffix", [".mjs", ".cjs", ".mts", ".cts"])
def test_extract_functions_discovers_leaf_javascript_variant_functions(tmp_path: Path, suffix: str) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_path = repo_path / f"app{suffix}"
    source_path.write_text(
        "\n".join(
            [
                "export function entry() {",
                "  return helper();",
                "}",
                "",
                "const helper = () => 1;",
            ]
        ),
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo_path)
    analyzer.languages = ["javascript"]

    analyzer._extract_functions()

    function_names = {func.name for func in analyzer._functions.values()}
    assert {"entry", "helper"} <= function_names
    assert all(func.file == source_path.name for func in analyzer._functions.values())


@pytest.mark.parametrize("suffix", [".cu", ".cuh"])
def test_extract_functions_discovers_leaf_cuda_family_functions(tmp_path: Path, suffix: str) -> None:
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    source_path = repo_path / f"kernel{suffix}"
    source_path.write_text(
        "\n".join(
            [
                "__global__ void launch_kernel() {",
                "}",
                "",
                "inline int helper() {",
                "  return 1;",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    analyzer = _build_analyzer(repo_path)
    analyzer.languages = ["cpp"]

    analyzer._extract_functions()

    function_names = {func.name for func in analyzer._functions.values()}
    assert {"launch_kernel", "helper"} <= function_names
    assert all(func.file == source_path.name for func in analyzer._functions.values())
