from profiler.software.repo_analyzer import RepoAnalyzer
from utils.codeql_native import CallGraphEdge


def _build_analyzer_with_edges(edges):
    analyzer = RepoAnalyzer.__new__(RepoAnalyzer)
    analyzer.languages = []
    analyzer._call_graph_edges = edges
    analyzer._functions = {}
    analyzer._function_key_index = {}
    analyzer._dependencies = {}
    return analyzer


def test_extract_functions_keeps_duplicate_names_across_files():
    edges = [
        CallGraphEdge(
            caller_name="run",
            caller_file="src/a.py",
            caller_line=10,
            callee_name="process",
            callee_file="src/common.py",
            callee_line=5,
            call_site_line=12,
        ),
        CallGraphEdge(
            caller_name="run",
            caller_file="src/b.py",
            caller_line=20,
            callee_name="process",
            callee_file="src/common.py",
            callee_line=5,
            call_site_line=22,
        ),
    ]
    analyzer = _build_analyzer_with_edges(edges)

    analyzer._extract_functions()

    run_ids = sorted(
        func_id
        for func_id, func in analyzer._functions.items()
        if func.name == "run"
    )
    process_ids = sorted(
        func_id
        for func_id, func in analyzer._functions.items()
        if func.name == "process"
    )
    assert len(run_ids) == 2
    assert len(process_ids) == 1
    assert len(analyzer._functions) == 3
    assert {analyzer._functions[run_id].file for run_id in run_ids} == {"src/a.py", "src/b.py"}


def test_get_info_exposes_function_ids_for_edges_and_functions():
    edges = [
        CallGraphEdge(
            caller_name="run",
            caller_file="src/a.py",
            caller_line=10,
            callee_name="process",
            callee_file="src/common.py",
            callee_line=5,
            call_site_line=12,
        ),
        CallGraphEdge(
            caller_name="<module>",
            caller_file="src/a.py",
            caller_line=0,
            callee_name="len",
            callee_file="",
            callee_line=0,
            call_site_line=2,
        ),
    ]
    analyzer = _build_analyzer_with_edges(edges)
    analyzer._extract_functions()

    info = analyzer.get_info()
    assert info["functions"]
    assert all(func.get("function_id") for func in info["functions"])

    resolved_edge = info["call_graph_edges"][0]
    assert resolved_edge["caller_id"]
    assert resolved_edge["callee_id"]

    unresolved_edge = info["call_graph_edges"][1]
    assert unresolved_edge["caller_id"]
    assert unresolved_edge["callee_id"] == ""
