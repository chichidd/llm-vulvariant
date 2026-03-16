from profiler.software.analyzer import SoftwareProfiler


def test_enhance_modules_aligns_internal_dependencies_with_calls_modules():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler._detect_patterns = lambda _functions, _pattern_type: []

    base_modules = [
        {
            "name": "module.a",
            "description": "",
            "files": ["src/a"],
            "key_functions": [],
            "dependencies": [],
        },
        {
            "name": "module.b",
            "description": "",
            "files": ["src/b"],
            "key_functions": [],
            "dependencies": [],
        },
    ]
    repo_analysis = {
        "functions": [
            {"file": "src/a/main.py", "name": "entry"},
            {"file": "src/b/core.py", "name": "handle"},
        ],
        "call_graph_edges": [
            {
                "caller": "entry",
                "caller_file": "src/a/main.py",
                "callee": "handle",
                "callee_file": "src/b/core.py",
            }
        ],
        "dependencies": [],
    }

    modules = profiler._enhance_modules_with_repo_analysis(base_modules, repo_analysis)
    modules_by_name = {module.name: module for module in modules}

    assert modules_by_name["module.a"].calls_modules == ["module.b"]
    assert modules_by_name["module.a"].internal_dependencies == ["module.b"]


def test_enhance_modules_preserves_raw_dependencies_alongside_internal_edges():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler._detect_patterns = lambda _functions, _pattern_type: []

    base_modules = [
        {
            "name": "module.a",
            "description": "",
            "files": ["src/a"],
            "key_functions": [],
            "dependencies": ["module.b", "requests", "module.b"],
        },
        {
            "name": "module.b",
            "description": "",
            "files": ["src/b"],
            "key_functions": [],
            "dependencies": [],
        },
    ]
    repo_analysis = {
        "functions": [],
        "call_graph_edges": [],
        "dependencies": [],
    }

    modules = profiler._enhance_modules_with_repo_analysis(base_modules, repo_analysis)
    modules_by_name = {module.name: module for module in modules}

    assert modules_by_name["module.a"].dependencies == ["module.b", "requests"]
    assert modules_by_name["module.a"].internal_dependencies == ["module.b"]
