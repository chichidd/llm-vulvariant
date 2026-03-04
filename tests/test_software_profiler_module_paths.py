from profiler.software.analyzer import SoftwareProfiler


def test_enhance_modules_ignores_empty_paths_and_matches_extensionless_files():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler._detect_patterns = lambda _functions, _pattern_type: []

    base_modules = [
        {
            "name": "module.src",
            "description": "",
            "files": ["", "src"],
            "key_functions": [],
            "dependencies": [],
        },
        {
            "name": "module.makefile",
            "description": "",
            "files": ["Makefile"],
            "key_functions": [],
            "dependencies": [],
        },
    ]
    repo_analysis = {
        "functions": [
            {"file": "src/main.py", "name": "main"},
            {"file": "src/lib/util.py", "name": "util"},
            {"file": "Makefile", "name": "build"},
            {"file": "scripts/deploy.sh", "name": "deploy"},
        ],
        "call_graph_edges": [],
        "dependencies": [],
    }

    modules = profiler._enhance_modules_with_repo_analysis(base_modules, repo_analysis)
    modules_by_name = {module.name: module for module in modules}

    assert set(modules_by_name["module.src"].files) == {"src/main.py", "src/lib/util.py"}
    assert "scripts/deploy.sh" not in modules_by_name["module.src"].files
    assert modules_by_name["module.makefile"].files == ["Makefile"]


def test_detect_patterns_uses_token_matching_to_avoid_substring_false_positives():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.detection_rules = {
        "data_sources": {
            "file": ["read"],
        },
        "data_formats": {},
        "processing_operations": {
            "transform": ["map"],
        },
    }

    functions = [
        {"name": "thread_ready"},
        {"name": "spread_data"},
        {"name": "bitmap_create"},
        {"name": "hashmap_get"},
        {"name": "read_file"},
        {"name": "map_records"},
    ]

    assert profiler._detect_patterns(functions, "data_sources") == ["file"]
    assert profiler._detect_patterns(functions, "processing_operations") == ["transform"]


def test_detect_patterns_normalizes_call_like_keywords():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.detection_rules = {
        "data_sources": {
            "file": ["open(", "Path("],
        },
        "data_formats": {},
        "processing_operations": {},
    }

    functions = [
        {"name": "open"},
        {"name": "Path"},
        {"name": "reopen_cache"},
    ]

    assert profiler._detect_patterns(functions, "data_sources") == ["file"]


def test_enhance_modules_detects_external_called_apis_for_c_like_code():
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.detection_rules = {
        "data_sources": {
            "file": ["open("],
            "network": ["socket"],
        },
        "data_formats": {},
        "processing_operations": {},
    }

    base_modules = [
        {
            "name": "module.io",
            "description": "",
            "files": ["src/io.c"],
            "key_functions": [],
            "dependencies": [],
        }
    ]
    repo_analysis = {
        "functions": [
            {
                "function_id": "src/io.c::parse_packet@10",
                "file": "src/io.c",
                "name": "parse_packet",
                "start_line": 10,
            },
        ],
        "call_graph_edges": [
            {
                "caller": "parse_packet",
                "caller_file": "src/io.c",
                "caller_line": 10,
                "caller_id": "src/io.c::parse_packet@10",
                "callee": "fopen",
                "callee_file": "",
                "callee_line": 0,
                "callee_id": "",
            },
            {
                "caller": "parse_packet",
                "caller_file": "src/io.c",
                "caller_line": 10,
                "caller_id": "src/io.c::parse_packet@10",
                "callee": "recv",
                "callee_file": "",
                "callee_line": 0,
                "callee_id": "",
            },
        ],
        "dependencies": [],
    }

    modules = profiler._enhance_modules_with_repo_analysis(base_modules, repo_analysis)

    assert set(modules[0].data_sources) == {"file", "network"}
