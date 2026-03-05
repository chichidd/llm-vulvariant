from pathlib import Path

from profiler.software.module_analyzer.skill import SkillModuleAnalyzer as SkillModuleAnalyzer


def test_skill_build_modules_fallback_keeps_paths_and_files_consistent():
    analyzer = SkillModuleAnalyzer()
    analyzer.taxonomy = {"platform_systems": {"runtime": {}}}

    repo_info = {
        "files": ["src/a.py", "src/b.py"],
        "config_files": [],
    }
    module_map = {"modules": {"platform_systems": {"score": 1}}}
    file_index = {"src/a.py": "platform_systems.runtime"}

    modules, filtered_index = analyzer._build_modules(
        module_profile={},
        module_map=module_map,
        file_index=file_index,
        repo_info=repo_info,
    )

    assert filtered_index["src/a.py"] == "platform_systems.runtime"
    assert "src/b.py" in filtered_index
    assert modules

    for module in modules:
        assert "paths" in module
        assert "files" in module
        assert sorted(module["paths"]) == sorted(module["files"])


def test_skill_attach_dependencies_supports_modules_without_paths_field():
    analyzer = SkillModuleAnalyzer()
    modules = [
        {
            "name": "module.a",
            "category": "module",
            "description": "",
            "files": ["src/a.py"],
            "key_functions": [],
            "dependencies": [],
        },
        {
            "name": "module.b",
            "category": "module",
            "description": "",
            "files": ["src/b.py"],
            "key_functions": [],
            "dependencies": [],
        },
    ]
    repo_info = {
        "repo_analysis": {
            "functions": [
                {"file": "src/a.py", "name": "func_a"},
                {"file": "src/b.py", "name": "func_b"},
            ],
            "call_graph_edges": [
                {"caller_file": "src/a.py", "callee_file": "src/b.py"},
            ],
        }
    }

    enriched = analyzer._attach_key_functions_and_dependencies(modules, repo_info, Path("/tmp/repo"))

    assert enriched[0]["key_functions"] == ["func_a"]
    assert enriched[0]["dependencies"] == ["module.b"]



def test_skill_attach_dependencies_ignores_module_level_entries():
    analyzer = SkillModuleAnalyzer()
    modules = [
        {
            "name": "module.a",
            "category": "module",
            "description": "",
            "files": ["src/a.py"],
            "key_functions": [],
            "dependencies": [],
        }
    ]
    repo_info = {
        "repo_analysis": {
            "functions": [
                {"file": "src/a.py", "name": "<module>"},
                {"file": "src/a.py", "name": "run"},
            ],
            "call_graph_edges": [],
        }
    }

    enriched = analyzer._attach_key_functions_and_dependencies(modules, repo_info, Path("/tmp/repo"))

    assert enriched[0]["key_functions"] == ["run"]