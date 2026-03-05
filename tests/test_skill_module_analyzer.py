from pathlib import Path

from profiler.software.module_analyzer.skill import SkillModuleAnalyzer as SkillModuleAnalyzer



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
