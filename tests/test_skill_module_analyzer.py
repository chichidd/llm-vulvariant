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


class _StorageManagerStub:
    def __init__(self, checkpoint_dir: Path):
        self._checkpoint_dir = checkpoint_dir
        self.saved = {}

    def get_checkpoint_dir(self, *path_parts):
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        return self._checkpoint_dir

    def save_checkpoint(self, checkpoint_name, data, *path_parts):
        self.saved[checkpoint_name] = data


def test_skill_analyze_force_regenerate_cleans_existing_outputs(tmp_path):
    analyzer = SkillModuleAnalyzer()
    analyzer.taxonomy = {"coarse": {"fine": {}}}

    checkpoint_dir = tmp_path / "checkpoints"
    output_dir = checkpoint_dir / "skill_module_modeler"
    output_dir.mkdir(parents=True)
    stale_file = output_dir / "stale.json"
    stale_file.write_text("stale", encoding="utf-8")

    def _run(repo_path, actual_output_dir, repo_name):
        assert actual_output_dir == output_dir
        assert not stale_file.exists()
        (actual_output_dir / "module_map.json").write_text("{}", encoding="utf-8")
        (actual_output_dir / "file_index.json").write_text("{}", encoding="utf-8")
        (actual_output_dir / "module_profile.json").write_text('{"modules": []}', encoding="utf-8")
        return True

    analyzer._run_claude_analysis = _run
    storage_manager = _StorageManagerStub(checkpoint_dir)

    result = analyzer.analyze(
        repo_info={"files": []},
        repo_path=tmp_path / "repo",
        storage_manager=storage_manager,
        repo_name="demo",
        version="abc123",
        force_regenerate=True,
    )

    assert result["modules"] == []
