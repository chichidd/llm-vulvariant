from pathlib import Path

from profiler.software.module_analyzer.taxonomy_loader import load_ai_infra_taxonomy


def _write_taxonomy_module(skill_root: Path, payload: str) -> None:
    scripts_dir = skill_root / "scripts"
    scripts_dir.mkdir(parents=True)
    (scripts_dir / "ai_infra_taxonomy.py").write_text(payload, encoding="utf-8")


def test_load_ai_infra_taxonomy_reads_each_skill_root_independently(tmp_path):
    first_root = tmp_path / "skill-a"
    second_root = tmp_path / "skill-b"
    _write_taxonomy_module(first_root, 'AI_INFRA_TAXONOMY = {"name": "first"}\n')
    _write_taxonomy_module(second_root, 'AI_INFRA_TAXONOMY = {"name": "second"}\n')

    first = load_ai_infra_taxonomy(first_root)
    second = load_ai_infra_taxonomy(second_root)

    assert first == {"name": "first"}
    assert second == {"name": "second"}
