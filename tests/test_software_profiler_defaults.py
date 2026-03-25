from types import SimpleNamespace

import pytest

from profiler.software.analyzer import SoftwareProfiler
from profiler.software import analyzer as analyzer_module


def test_software_profiler_uses_defaults_when_rules_omit_file_extensions(monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_loader = SoftwareProfiler._load_detection_rules

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    monkeypatch.setattr(
        SoftwareProfiler,
        "_load_detection_rules",
        classmethod(
            lambda cls, rules_path=None, output_dir=None: {
                "data_sources": {},
                "data_formats": {},
                "processing_operations": {},
                "analyzer_config": {
                    "exclude_dirs": [],
                },
                "module_analyzer_config": {},
            }
        ),
    )

    try:
        profiler = SoftwareProfiler(output_dir=None)
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._load_detection_rules = original_loader

    merged_extensions = set(profiler.file_extensions)
    assert ".tsx" in merged_extensions
    assert ".h" in merged_extensions
    assert ".cc" in merged_extensions


def test_software_profiler_honors_configured_file_extensions(monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_loader = SoftwareProfiler._load_detection_rules

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    monkeypatch.setattr(
        SoftwareProfiler,
        "_load_detection_rules",
        classmethod(
            lambda cls, rules_path=None, output_dir=None: {
                "data_sources": {},
                "data_formats": {},
                "processing_operations": {},
                "analyzer_config": {
                    "file_extensions": [".py", ".pyw"],
                    "exclude_dirs": [],
                },
                "module_analyzer_config": {},
            }
        ),
    )

    try:
        profiler = SoftwareProfiler(output_dir=None)
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._load_detection_rules = original_loader

    assert profiler.file_extensions == [".py", ".pyw"]


def test_software_profiler_uses_repo_config_even_when_output_dirs_have_saved_rules(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}
    monkeypatch.setitem(analyzer_module._path_config, "repo_root", tmp_path)

    output_dir_a = tmp_path / "run-a"
    output_dir_b = tmp_path / "run-b"
    output_dir_a.mkdir(parents=True, exist_ok=True)
    output_dir_b.mkdir(parents=True, exist_ok=True)
    config_path = tmp_path / "config" / "software_profile_rule.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        """
analyzer_config:
  file_extensions:
    - .py
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
        encoding="utf-8",
    )
    (output_dir_a / "software_profile_rule.yaml").write_text(
        """
analyzer_config:
  file_extensions:
    - .rb
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
        encoding="utf-8",
    )
    (output_dir_b / "software_profile_rule.yaml").write_text(
        """
analyzer_config:
  file_extensions:
    - .rb
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
        encoding="utf-8",
    )

    try:
        profiler_a = SoftwareProfiler(output_dir=str(output_dir_a))
        profiler_b = SoftwareProfiler(output_dir=str(output_dir_b))
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._detection_rules_cache = original_cache

    assert profiler_a.file_extensions == [".py"]
    assert profiler_b.file_extensions == [".py"]


def test_software_profiler_reload_rules_when_repo_config_changes(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}
    monkeypatch.setitem(analyzer_module._path_config, "repo_root", tmp_path)

    output_dir = tmp_path / "run-a"
    output_dir.mkdir(parents=True, exist_ok=True)
    rules_path = tmp_path / "config" / "software_profile_rule.yaml"
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(
        """
analyzer_config:
  file_extensions:
    - .py
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
        encoding="utf-8",
    )

    try:
        profiler_first = SoftwareProfiler(output_dir=str(output_dir))
        rules_path.write_text(
            """
analyzer_config:
  file_extensions:
    - .rb
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
            encoding="utf-8",
        )
        profiler_second = SoftwareProfiler(output_dir=str(output_dir))
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._detection_rules_cache = original_cache

    assert profiler_first.file_extensions == [".py"]
    assert profiler_second.file_extensions == [".rb"]


def test_software_profiler_saves_rule_snapshot_inside_profile_directory(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}
    monkeypatch.setitem(analyzer_module._path_config, "repo_root", tmp_path)

    rules_path = tmp_path / "config" / "software_profile_rule.yaml"
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(
        """
analyzer_config:
  file_extensions:
    - .py
  exclude_dirs: []
module_analyzer_config: {}
""".strip(),
        encoding="utf-8",
    )

    try:
        profiler = SoftwareProfiler(output_dir=str(tmp_path / "profiles"))
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._detection_rules_cache = original_cache

    profile_dir = tmp_path / "profiles" / "demo" / "commit"

    class _StorageManager:
        def _get_profile_dir(self, *path_parts):
            assert path_parts == ("demo", "commit")
            profile_dir.mkdir(parents=True, exist_ok=True)
            return profile_dir

    profiler.storage_manager = _StorageManager()
    profiler._current_profile_path_parts = ("demo", "commit")
    profiler._save_config_to_output_dir()

    assert not (tmp_path / "profiles" / "software_profile_rule.yaml").exists()
    saved_snapshot = profile_dir / "software_profile_rule.yaml"
    assert saved_snapshot.exists()
    assert ".py" in saved_snapshot.read_text(encoding="utf-8")


def test_software_profiler_passes_validation_settings_to_skill_module_analyzer(monkeypatch):
    captured = {}
    original_loader = SoftwareProfiler._load_detection_rules

    class RecordingSkillModuleAnalyzer:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(analyzer_module, "SkillModuleAnalyzer", RecordingSkillModuleAnalyzer)
    monkeypatch.setattr(
        SoftwareProfiler,
        "_load_detection_rules",
        classmethod(
            lambda cls, rules_path=None, output_dir=None: {
                "data_sources": {},
                "data_formats": {},
                "processing_operations": {},
                "analyzer_config": {
                    "exclude_dirs": [],
                },
                "module_analyzer_config": {
                    "analyzer_type": "skill",
                    "validation_mode": True,
                    "validation_temperature": 0.0,
                    "validation_max_workers": 1,
                },
            }
        ),
    )

    try:
        profiler = SoftwareProfiler(
            llm_client=SimpleNamespace(config=SimpleNamespace(provider="deepseek", model="deepseek-chat")),
            output_dir=None,
        )
    finally:
        SoftwareProfiler._load_detection_rules = original_loader

    assert profiler.module_analyzer is not None
    assert captured["validation_mode"] is True
    assert captured["validation_temperature"] == 0.0
    assert captured["validation_max_workers"] == 1


def test_software_profiler_raises_when_detection_rules_file_is_missing(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}
    monkeypatch.setitem(analyzer_module._path_config, "repo_root", tmp_path)

    try:
        with pytest.raises(FileNotFoundError, match="software_profile_rule.yaml"):
            SoftwareProfiler(output_dir=None)
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._detection_rules_cache = original_cache


def test_software_profiler_raises_when_detection_rules_yaml_is_invalid(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}
    monkeypatch.setitem(analyzer_module._path_config, "repo_root", tmp_path)

    rules_path = tmp_path / "config" / "software_profile_rule.yaml"
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text("analyzer_config: [invalid", encoding="utf-8")

    try:
        with pytest.raises(RuntimeError, match="Failed to parse detection rules file"):
            SoftwareProfiler(output_dir=None)
    finally:
        SoftwareProfiler._init_analyzers = original_init_analyzers
        SoftwareProfiler._detection_rules_cache = original_cache
