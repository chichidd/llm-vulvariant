from profiler.software.analyzer import SoftwareProfiler


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


def test_software_profiler_loads_saved_rules_per_output_dir(tmp_path, monkeypatch):
    original_init_analyzers = SoftwareProfiler._init_analyzers
    original_cache = dict(SoftwareProfiler._detection_rules_cache)

    monkeypatch.setattr(SoftwareProfiler, "_init_analyzers", lambda self: None)
    SoftwareProfiler._detection_rules_cache = {}

    output_dir_a = tmp_path / "run-a"
    output_dir_b = tmp_path / "run-b"
    output_dir_a.mkdir(parents=True, exist_ok=True)
    output_dir_b.mkdir(parents=True, exist_ok=True)
    (output_dir_a / "software_profile_rule.yaml").write_text(
        """
analyzer_config:
  file_extensions:
    - .py
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
    assert profiler_b.file_extensions == [".rb"]
