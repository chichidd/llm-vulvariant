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
