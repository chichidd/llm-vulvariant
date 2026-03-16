import json
import os
import time
from pathlib import Path
from unittest.mock import patch

from profiler.profile_storage import ProfileStorageManager
from profiler.software.models import DataFlowPattern, ModuleInfo, SoftwareProfile
from profiler.vulnerability.models import (
    FlowFeature,
    SinkFeature,
    SourceFeature,
    VulnerabilityProfile,
)


def test_moduleinfo_to_dict_and_from_dict_fields():
    module = ModuleInfo(
        name="api",
        files=["src/api.py"],
        internal_dependencies=["core"],
        external_dependencies=["requests"],
    )

    data = module.to_dict()
    assert data["internal_dependencies"] == ["core"]
    assert "dependencies" not in data

    restored = ModuleInfo.from_dict({"name": "x", "files": ["a.py"], "internal_dependencies": ["b"]})
    assert restored.files == ["a.py"]
    assert restored.internal_dependencies == ["b"]


def test_moduleinfo_preserves_raw_dependencies_field_when_present():
    module = ModuleInfo.from_dict(
        {
            "name": "api",
            "files": ["src/api.py"],
            "dependencies": ["core"],
        }
    )

    assert module.dependencies == ["core"]
    assert module.to_dict()["dependencies"] == ["core"]


def test_software_profile_roundtrip_keeps_module_and_dependency_fields():
    profile = SoftwareProfile(
        name="demo",
        version="abc123",
        description="A service that handles model serving",
        target_application=["inference"],
        target_user=["ml engineer"],
        modules=[
            ModuleInfo(
                name="serving",
                files=["serving.py"],
                external_dependencies=["torch"],
                internal_dependencies=["utils"],
            )
        ],
        third_party_libraries=["torch", "numpy"],
        builtin_libraries=["json"],
        dependency_usage_count={"torch": 2},
        total_functions=11,
        metadata={"llm_usage_summary": {"calls_total": 2}},
    )

    encoded = profile.to_dict()
    decoded = SoftwareProfile.from_dict(encoded)

    assert decoded.name == "demo"
    assert decoded.version == "abc123"
    assert len(decoded.modules) == 1
    assert isinstance(decoded.modules[0], ModuleInfo)
    assert decoded.modules[0].external_dependencies == ["torch"]
    assert decoded.third_party_libraries == ["torch", "numpy"]
    assert decoded.dependency_usage_count == {"torch": 2}
    assert decoded.total_functions == 11
    assert decoded.metadata == {"llm_usage_summary": {"calls_total": 2}}


def test_software_profile_to_dict_keeps_builtin_only_dependency_details():
    profile = SoftwareProfile(
        name="demo",
        builtin_libraries=["json"],
        dependency_usage_count={"json": 3},
    )

    encoded = profile.to_dict()
    decoded = SoftwareProfile.from_dict(encoded)

    assert encoded["dependencies_detailed"]["builtin"] == ["json"]
    assert encoded["dependencies_detailed"]["usage_count"] == {"json": 3}
    assert decoded.builtin_libraries == ["json"]
    assert decoded.dependency_usage_count == {"json": 3}


def test_software_profile_from_dict_normalizes_modules_and_data_flow_patterns():
    data = {
        "basic_info": {"name": "repo", "version": "v1"},
        "modules": [{"name": "raw", "files": ["a.py"]}],
        "data_flow_patterns": [{"pattern_type": "file_to_memory", "source_apis": ["open"]}],
    }

    profile = SoftwareProfile.from_dict(data)

    assert len(profile.modules) == 1
    assert isinstance(profile.modules[0], ModuleInfo)
    assert profile.modules[0].name == "raw"
    assert len(profile.data_flow_patterns) == 1
    assert isinstance(profile.data_flow_patterns[0], DataFlowPattern)
    assert profile.data_flow_patterns[0].pattern_type == "file_to_memory"


def test_software_profile_to_dict_normalizes_module_dicts():
    profile = SoftwareProfile(
        name="repo",
        modules=[{"name": "api", "files": ["src/api.py"], "dependencies": ["core"]}],
        data_flow_patterns=[{"pattern_type": "network_to_file"}],
    )

    encoded = profile.to_dict()

    assert encoded["modules"] == [
        {
            "name": "api",
            "category": "",
            "description": "",
            "files": ["src/api.py"],
            "key_functions": [],
            "data_sources": [],
            "data_formats": [],
            "processing_operations": [],
            "external_dependencies": [],
            "internal_dependencies": [],
            "called_by_modules": [],
            "calls_modules": [],
            "dependencies": ["core"],
        }
    ]
    assert encoded["data_flow_patterns"] == [
        {
            "pattern_type": "network_to_file",
            "source_apis": [],
            "sink_apis": [],
            "intermediate_operations": [],
            "file_paths": [],
        }
    ]


def test_software_profile_roundtrip_preserves_raw_module_dependencies():
    profile = SoftwareProfile(
        name="repo",
        modules=[{"name": "api", "files": ["src/api.py"], "dependencies": ["core"]}],
    )

    encoded = profile.to_dict()
    decoded = SoftwareProfile.from_dict(encoded)

    assert encoded["modules"][0]["dependencies"] == ["core"]
    assert len(decoded.modules) == 1
    assert isinstance(decoded.modules[0], ModuleInfo)
    assert decoded.modules[0].dependencies == ["core"]


def test_vulnerability_profile_dict_roundtrip():
    original = VulnerabilityProfile(
        repo_name="repo",
        affected_version="deadbeef",
        cve_id="CVE-2025-0001",
        payload="poc",
        source_features=SourceFeature(description="src", api="read", data_type="user_input"),
        flow_features=FlowFeature(description="flow", operations=["concat"]),
        sink_features=SinkFeature(description="sink", type="command_injection", function="os.system"),
        exploit_scenarios=["attacker controls input"],
        affected_modules={"src/api.py": "api"},
        metadata={"llm_calls": 4},
    )

    restored = VulnerabilityProfile.from_dict(original.to_dict())

    assert restored.repo_name == "repo"
    assert restored.cve_id == "CVE-2025-0001"
    assert restored.source_features is not None
    assert restored.source_features.api == "read"
    assert restored.flow_features is not None
    assert restored.flow_features.operations == ["concat"]
    assert restored.sink_features is not None
    assert restored.sink_features.function == "os.system"
    assert restored.affected_modules == {"src/api.py": "api"}
    assert restored.metadata == {"llm_calls": 4}


def test_profile_storage_manager_checkpoint_conversation_and_result(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")

    manager.save_checkpoint("flow", {"k": 1}, "repo", "ver")
    assert manager.load_checkpoint("flow", "repo", "ver") == {"k": 1}

    manager.save_final_result("software_profile.json", "{}", "repo", "ver")
    assert manager.load_final_result("software_profile.json", "repo", "ver") == "{}"

    manager.save_conversation("source", {"step": 1}, "repo", "ver", file_identifier="old")
    old_file = tmp_path / "repo" / "ver" / "conversations" / "source" / "old.json"
    os.utime(old_file, (time.time() - 20, time.time() - 20))

    manager.save_conversation("source", {"step": 2}, "repo", "ver", file_identifier="new")
    latest = manager.load_conversation("source", "repo", "ver")
    assert latest == {"step": 2}


def test_profile_storage_manager_loads_named_conversation_without_falling_back_to_latest(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")

    manager.save_conversation("source", {"step": "wanted"}, "repo", "ver", file_identifier="wanted")
    manager.save_conversation("source", {"step": "other"}, "repo", "ver", file_identifier="other")

    loaded = manager.load_conversation("source", "repo", "ver", file_identifier="wanted")

    assert loaded == {"step": "wanted"}


def test_profile_storage_manager_info_save_and_load(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")
    payload = {"repo": "demo", "version": "abc"}

    manager.save_profile_info(payload, "demo", "abc", info_filename="profile_info.json")
    loaded = manager.load_profile_info("demo", "abc", info_filename="profile_info.json")

    assert loaded == payload
    raw = json.loads((tmp_path / "demo" / "abc" / "profile_info.json").read_text(encoding="utf-8"))
    assert raw["repo"] == "demo"


def test_profile_storage_manager_loads_do_not_create_missing_dirs(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")

    assert manager.load_checkpoint("flow", "repo", "ver") is None
    assert manager.load_conversation("source", "repo", "ver") is None
    assert manager.load_final_result("software_profile.json", "repo", "ver") is None
    assert not (tmp_path / "repo").exists()


def test_profile_storage_manager_uses_atomic_replace_for_checkpoint_and_result(tmp_path, monkeypatch):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")
    replaced_paths = []
    original_replace = Path.replace

    def record_replace(source_path: Path, target_path: Path) -> Path:
        replaced_paths.append((Path(source_path), Path(target_path)))
        return original_replace(source_path, target_path)

    monkeypatch.setattr(Path, "replace", record_replace)

    manager.save_checkpoint("flow", {"k": 1}, "repo", "ver")
    manager.save_final_result("software_profile.json", "{}", "repo", "ver")

    assert manager.load_checkpoint("flow", "repo", "ver") == {"k": 1}
    assert manager.load_final_result("software_profile.json", "repo", "ver") == "{}"
    assert len(replaced_paths) == 2

    for source_path, target_path in replaced_paths:
        assert source_path.parent == target_path.parent
        assert source_path != target_path
        assert source_path.name.startswith(f".{target_path.name}.")
        assert source_path.name.endswith(".tmp")
        assert not source_path.exists()


def test_profile_storage_manager_does_not_log_success_when_atomic_replace_fails(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")
    manager.save_checkpoint("flow", {"k": 1}, "repo", "ver")
    checkpoint_dir = tmp_path / "repo" / "ver" / "checkpoints"

    with patch("pathlib.Path.replace", side_effect=OSError("disk full")), patch(
        "profiler.profile_storage.logger.info"
    ) as info_log, patch("profiler.profile_storage.logger.warning") as warning_log:
        manager.save_checkpoint("flow", {"k": 2}, "repo", "ver")

    assert manager.load_checkpoint("flow", "repo", "ver") == {"k": 1}
    info_log.assert_not_called()
    warning_log.assert_called_once()
    assert "Failed to write JSON file" in warning_log.call_args[0][0]
    assert not list(checkpoint_dir.glob(".*.tmp"))
