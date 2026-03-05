import json
import os
import time

from profiler.profile_storage import ProfileStorageManager
from profiler.software.models import ModuleInfo, SoftwareProfile
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


def test_software_profile_from_dict_prefers_enhanced_modules_over_modules():
    data = {
        "basic_info": {"name": "repo", "version": "v1"},
        "modules": [{"name": "raw", "files": ["a.py"]}],
        "enhanced_modules": [{"name": "enh", "external_dependencies": ["pandas"]}],
    }

    profile = SoftwareProfile.from_dict(data)

    assert len(profile.modules) == 1
    assert isinstance(profile.modules[0], ModuleInfo)
    assert profile.modules[0].name == "enh"
    assert profile.modules[0].external_dependencies == ["pandas"]


def test_vulnerability_profile_json_roundtrip():
    original = VulnerabilityProfile(
        repo_name="repo",
        affected_version="deadbeef",
        cve_id="CVE-2025-0001",
        payload="poc",
        source_features=SourceFeature(description="src", api="read", data_type="user_input"),
        flow_features=FlowFeature(description="flow", operations=["concat"]),
        sink_features=SinkFeature(description="sink", type="command_injection", function="os.system"),
        exploit_scenarios=["attacker controls input"],
        affected_modules=["api"],
    )

    encoded = original.to_json()
    restored = VulnerabilityProfile.from_json(encoded)

    assert restored.repo_name == "repo"
    assert restored.cve_id == "CVE-2025-0001"
    assert restored.source_features is not None
    assert restored.source_features.api == "read"
    assert restored.flow_features is not None
    assert restored.flow_features.operations == ["concat"]
    assert restored.sink_features is not None
    assert restored.sink_features.function == "os.system"


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


def test_profile_storage_manager_info_save_and_load(tmp_path):
    manager = ProfileStorageManager(base_dir=tmp_path, profile_type="test")
    payload = {"repo": "demo", "version": "abc"}

    manager.save_profile_info(payload, "demo", "abc", info_filename="profile_info.json")
    loaded = manager.load_profile_info("demo", "abc", info_filename="profile_info.json")

    assert loaded == payload
    raw = json.loads((tmp_path / "demo" / "abc" / "profile_info.json").read_text(encoding="utf-8"))
    assert raw["repo"] == "demo"
