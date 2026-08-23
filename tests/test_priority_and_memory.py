import copy
from pathlib import Path

import pytest

from profiler.fingerprint import stable_data_hash
from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.agent import priority as priority_module
from scanner.agent.memory import AgentMemoryManager
from scanner.agent.priority import calculate_module_priorities
from scanner.agent.schedule_window import FROZEN_SCHEDULE_PAGE_SIZE



def test_calculate_module_priorities_marks_affected_and_related():
    software = SoftwareProfile(
        name="repo",
        modules=[
            ModuleInfo(name="api", files=["api.py"], calls_modules=["core"]),
            ModuleInfo(name="core", files=["core.py"], called_by_modules=["api"]),
            ModuleInfo(name="misc", files=["misc.py"]),
        ],
    )
    vulnerability = type("V", (), {"affected_modules": {"api.py": "core"}})()

    priorities, file_to_module = calculate_module_priorities(software, vulnerability)

    assert priorities["core"] == 1
    assert priorities["api"] == 2
    assert priorities["misc"] == 3
    assert file_to_module["core.py"] == "core"


def test_calculate_module_priorities_promotes_embedding_similar_modules(monkeypatch):
    software = SoftwareProfile(
        name="repo",
        modules=[
            ModuleInfo(name="model_loader", files=["loader.py"], description="load model checkpoints"),
            ModuleInfo(name="data_loader", files=["data.py"], description="read dataset files"),
            ModuleInfo(name="webui", files=["web.py"], description="serve browser interface"),
            ModuleInfo(name="cliui", files=["cli.py"], description="serve terminal interface"),
            ModuleInfo(name="helper", files=["helper.py"], called_by_modules=["cliui"]),
        ],
    )
    vulnerability = type("V", (), {"affected_modules": {"web.py": "webui"}})()

    monkeypatch.setitem(
        priority_module._scanner_config["module_similarity"],
        "threshold",
        0.8,
    )

    class DummyRetriever:
        def similarity(self, left, right):
            pair = (left, right)
            if "webui" in pair[0] and "cliui" in pair[1]:
                return 0.9
            if "webui" in pair[1] and "cliui" in pair[0]:
                return 0.9
            return 0.2

    monkeypatch.setattr(priority_module, "build_text_retriever", lambda **kwargs: DummyRetriever())

    priorities, file_to_module = calculate_module_priorities(software, vulnerability)

    assert priorities == {
        "model_loader": 3,
        "data_loader": 3,
        "webui": 1,
        "cliui": 1,
        "helper": 2,
    }
    assert file_to_module == {
        "loader.py": "model_loader",
        "data.py": "data_loader",
        "web.py": "webui",
        "cli.py": "cliui",
        "helper.py": "helper",
    }


def test_calculate_module_priorities_respects_module_similarity_override(monkeypatch):
    software = SoftwareProfile(
        name="repo",
        modules=[
            ModuleInfo(name="webui", files=["web.py"], description="serve browser interface"),
            ModuleInfo(name="cliui", files=["cli.py"], description="serve terminal interface"),
        ],
    )
    vulnerability = type("V", (), {"affected_modules": {"web.py": "webui"}})()
    captured = {}

    class DummyRetriever:
        def similarity(self, left, right):
            return 0.9 if "cliui" in left or "cliui" in right else 0.2

    def fake_build_text_retriever(**kwargs):
        captured.update(kwargs)
        return DummyRetriever()

    monkeypatch.setattr(priority_module, "build_text_retriever", fake_build_text_retriever)

    priorities, _ = calculate_module_priorities(
        software,
        vulnerability,
        module_similarity_config={"threshold": 0.8, "model_name": "mini-model", "device": "cuda"},
    )

    assert priorities["webui"] == 1
    assert priorities["cliui"] == 1
    assert captured == {"model_name": "mini-model", "device": "cuda"}


def test_calculate_module_priorities_accepts_plain_attribute_module_objects():
    plain_module = type(
        "PlainModule",
        (),
        {
            "name": "cliui",
            "files": ["cli.py"],
            "calls_modules": [],
            "called_by_modules": [],
            "category": "ui",
            "description": "command-line interface",
        },
    )()
    software = type("S", (), {"modules": [plain_module]})()
    vulnerability = type("V", (), {"affected_modules": {"cli.py": "cliui"}})()

    priorities, file_to_module = calculate_module_priorities(software, vulnerability)

    assert priorities == {"cliui": 1}
    assert file_to_module == {"cli.py": "cliui"}


def test_agent_memory_manager_deduplicate_findings_and_progress(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1, "core": 2},
        file_to_module={"a.py": "api", "b.py": "core"},
    )

    assert resumed is False

    added = mgr.add_finding(
        {
            "file_path": "a.py",
            "function_name": "f",
            "vulnerability_type": "command_injection",
            "line_number": 12,
            "confidence": "high",
        }
    )
    duplicate = mgr.add_finding(
        {
            "file_path": "a.py",
            "function_name": "f",
            "vulnerability_type": "command_injection",
            "line_number": 12,
            "confidence": "high",
        }
    )

    assert mgr.memory.file_status["a.py"] == "pending"

    mgr.mark_file_completed("a.py", reason="done")
    mgr.mark_file("b.py", "skipped")
    progress = mgr.get_progress()
    summary = mgr.summarize_statuses(mgr.memory.file_status)

    assert added is True
    assert duplicate is False
    assert progress["completed"] == 1
    assert progress["priority_1"]["completed"] == 1
    assert mgr.get_pending_files(max_priority=2) == []
    assert summary == "1 completed, 0 pending, 1 skipped, 0 not tracked"
    assert mgr.memory.file_completion_reasons["a.py"] == "done"


def test_agent_memory_manager_keeps_file_pending_after_first_finding(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api"},
    )

    added = mgr.add_finding(
        {
            "file_path": "a.py",
            "function_name": "f",
            "vulnerability_type": "command_injection",
            "line_number": 12,
            "confidence": "high",
        }
    )

    assert added is True
    assert mgr.memory.file_status["a.py"] == "pending"
    assert mgr.get_pending_files(max_priority=1) == ["a.py"]
    assert mgr.is_critical_complete(max_priority=1) is False


def test_agent_memory_manager_add_findings_batches_and_deduplicates(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api"},
    )

    save_calls = []
    original_save = mgr.save

    def counted_save():
        save_calls.append("save")
        return original_save()

    mgr.save = counted_save

    added = mgr.add_findings(
        [
            {
                "file_path": "a.py",
                "function_name": "f",
                "vulnerability_type": "command_injection",
                "line_number": 12,
                "confidence": "high",
            },
            {
                "file_path": "a.py",
                "function_name": "f",
                "vulnerability_type": "command_injection",
                "line_number": 12,
                "confidence": "high",
            },
            {
                "file_path": "a.py",
                "function_name": "g",
                "vulnerability_type": "command_injection",
                "line_number": 15,
                "confidence": "medium",
            },
        ]
    )

    assert added == 2
    assert len(save_calls) == 1
    assert len(mgr.memory.findings) == 2
    assert [finding["function_name"] for finding in mgr.memory.findings] == ["f", "g"]


def test_agent_memory_batch_normalization_failure_leaves_ram_and_disk_unchanged(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api"},
    )
    before_disk = mgr.memory_file.read_bytes()
    valid = {
        "file_path": "a.py",
        "function_name": "f",
        "vulnerability_type": "command_injection",
    }

    with pytest.raises(AttributeError):
        mgr.add_findings([valid, "not-a-finding"])

    assert mgr.memory.findings == []
    assert mgr.memory_file.read_bytes() == before_disk
    reloaded = AgentMemoryManager(output_dir=tmp_path)
    assert reloaded.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api"},
    ) is True
    assert reloaded.memory.findings == []


def test_atomic_finding_transition_save_failure_rolls_back_ram_and_disk(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api", "b.py": "api"},
    )
    before_disk = mgr.memory_file.read_bytes()

    def fail_save():
        raise RuntimeError("injected save failure")

    mgr.save = fail_save
    with pytest.raises(RuntimeError, match="injected save failure"):
        mgr.add_findings_with_first_touches(
            [{
                "file_path": "a.py",
                "function_name": "f",
                "vulnerability_type": "command_injection",
            }],
            ["a.py", "b.py"],
        )

    assert mgr.memory.findings == []
    assert mgr.memory.coverage_first_touches == []
    assert mgr.memory_file.read_bytes() == before_disk
    reloaded = AgentMemoryManager(output_dir=tmp_path)
    assert reloaded.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api", "b.py": "api"},
    ) is True
    assert reloaded.memory.findings == []
    assert reloaded.memory.coverage_first_touches == []


def test_atomic_finding_transition_validates_existing_findings_before_touch(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1},
        file_to_module={"a.py": "api"},
    )
    mgr.memory.findings = ["malformed-existing-finding"]

    with pytest.raises(AttributeError):
        mgr.add_findings_with_first_touches([], ["a.py"])

    assert mgr.memory.coverage_first_touches == []
    assert mgr.memory.findings == ["malformed-existing-finding"]


def test_agent_memory_manager_reload_existing_state(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
    )

    mgr.mark_file("x.py", "completed")

    mgr2 = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr2.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
    )

    assert resumed is True
    assert mgr2.get_scanned_files() == ["x.py"]
    assert (Path(tmp_path) / "scan_memory.json").exists()


def test_agent_memory_manager_discards_stale_resume_inputs(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
    )
    mgr.mark_file("x.py", "completed")

    mgr2 = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr2.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"other": 1},
        file_to_module={"y.py": "other"},
    )

    assert resumed is False
    assert mgr2.get_scanned_files() == []
    assert mgr2.memory.file_status == {"y.py": "pending"}


def test_agent_memory_generate_summary_uses_cautious_language_for_partial_coverage(tmp_path):
    class _LLM:
        def __init__(self):
            self.prompt = ""

        def complete(self, prompt):
            self.prompt = prompt
            return type("Resp", (), {"content": "summary"})()

    llm = _LLM()
    mgr = AgentMemoryManager(output_dir=tmp_path, llm_client=llm)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef1234567890",
        cve_id="CVE-2025-0001",
        module_priorities={"api": 1, "core": 2},
        file_to_module={"a.py": "api", "b.py": "core"},
        critical_stop_max_priority=2,
    )
    mgr.add_finding(
        {
            "file_path": "a.py",
            "function_name": "f",
            "vulnerability_type": "command_injection",
            "line_number": 12,
            "confidence": "high",
        }
    )
    mgr.mark_file_completed("a.py")

    summary = mgr.generate_summary()

    assert summary == "summary"
    assert "Coverage status: partial" in llm.prompt
    assert "Treat the findings as scan-stage candidates" in llm.prompt


def test_agent_memory_manager_discards_resume_when_scan_signature_changes(tmp_path):
    signature_v1 = {
        "scan_config": {
            "max_iterations": 10,
            "stop_when_critical_complete": False,
            "critical_stop_mode": "max",
            "critical_stop_max_priority": 2,
            "scan_languages": ["python", "go"],
            "codeql_database_names": {"python": "db-python"},
        },
        "llm": {
            "provider": "provider-a",
            "model": "model-a",
            "temperature": 0.1,
        },
    }
    signature_v2 = {
        **signature_v1,
        "scan_config": {
            **signature_v1["scan_config"],
            "max_iterations": 11,
        },
    }

    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
        scan_signature=signature_v1,
    )
    mgr.mark_file("x.py", "completed")
    assert mgr.get_scanned_files() == ["x.py"]

    mgr2 = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr2.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
        scan_signature=signature_v1,
    )
    assert resumed is True
    assert mgr2.get_scanned_files() == ["x.py"]

    mgr3 = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr3.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"m": 1},
        file_to_module={"x.py": "m"},
        scan_signature=signature_v2,
    )
    assert resumed is False
    assert mgr3.get_scanned_files() == []


def test_agent_memory_manager_rejects_empty_priority_scope_as_critical_complete(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"other": 3},
        file_to_module={"x.py": "other"},
    )

    assert mgr.is_critical_complete() is False


def test_agent_memory_manager_treats_priority_two_as_critical_scope(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"p1": 1, "p2": 2, "other": 3},
        file_to_module={"a.py": "p1", "b.py": "p2", "c.py": "other"},
    )

    mgr.mark_file_completed("a.py", reason="done")
    assert mgr.is_critical_complete() is False

    mgr.mark_file_completed("b.py", reason="done")
    assert mgr.is_critical_complete() is True


def test_agent_memory_manager_updates_critical_scope_when_resuming(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"p1": 1, "p2": 2},
        file_to_module={"a.py": "p1", "b.py": "p2"},
        critical_stop_max_priority=2,
    )

    mgr2 = AgentMemoryManager(output_dir=tmp_path)
    resumed = mgr2.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"p1": 1, "p2": 2},
        file_to_module={"a.py": "p1", "b.py": "p2"},
        critical_stop_max_priority=1,
    )

    assert resumed is True
    assert mgr2.memory.critical_stop_max_priority == 1

    mgr3 = AgentMemoryManager(output_dir=tmp_path)
    assert mgr3.load() is True
    assert mgr3.memory.critical_stop_max_priority == 1


def test_agent_memory_manager_markdown_rejects_empty_priority_one_scope(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"related": 2},
        file_to_module={"b.py": "related"},
        critical_stop_max_priority=1,
    )

    markdown = mgr.to_markdown()

    assert "**Critical Scope**: priority-1 (directly affected or embedding-similar) only" in markdown
    assert "Incomplete Critical Files" in markdown
    assert "No files are bound to the configured critical scope" in markdown


def test_agent_memory_manager_markdown_lists_pending_priority_two_files_in_scope(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"related": 2},
        file_to_module={"b.py": "related"},
        critical_stop_max_priority=2,
    )

    markdown = mgr.to_markdown()

    assert "**Critical Scope**: priority-1/2 (directly affected or embedding-similar + related)" in markdown
    assert "Incomplete Critical Files" in markdown
    assert "- [ ] `b.py`" in markdown


def test_module_priority_helper_rejects_candidate_ablation_without_schedule():
    software = SoftwareProfile(
        name="repo",
        modules=[
            ModuleInfo(name="api", files=["api.py"]),
            ModuleInfo(name="worker", files=["worker.py"]),
            ModuleInfo(name="misc", files=["misc.py"]),
        ],
    )
    vulnerability = type("V", (), {"affected_modules": {"api.py": "api"}})()
    with pytest.raises(
        ValueError,
        match="requires an externally frozen global file schedule",
    ):
        calculate_module_priorities(
            software,
            vulnerability,
            candidate_priority_enabled=False,
        )

def test_agent_memory_resume_rejects_changed_reference_profile_hash(tmp_path):
    first_signature = {"scan_config": {"reference_profile_hash": "card-hash-1"}}
    second_signature = {"scan_config": {"reference_profile_hash": "card-hash-2"}}
    manager = AgentMemoryManager(output_dir=tmp_path)
    manager.initialize(
        target_repo="repo", target_commit="abcdef", cve_id="",
        module_priorities={"m": 1}, file_to_module={"x.py": "m"},
        scan_signature=first_signature,
    )
    manager.mark_file("x.py", "completed")
    resumed_manager = AgentMemoryManager(output_dir=tmp_path)
    resumed = resumed_manager.initialize(
        target_repo="repo", target_commit="abcdef", cve_id="",
        module_priorities={"m": 1}, file_to_module={"x.py": "m"},
        scan_signature=second_signature,
    )
    assert resumed is False
    assert resumed_manager.get_scanned_files() == []


def test_agent_memory_schedule_history_is_exact_contiguous_and_resume_durable(tmp_path):
    manager = AgentMemoryManager(output_dir=tmp_path)
    manager.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"schedule": 1},
        file_to_module={"a.py": "schedule"},
    )
    first_files = [f"src/file-{index}.py" for index in range(FROZEN_SCHEDULE_PAGE_SIZE)]
    first_event = {
        "schema_version": 1,
        "cursor_index": 0,
        "window_end_index_exclusive": FROZEN_SCHEDULE_PAGE_SIZE,
        "window_file_count": FROZEN_SCHEDULE_PAGE_SIZE,
        "active_pending_file_count": FROZEN_SCHEDULE_PAGE_SIZE,
        "completed_window_count": 0,
        "window_sha256": stable_data_hash(first_files),
    }
    final_files = ["src/final-a.py", "src/final-b.py", "src/final-c.py"]
    final_event = {
        "schema_version": 1,
        "cursor_index": FROZEN_SCHEDULE_PAGE_SIZE,
        "window_end_index_exclusive": FROZEN_SCHEDULE_PAGE_SIZE + len(final_files),
        "window_file_count": len(final_files),
        "active_pending_file_count": len(final_files),
        "completed_window_count": 0,
        "window_sha256": stable_data_hash(final_files),
    }

    with pytest.raises(ValueError, match="no matching entered-window event"):
        manager.record_schedule_presented_page(0)
    with pytest.raises(ValueError, match="first|exactly contiguous"):
        manager.record_schedule_window_event(final_event)

    manager.record_schedule_window_event(first_event)
    manager.record_schedule_window_event(first_event)
    manager.record_schedule_presented_page(0)
    manager.record_schedule_presented_page(0)
    manager.record_schedule_window_event(final_event)
    manager.record_schedule_presented_page(1)

    assert manager.memory.schedule_window_events == [first_event, final_event]
    assert manager.memory.schedule_presented_page_indices == [0, 1]

    malformed = dict(final_event, completed_window_count=1)
    with pytest.raises(ValueError, match="content is invalid"):
        manager.record_schedule_window_event(malformed)
    skipped = dict(final_event, cursor_index=2 * FROZEN_SCHEDULE_PAGE_SIZE)
    skipped["window_end_index_exclusive"] = skipped["cursor_index"] + len(final_files)
    with pytest.raises(ValueError, match="exactly contiguous"):
        manager.record_schedule_window_event(skipped)
    with pytest.raises(ValueError, match="exact key set"):
        manager.record_schedule_window_event({**first_event, "unexpected": True})

    resumed = AgentMemoryManager(output_dir=tmp_path)
    assert resumed.load() is True
    assert resumed.memory.schedule_window_events == [first_event, final_event]
    assert resumed.memory.schedule_presented_page_indices == [0, 1]


def test_agent_memory_resume_rejects_exact_identity_and_runtime_mutations(
    tmp_path,
):
    decoding = {
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 1024,
        "enable_thinking": None,
        "reasoning_effort": None,
        "service_tier": None,
    }
    decoding_sha256 = stable_data_hash(decoding)
    endpoint_snapshot = {
        "snapshot_id": "deployment-fixture-a",
        "base_url": "https://api.example.invalid/v1",
        "api_family": "openai_compatible",
    }
    endpoint_sha256 = stable_data_hash(endpoint_snapshot)
    attestation_binding = {
        "path": "rq2/inputs/model-revision-attestations/fixture.json",
        "file_sha256": "8" * 64,
        "payload_sha256": "9" * 64,
    }
    runtime_projection = {
        "raw_reference_sha256": "1" * 64,
        "projected_reference_sha256": "2" * 64,
        "raw_static_input_sha256": "3" * 64,
        "projected_static_input_sha256": "4" * 64,
        "invariant_projected_static_input_sha256": "4" * 64,
        "policy_visible_static_input_sha256": "5" * 64,
        "policy_preserved_fields": [
            "target_software.modules[].files"
        ],
    }
    signature = {
        "scan_config": {
            "max_iterations": 10,
            "model_visible_input_projection": {
                "artifact_sha256": "6" * 64,
            },
            "model_revision_attestation": dict(attestation_binding),
            "model_visible_input_runtime_projection": runtime_projection,
            "endpoint_snapshot": endpoint_snapshot,
            "endpoint_snapshot_sha256": endpoint_sha256,
            "decoding_config_requested": decoding,
            "decoding_config_requested_sha256": decoding_sha256,
            "decoding_config_effective": decoding,
            "decoding_config_effective_sha256": decoding_sha256,
        },
        "llm": {
            "provider": "lab",
            "model": "fixture-model",
            "model_revision": "fixture-revision-a",
            "model_revision_attestation": dict(attestation_binding),
            "base_url": endpoint_snapshot["base_url"],
            "endpoint_snapshot": endpoint_snapshot,
            "endpoint_snapshot_sha256": endpoint_sha256,
            "decoding_config_requested": decoding,
            "decoding_config_requested_sha256": decoding_sha256,
            "decoding_config_effective": decoding,
            "decoding_config_effective_sha256": decoding_sha256,
            **decoding,
            "fallback_on_retry_exhausted": False,
            "exact_decoding_enforced": True,
        },
        "config_hashes": {
            "paths.yaml": "a" * 64,
            "scanner_config.yaml": "b" * 64,
            "codeql_config.yaml": "c" * 64,
            "llm_config.yaml": "d" * 64,
        },
    }

    def mutate_decoding(candidate):
        effective = {
            **candidate["llm"]["decoding_config_effective"],
            "reasoning_effort": "high",
        }
        candidate["llm"]["decoding_config_effective"] = effective
        candidate["llm"][
            "decoding_config_effective_sha256"
        ] = stable_data_hash(effective)

    def mutate_runtime(candidate):
        candidate["scan_config"][
            "model_visible_input_runtime_projection"
        ]["raw_reference_sha256"] = "7" * 64

    def mutate_endpoint(candidate):
        candidate["llm"]["endpoint_snapshot"][
            "snapshot_id"
        ] = "deployment-fixture-b"
        candidate["llm"]["endpoint_snapshot_sha256"] = stable_data_hash(
            candidate["llm"]["endpoint_snapshot"]
        )

    def mutate_llm_attestation(candidate):
        candidate["llm"]["model_revision_attestation"][
            "payload_sha256"
        ] = "7" * 64

    def mutate_scan_attestation(candidate):
        candidate["scan_config"]["model_revision_attestation"][
            "file_sha256"
        ] = "6" * 64

    def mutate_codeql_config(candidate):
        candidate["config_hashes"]["codeql_config.yaml"] = "5" * 64

    for index, mutate in enumerate(
        (
            mutate_decoding,
            mutate_runtime,
            mutate_endpoint,
            mutate_llm_attestation,
            mutate_scan_attestation,
            mutate_codeql_config,
        )
    ):
        output_dir = tmp_path / f"case-{index}"
        manager = AgentMemoryManager(output_dir=output_dir)
        manager.initialize(
            target_repo="repo",
            target_commit="abcdef",
            cve_id="CVE",
            module_priorities={"m": 1},
            file_to_module={"x.py": "m"},
            scan_signature=signature,
        )
        manager.mark_file("x.py", "completed")

        changed_signature = copy.deepcopy(signature)
        mutate(changed_signature)
        resumed_manager = AgentMemoryManager(output_dir=output_dir)
        resumed = resumed_manager.initialize(
            target_repo="repo",
            target_commit="abcdef",
            cve_id="CVE",
            module_priorities={"m": 1},
            file_to_module={"x.py": "m"},
            scan_signature=changed_signature,
        )

        assert resumed is False
        assert resumed_manager.get_scanned_files() == []
