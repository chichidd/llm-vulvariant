from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from profiler.software.models import ModuleInfo
from scanner.agent.prompts import (
    build_initial_user_message,
    build_intermediate_user_message,
    build_system_prompt,
)
from scanner.agent.schedule_window import (
    FROZEN_SCHEDULE_CONTRACT,
    build_schedule_page,
)


class _DummyToolkit:
    def sanitize_invariant_model_value(self, value):
        return value

    def sanitize_scheduled_model_value(self, value, *, preserve_active=True):
        _ = preserve_active
        return value

    def get_available_tools(self):
        return [
            {
                "function": {
                    "name": "report_vulnerability",
                    "description": "report a finding",
                }
            },
            {
                "function": {
                    "name": "mark_file_completed",
                    "description": "mark a file as analyzed",
                }
            },
        ]


def test_build_system_prompt_requires_mark_file_completed_usage():
    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _DummyToolkit(),
    )

    assert "mark_file_completed" in prompt
    assert "even if you did not find a vulnerability" in prompt
    assert "read_shared_public_memory" not in prompt


def test_build_system_prompt_mentions_shared_public_memory_only_when_tool_exists():
    class _ToolkitWithSharedMemory(_DummyToolkit):
        def get_available_tools(self):
            tools = super().get_available_tools()
            tools.append(
                {
                    "function": {
                        "name": "read_shared_public_memory",
                        "description": "read shared observations",
                    }
                }
            )
            return tools

    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _ToolkitWithSharedMemory(),
    )

    assert "read_shared_public_memory" in prompt


def test_build_system_prompt_mentions_available_shared_observations():
    class _ToolkitWithSharedMemory(_DummyToolkit):
        def get_available_tools(self):
            tools = super().get_available_tools()
            tools.append(
                {
                    "function": {
                        "name": "read_shared_public_memory",
                        "description": "read shared observations",
                    }
                }
            )
            return tools

    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _ToolkitWithSharedMemory(),
        shared_observation_count=3,
    )

    assert "There are already 3 reusable shared observations" in prompt
    assert "read them early before repeating broad searches" in prompt


def test_build_system_prompt_guides_focused_shared_memory_queries():
    class _ToolkitWithSharedMemory(_DummyToolkit):
        def get_available_tools(self):
            tools = super().get_available_tools()
            tools.append(
                {
                    "function": {
                        "name": "read_shared_public_memory",
                        "description": "read shared observations",
                    }
                }
            )
            return tools

    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _ToolkitWithSharedMemory(),
        shared_observation_count=3,
    )

    assert "Prefer a focused query derived from the current vulnerability pattern" in prompt
    assert "Do not default to an empty shared-memory query" in prompt


def test_build_system_prompt_defines_structured_search_contract():
    class _ToolkitWithSharedMemory(_DummyToolkit):
        def get_available_tools(self):
            tools = super().get_available_tools()
            tools.append(
                {
                    "function": {
                        "name": "read_shared_public_memory",
                        "description": "read shared observations",
                    }
                }
            )
            return tools

    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
            "query_terms": ["os.system", "request.args"],
            "dangerous_apis": ["os.system"],
            "source_indicators": ["request.args.get"],
            "sink_indicators": ["os.system(cmd)"],
            "negative_constraints": ["feature flag disabled"],
            "scan_start_points": ["src/api.py:entry"],
            "variant_hypotheses": ["subprocess.run(..., shell=True)"],
            "likely_false_positive_patterns": ["fixed literal command"],
        },
        _ToolkitWithSharedMemory(),
        shared_observation_count=2,
    )

    assert "query_terms" in prompt
    assert "dangerous_apis" in prompt
    assert "source_indicators" in prompt
    assert "sink_indicators" in prompt
    assert "negative_constraints" in prompt
    assert "scan_start_points" in prompt
    assert "variant_hypotheses" in prompt
    assert "likely_false_positive_patterns" in prompt
    assert "Identify the vulnerability pattern from query_terms, dangerous_apis" in prompt
    assert "Use scan_start_points as concrete anchors" in prompt
    assert "If shared observations are available, read them with a focused query before broad reads" in prompt
    assert "Search PRIORITY-1 scope first" in prompt
    assert "Widen to RELATED or repo-wide searches only when the current evidence is insufficient" in prompt
    assert "Record rejected hypotheses, evidence gaps, and next best queries" in prompt


def test_build_system_prompt_includes_summary_level_contract_fields():
    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
            "status": "ok",
            "confidence": "medium",
            "evidence": ["api.py:12"],
            "evidence_summary": "The known sink is grounded in api.py.",
            "uncertainty": "low",
        },
        _DummyToolkit(),
    )

    assert '"status": "ok"' in prompt
    assert '"confidence": "medium"' in prompt
    assert '"evidence_summary": "The known sink is grounded in api.py."' in prompt
    assert '"evidence_samples": [' in prompt
    assert '"evidence_count": 1' in prompt
    assert '"uncertainty": "low"' in prompt


def test_build_system_prompt_requires_report_evidence_gate():
    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "unsafe_deserialization"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _DummyToolkit(),
    )

    assert re.search(r"\brq\d+\b", prompt, flags=re.IGNORECASE) is None
    assert "Before calling report_vulnerability" in prompt
    assert "security claim verification contract" in prompt
    assert "attacker-controlled source" in prompt
    assert "trust boundary" in prompt
    assert "sink semantics" in prompt
    assert "protection analysis" in prompt
    assert "security impact" in prompt
    assert "counterevidence" in prompt
    assert "mark_file_completed with the rejection reason" in prompt


def test_build_initial_and_intermediate_messages_reinforce_completion_tracking():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [{"name": "m1", "files": ["a.py"], "description": "d", "key_functions": []}],
    }

    initial = build_initial_user_message(software_profile, {"m1": 1})
    intermediate = build_intermediate_user_message(scanned_files=["a.py"])

    assert "mark_file_completed" in initial
    assert "mark_file_completed" in intermediate


def test_build_messages_require_evidence_gap_tracking_before_widening_scope():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [
            {"name": "m1", "files": ["a.py"], "description": "affected", "key_functions": []},
            {"name": "m2", "files": ["b.py"], "description": "related", "key_functions": []},
        ],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m1": 1, "m2": 2},
        shared_observation_count=3,
    )
    intermediate = build_intermediate_user_message(
        scanned_files=["a.py"],
        shared_observation_count=3,
    )

    assert "Widen to 🟡 RELATED modules only when 🔴 PRIORITY-1 evidence is insufficient" in initial
    assert "Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries" in initial
    assert "Record rejected hypotheses, evidence gaps, shared-memory hits, and next best queries" in intermediate


def test_build_messages_surface_shared_public_memory_availability():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [{"name": "m1", "files": ["a.py"], "description": "d", "key_functions": []}],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m1": 1},
        shared_observation_count=5,
    )
    intermediate = build_intermediate_user_message(
        scanned_files=["a.py"],
        shared_observation_count=5,
    )

    assert "Shared public memory already has 5 reusable observations" in initial
    assert "Call read_shared_public_memory before broad searches" in initial
    assert "5 reusable observations are already available" in intermediate
    assert "Call `read_shared_public_memory` before repeating broad searches" in intermediate


def test_build_intermediate_user_message_compact_omits_large_inventory_lists():
    scanned_files = [f"file_{index}.py" for index in range(30)]
    findings = [
        {"file": f"vuln_{index}.py", "type": "command_injection", "confidence": "high"}
        for index in range(5)
    ]

    intermediate = build_intermediate_user_message(
        scanned_files=scanned_files,
        findings=findings,
        progress_info="10/30 files scanned, 5 findings.",
        shared_observation_count=3,
        compact=True,
    )

    assert "10/30 files scanned, 5 findings." in intermediate
    assert "Shared Public Memory" in intermediate
    assert "Already Reported Vulnerabilities" not in intermediate
    assert "Already Scanned Files" not in intermediate
    assert "5 previously reported vulnerabilities tracked in memory" in intermediate
    assert "30 previously scanned files tracked in memory" in intermediate
    assert "vuln_0.py" not in intermediate
    assert "file_0.py" not in intermediate


def test_build_initial_message_guides_shared_memory_first_when_priority_one_empty():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [{"name": "m3", "files": ["c.py"], "description": "other", "key_functions": []}],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m3": 3},
        shared_observation_count=2,
    )

    assert "No PRIORITY-1 modules are currently identified" in initial
    assert "Start by calling read_shared_public_memory with focused query terms" in initial
    assert "**Start with PRIORITY-1 modules**" not in initial
    assert "For each PRIORITY-1 module" not in initial


def test_build_initial_message_handles_no_priority_one_with_related_modules():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [
            {"name": "m2", "files": ["b.py"], "description": "related", "key_functions": []},
            {"name": "m3", "files": ["c.py"], "description": "other", "key_functions": []},
        ],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m2": 2, "m3": 3},
        shared_observation_count=1,
    )

    assert "No PRIORITY-1 modules are currently identified" in initial
    assert "🟡 RELATED (1 modules): Follow-up scope only after all PRIORITY-1 files are complete" not in initial
    assert "Widen to 🟡 RELATED modules only when 🔴 PRIORITY-1 evidence is insufficient" not in initial
    assert "Use 🟡 RELATED modules as the highest-priority concrete scan targets" in initial
    assert "then use 🟡 RELATED modules as the highest-priority concrete scan scope" in initial
    assert (
        "Begin analysis now. Start by reading shared public memory with a focused query, then use the 🟡 "
        "RELATED modules as the highest-priority concrete scope before any repo-wide widening."
    ) in initial


def test_build_initial_message_uses_module_priorities_when_profile_is_attribute_based():
    software_profile = SimpleNamespace(
        name="demo",
        modules=[
            {"name": "m2", "files": ["b.py"], "description": "related", "key_functions": []},
        ],
    )

    initial = build_initial_user_message(
        software_profile,
        {"m2": 2},
        shared_observation_count=0,
    )

    assert "Use 🟡 RELATED modules as the highest-priority concrete scan targets" in initial
    assert '"project_name": "demo"' in initial
    assert '"priority": "🟡 RELATED"' in initial


def test_build_initial_message_accepts_repo_native_module_objects():
    software_profile = SimpleNamespace(
        name="demo",
        modules=[
            ModuleInfo(
                name="m2",
                files=["b.py"],
                description="related",
                key_functions=["run"],
            ),
        ],
    )

    initial = build_initial_user_message(
        software_profile,
        {"m2": 2},
        shared_observation_count=0,
    )

    assert '"project_name": "demo"' in initial
    assert '"name": "m2"' in initial
    assert '"priority": "🟡 RELATED"' in initial
    assert '"files": [' in initial


def test_build_initial_message_starts_with_related_modules_when_no_priority_one_and_no_shared_memory():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [
            {"name": "m2", "files": ["b.py"], "description": "related", "key_functions": []},
            {"name": "m3", "files": ["c.py"], "description": "other", "key_functions": []},
        ],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m2": 2, "m3": 3},
        shared_observation_count=0,
    )

    assert "Use 🟡 RELATED modules as the highest-priority concrete scan targets" in initial
    assert "Start with focused repo-wide searches anchored on the vulnerability pattern" not in initial
    assert (
        "Begin analysis now. No PRIORITY-1 modules are currently identified, so start with focused "
        "repo-wide searches anchored on the vulnerability pattern."
    ) not in initial
    assert "Begin analysis now. Start with the 🟡 RELATED modules as the highest-priority concrete scope." in initial


def test_build_priority_one_messages_keep_focus_on_priority_one_modules():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [
            {"name": "m1", "files": ["a.py"], "description": "affected", "key_functions": []},
            {"name": "m2", "files": ["b.py"], "description": "related", "key_functions": []},
        ],
    }

    initial = build_initial_user_message(
        software_profile,
        {"m1": 1, "m2": 2},
        critical_stop_max_priority=1,
    )
    intermediate = build_intermediate_user_message(
        scanned_files=["a.py"],
        critical_stop_max_priority=1,
    )

    assert "critical scope is 🔴 PRIORITY-1 modules only" in initial
    assert "directly affected or embedding-similar" in initial
    assert "Do not spend analysis turns on 🟡 RELATED modules" in initial
    assert "Have you checked RELATED" not in intermediate
    assert "Do not spend turns on RELATED (🟡) modules" in intermediate


def test_build_intermediate_message_handles_no_priority_one_with_related_modules():
    intermediate = build_intermediate_user_message(
        scanned_files=["b.py"],
        shared_observation_count=2,
        has_priority_one=False,
        has_related=True,
    )

    assert "No PRIORITY-1 modules are currently identified" in intermediate
    assert "scan ALL files in 🟡 RELATED modules before any repo-wide widening" in intermediate
    assert "Have you scanned ALL files in PRIORITY-1" not in intermediate
    assert "Have you checked RELATED" not in intermediate


def test_build_intermediate_message_handles_no_priority_one_or_related_without_shared_memory():
    intermediate = build_intermediate_user_message(
        scanned_files=["done.py"],
        shared_observation_count=0,
        has_priority_one=False,
        has_related=False,
    )

    assert "No PRIORITY-1 or RELATED modules are currently identified" in intermediate
    assert "scan_start_points and focused repo-wide searches" in intermediate
    assert "shared-memory queries" not in intermediate


def test_system_prompt_exposes_scoped_verifier_and_candidate_priority_ablations():
    prompt = build_system_prompt(
        {
            "cve_id": "CVE-2026-0001",
            "sink_features": {"type": "command_injection"},
            "vuln_description": "desc",
            "vuln_cause": "cause",
            "payload": "payload",
            "source_features": {},
            "flow_features": {},
            "exploit_scenarios": [],
            "exploit_conditions": [],
        },
        _DummyToolkit(),
        verifier_enabled=False,
        candidate_priority_enabled=False,
        candidate_file_order=["src/b.py", "src/a.py"],
    )

    assert "Claim-verifier ablation" in prompt
    assert "same-type verifier gate are disabled" in prompt
    assert "Candidate-priority ablation is active" in prompt
    assert "Frozen global schedule contract" in prompt
    assert FROZEN_SCHEDULE_CONTRACT in prompt
    assert "src/b.py" not in prompt and "src/a.py" not in prompt


def test_initial_prompt_candidate_priority_ablation_points_to_system_schedule():
    software_profile = SimpleNamespace(
        modules=[
            ModuleInfo(name="api", files=["api.py"]),
            ModuleInfo(name="worker", files=["worker.py"]),
        ]
    )

    prompt = build_initial_user_message(
        software_profile,
        {"api": 1, "worker": 3},
        candidate_priority_enabled=False,
        candidate_file_order=["worker.py", "api.py"],
        candidate_schedule_page=build_schedule_page(
            ["worker.py", "api.py"],
            cursor=0,
        ),
    )

    assert "active_frozen_schedule_window" in prompt
    assert '"total_file_count": 2' in prompt
    assert '"modules"' not in prompt
    assert "UNIFORM" not in prompt
    assert prompt.index('"worker.py"') < prompt.index('"api.py"')


def test_prioritized_initial_prompt_ignores_candidate_file_order_argument():
    software_profile = SimpleNamespace(
        modules=[
            ModuleInfo(name="api", files=["api.py"]),
            ModuleInfo(name="worker", files=["worker.py"]),
        ]
    )

    prompt = build_initial_user_message(
        software_profile,
        {"api": 1, "worker": 2},
        candidate_priority_enabled=True,
        candidate_file_order=["worker.py", "api.py"],
    )

    assert prompt.index('"api"') < prompt.index('"worker"')
    assert prompt.index('"api.py"') < prompt.index('"worker.py"')
    assert "Frozen global unique file schedule" not in prompt

def test_reference_semantics_ablation_exposes_only_opaque_card_fields():
    profile = {
        "schema_version": 1,
        "card_id": "card-public-7",
        "weaknesses": ["CWE-22", "CWE-78"],
        "cve_id": "CVE-2026-9999",
        "query_terms": ["SECRET-QUERY"],
        "dangerous_apis": ["SECRET-API"],
        "source_features": {"sentinel": "SECRET-SOURCE"},
        "sink_features": {"sentinel": "SECRET-SINK"},
        "negative_constraints": ["SECRET-NEGATIVE"],
        "evidence": ["SECRET-EVIDENCE"],
    }
    prompt = build_system_prompt(
        profile,
        _DummyToolkit(),
        reference_semantics_enabled=False,
    )
    assert "card-public-7" in prompt
    assert "CWE-22" in prompt and "CWE-78" in prompt
    for secret in (
        "CVE-2026-9999", "SECRET-QUERY", "SECRET-API", "SECRET-SOURCE",
        "SECRET-SINK", "SECRET-NEGATIVE", "SECRET-EVIDENCE",
    ):
        assert secret not in prompt
    for hidden_field in (
        "query_terms", "dangerous_apis", "source_features", "sink_features",
        "negative_constraints", "evidence_samples",
    ):
        assert hidden_field not in prompt


def test_frozen_candidate_order_is_complete_unique_and_module_independent():
    files = ["src/shared.py", *[f"src/file_{index:02d}.py" for index in range(60)]]
    schedule = [*files[1::2], *files[::2]]
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [
            {
                "name": "alpha-overlap-module",
                "files": ["src/shared.py", *files[2::2]],
                "description": "alpha",
            },
            {
                "name": "beta-overlap-module",
                "files": ["src/shared.py", *files[1::2]],
                "description": "beta",
            },
        ],
    }
    vulnerability_profile = {
        "cve_id": "CVE-2026-0001",
        "sink_features": {"type": "command_injection"},
        "vuln_description": "desc",
        "vuln_cause": "cause",
        "payload": "payload",
        "source_features": {},
        "flow_features": {},
        "exploit_scenarios": [],
        "exploit_conditions": [],
        "scan_start_points": schedule[:3],
    }

    for reference_semantics_enabled in (True, False):
        system_prompt = build_system_prompt(
            vulnerability_profile,
            _DummyToolkit(),
            candidate_priority_enabled=False,
            candidate_file_order=schedule,
            reference_semantics_enabled=reference_semantics_enabled,
        )
        initial_prompt = build_initial_user_message(
            software_profile,
            {"alpha-overlap-module": 1, "beta-overlap-module": 1},
            candidate_priority_enabled=False,
            candidate_file_order=schedule,
            candidate_schedule_page=build_schedule_page(schedule, cursor=0),
            reference_semantics_enabled=reference_semantics_enabled,
        )
        combined = system_prompt + initial_prompt

        assert len(schedule) > 50
        assert len(schedule) == len(set(schedule))
        assert all(combined.count(f'"{path}"') == 1 for path in schedule)
        assert all(path not in system_prompt for path in schedule)
        assert [initial_prompt.index(f'"{path}"') for path in schedule] == sorted(
            initial_prompt.index(f'"{path}"') for path in schedule
        )
        assert '"total_file_count": 61' in initial_prompt
        assert '"modules"' not in initial_prompt
        assert "presented_prefix" not in combined
        assert "alpha-overlap-module" not in initial_prompt
        assert "beta-overlap-module" not in initial_prompt
        assert FROZEN_SCHEDULE_CONTRACT in combined


def test_intermediate_prompt_projects_scanned_files_through_frozen_schedule():
    schedule = ["src/z.py", "src/a.py", "src/m.py"]
    prompt = build_intermediate_user_message(
        scanned_files=["src/m.py", "outside.py", "src/a.py", "src/a.py"],
        pending_files=["src/z.py", "outside.py", "src/z.py"],
        findings=[
            {"file": "src/m.py", "type": "cmd", "confidence": "high"},
            {"file": "src/a.py", "type": "path", "confidence": "medium"},
            {"file": "src/a.py", "type": "cmd", "confidence": "low"},
            {"file": "outside.py", "type": "outside", "confidence": "high"},
        ],
        shared_observation_count=0,
        has_priority_one=False,
        has_related=False,
        candidate_priority_enabled=False,
        candidate_file_order=schedule,
        candidate_schedule_page=build_schedule_page(
            schedule,
            cursor=0,
            completed_files=["src/a.py", "src/m.py"],
        ),
    )

    assert "src/a.py" not in prompt
    assert "src/m.py" not in prompt
    assert prompt.count("src/z.py") == 1
    assert "outside.py" not in prompt
    assert '"completed_window_offsets": [' in prompt
    assert "PRIORITY-1" not in prompt
    assert "RELATED" not in prompt


def test_intermediate_prompt_does_not_truncate_large_scheduled_scan_history():
    schedule = [f"src/file_{index:02d}.py" for index in range(61)]
    scanned = [*reversed(schedule[:55]), schedule[4], "outside.py"]
    pending = [*reversed(schedule[55:]), schedule[56], "outside.py"]

    for reference_semantics_enabled in (True, False):
        prompt = build_intermediate_user_message(
            scanned_files=scanned,
            pending_files=pending,
            candidate_priority_enabled=False,
            candidate_file_order=schedule,
            candidate_schedule_page=build_schedule_page(
                schedule,
                cursor=0,
                completed_files=schedule[:55],
            ),
            reference_semantics_enabled=reference_semantics_enabled,
        )
        pending_schedule = schedule[55:]
        positions = [prompt.index(path) for path in pending_schedule]
        assert positions == sorted(positions)
        assert all(path not in prompt for path in schedule[:55])
        assert all(prompt.count(path) == 1 for path in pending_schedule)
        assert "outside.py" not in prompt
        assert "... and" not in prompt


def test_candidate_priority_ablation_requires_schedule_at_every_prompt_boundary():
    with pytest.raises(ValueError, match="requires a frozen global file schedule"):
        build_system_prompt(
            {},
            _DummyToolkit(),
            candidate_priority_enabled=False,
        )
    with pytest.raises(ValueError, match="requires a frozen global file schedule"):
        build_initial_user_message(
            SimpleNamespace(modules=[]),
            candidate_priority_enabled=False,
        )
    with pytest.raises(ValueError, match="requires a frozen global file schedule"):
        build_intermediate_user_message(
            candidate_priority_enabled=False,
        )
