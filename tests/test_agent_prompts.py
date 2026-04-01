from __future__ import annotations

from types import SimpleNamespace

from profiler.software.models import ModuleInfo
from scanner.agent.prompts import (
    build_initial_user_message,
    build_intermediate_user_message,
    build_system_prompt,
)


class _DummyToolkit:
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
