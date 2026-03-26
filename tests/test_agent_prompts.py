from __future__ import annotations

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


def test_build_initial_and_intermediate_messages_reinforce_completion_tracking():
    software_profile = {
        "basic_info": {"name": "demo"},
        "modules": [{"name": "m1", "files": ["a.py"], "description": "d", "key_functions": []}],
    }

    initial = build_initial_user_message(software_profile, {"m1": 1})
    intermediate = build_intermediate_user_message(scanned_files=["a.py"])

    assert "mark_file_completed" in initial
    assert "mark_file_completed" in intermediate


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
