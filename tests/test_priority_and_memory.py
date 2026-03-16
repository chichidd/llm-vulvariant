from pathlib import Path

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.agent.memory import AgentMemoryManager
from scanner.agent.priority import calculate_module_priorities



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

    mgr.mark_file("a.py", "completed")
    mgr.mark_file("b.py", "skipped")
    progress = mgr.get_progress()
    summary = mgr.summarize_statuses(mgr.memory.file_status)

    assert added is True
    assert duplicate is False
    assert progress["completed"] == 1
    assert progress["priority_1"]["completed"] == 1
    assert mgr.get_pending_files(max_priority=2) == []
    assert summary == "1 completed, 0 pending, 1 skipped, 0 not tracked"


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
