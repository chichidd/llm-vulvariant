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


def test_agent_memory_manager_treats_empty_priority_scope_as_critical_complete(tmp_path):
    mgr = AgentMemoryManager(output_dir=tmp_path)
    mgr.initialize(
        target_repo="repo",
        target_commit="abcdef",
        cve_id="CVE",
        module_priorities={"other": 3},
        file_to_module={"x.py": "other"},
    )

    assert mgr.is_critical_complete() is True


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


def test_agent_memory_manager_markdown_matches_priority_one_scope(tmp_path):
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

    assert "**Critical Scope**: priority-1 (affected) only" in markdown
    assert "Incomplete Critical Files" not in markdown


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

    assert "**Critical Scope**: priority-1/2 (affected + related)" in markdown
    assert "Incomplete Critical Files" in markdown
    assert "- [ ] `b.py`" in markdown
