import json

from scanner.agent import toolkit as toolkit_module
from scanner.agent.shared_memory import SharedPublicMemoryManager


class _FakeCodeQLAnalyzer:
    def __init__(self, *args, **kwargs):
        self.is_available = True


def test_shared_public_memory_manager_deduplicates_and_filters_by_repo_commit(tmp_path):
    writer = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001",
    )
    reader = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0999",
    )
    other_writer = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="b" * 40,
        producer_id="CVE-2026-0002",
    )
    other_reader = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="b" * 40,
        producer_id="CVE-2026-0998",
    )

    writer.record_observation(
        "search_in_file",
        {"file_path": "app.py", "pattern": "yaml.load"},
        {
            "file_path": "app.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 14, "line_text": "yaml.load(payload)"}],
        },
    )
    writer.record_observation(
        "search_in_file",
        {"file_path": "app.py", "pattern": "yaml.load"},
        {
            "file_path": "app.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 14, "line_text": "yaml.load(payload)"}],
        },
    )
    other_writer.record_observation(
        "search_in_file",
        {"file_path": "other.py", "pattern": "pickle.load"},
        {
            "file_path": "other.py",
            "pattern": "pickle.load",
            "match_count": 1,
            "matches": [{"line_number": 9, "line_text": "pickle.load(handle)"}],
        },
    )

    current_results = reader.read_observations(query="yaml", limit=10)
    other_results = other_reader.read_observations(query="pickle", limit=10)

    assert current_results["total"] == 1
    assert current_results["observations"][0]["summary"]["match_count"] == 1
    assert current_results["observations"][0]["summary"]["matches"][0]["line_text"] == "yaml.load(payload)"
    assert other_results["total"] == 1
    assert other_results["observations"][0]["summary"]["file_path"] == "other.py"


def test_shared_public_memory_scope_excludes_current_producer(tmp_path):
    manager = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="scan-a",
    )
    manager.record_observation(
        "search_in_file",
        {"file_path": "foreign.py", "pattern": "yaml.load"},
        {
            "file_path": "foreign.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 4, "line_text": "yaml.load(payload)"}],
        },
    )
    same_scan_manager = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="scan-b",
    )
    same_scan_manager.record_observation(
        "search_in_file",
        {"file_path": "self.py", "pattern": "yaml.load"},
        {
            "file_path": "self.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 9, "line_text": "yaml.load(other)"}],
        },
    )

    scope = same_scan_manager.describe_scope()
    payload = same_scan_manager.read_observations(query="yaml", limit=10)

    assert scope["observation_count"] == 1
    assert payload["total"] == 1
    assert payload["observations"][0]["summary"]["file_path"] == "foreign.py"


def test_shared_public_memory_ignores_comment_only_search_matches(tmp_path):
    manager = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="scan-a",
    )

    persisted = manager.record_observation(
        "search_in_folder",
        {"folder_path": ".", "pattern": "shell\\s*=\\s*True", "max_results": 50},
        {
            "folder_path": ".",
            "pattern": "shell\\s*=\\s*True",
            "match_count": 2,
            "files": ["cli.py", "runner.py"],
            "matches": [
                {
                    "file_path": "cli.py",
                    "line_number": 10,
                    "line_text": "# NOTE: DO NOT USE shell=True to avoid security risk",
                },
                {
                    "file_path": "runner.py",
                    "line_number": 20,
                    "line_text": "   // shell=True is dangerous here",
                },
            ],
        },
    )

    assert persisted is None
    assert manager.describe_scope()["observation_count"] == 0


def test_shared_public_memory_visibility_is_not_order_dependent_across_producers(tmp_path):
    first_attempt = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001:attempt-a",
        visibility_scope_id="scan-a",
    )
    second_attempt = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001:attempt-b",
        visibility_scope_id="scan-b",
    )

    observation_parameters = {"file_path": "app.py", "pattern": "yaml.load"}
    observation_summary = {
        "file_path": "app.py",
        "pattern": "yaml.load",
        "match_count": 1,
        "matches": [{"line_number": 14, "line_text": "yaml.load(payload)"}],
    }

    first_attempt.record_observation("search_in_file", observation_parameters, observation_summary)
    second_attempt.record_observation("search_in_file", observation_parameters, observation_summary)

    payload = first_attempt.read_observations(query="yaml", limit=10)
    scope = first_attempt.describe_scope()

    assert payload["total"] == 1
    assert payload["observations"][0]["producer_ids"] == [
        "CVE-2026-0001:attempt-a",
        "CVE-2026-0001:attempt-b",
    ]
    assert payload["observations"][0]["scan_scope_ids"] == ["scan-a", "scan-b"]
    assert scope["observation_count"] == 1


def test_shared_public_memory_hides_previous_attempts_from_same_logical_scan(tmp_path):
    previous_attempt = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="attempt-a",
        visibility_scope_id="scan-a",
    )
    previous_attempt.record_observation(
        "search_in_file",
        {"file_path": "app.py", "pattern": "yaml.load"},
        {
            "file_path": "app.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 14, "line_text": "yaml.load(payload)"}],
        },
    )

    resumed_same_scan = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="attempt-b",
        visibility_scope_id="scan-a",
    )
    other_scan = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="attempt-c",
        visibility_scope_id="scan-b",
    )

    assert resumed_same_scan.describe_scope()["observation_count"] == 0
    assert resumed_same_scan.read_observations(query="yaml", limit=10)["total"] == 0
    assert other_scan.describe_scope()["observation_count"] == 1
    assert other_scan.read_observations(query="yaml", limit=10)["total"] == 1


def test_agentic_toolkit_records_and_reads_shared_public_memory(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("yaml.load(payload)\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    seed_manager = SharedPublicMemoryManager(
        root_dir=tmp_path / "shared",
        repo_name="repo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0000",
    )
    seed_manager.record_observation(
        "search_in_file",
        {"file_path": "seed.py", "pattern": "yaml.load"},
        {
            "file_path": "seed.py",
            "pattern": "yaml.load",
            "match_count": 1,
            "matches": [{"line_number": 2, "line_text": "yaml.load(seed_payload)"}],
        },
    )
    shared_manager = SharedPublicMemoryManager(
        root_dir=tmp_path / "shared",
        repo_name="repo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001",
    )
    toolkit = toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        languages=["python"],
        shared_public_memory_manager=shared_manager,
    )

    search_result = toolkit.execute_tool(
        "search_in_file",
        {"file_path": "app.py", "pattern": "yaml.load"},
    )
    read_result = toolkit.execute_tool(
        "read_shared_public_memory",
        {"query": "yaml", "limit": 5},
    )
    payload = json.loads(read_result.content)

    assert search_result.success is True
    assert read_result.success is True
    assert payload["total"] == 1
    assert payload["observations"][0]["tool_name"] == "search_in_file"
    assert payload["observations"][0]["summary"]["file_path"] == "seed.py"
    assert any(
        tool["function"]["name"] == "read_shared_public_memory"
        for tool in toolkit.get_available_tools()
    )


def test_agentic_toolkit_keeps_successful_tool_result_when_shared_memory_write_fails(tmp_path, monkeypatch):
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "app.py").write_text("yaml.load(payload)\n", encoding="utf-8")

    monkeypatch.setattr(
        toolkit_module,
        "_path_config",
        {
            "repo_root": tmp_path,
            "codeql_db_path": tmp_path / "codeql-dbs",
        },
    )
    monkeypatch.setattr(toolkit_module, "CodeQLAnalyzer", _FakeCodeQLAnalyzer)

    shared_manager = SharedPublicMemoryManager(
        root_dir=tmp_path / "shared",
        repo_name="repo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001",
    )
    monkeypatch.setattr(
        shared_manager,
        "record_observation",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("disk full")),
    )
    toolkit = toolkit_module.AgenticToolkit(
        repo_path=repo_path,
        languages=["python"],
        shared_public_memory_manager=shared_manager,
    )

    result = toolkit.execute_tool(
        "search_in_file",
        {"file_path": "app.py", "pattern": "yaml.load"},
    )

    assert result.success is True
    assert "Found 1 matches" in result.content


def test_shared_public_memory_reader_clamps_large_limit(tmp_path):
    writer = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001",
    )
    reader = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0002",
    )
    for index in range(30):
        writer.record_observation(
            "search_in_file",
            {"file_path": f"app_{index}.py", "pattern": "yaml.load"},
            {
                "file_path": f"app_{index}.py",
                "pattern": "yaml.load",
                "match_count": 1,
                "matches": [{"line_number": index + 1, "line_text": "yaml.load(payload)"}],
            },
        )

    payload = reader.read_observations(query="yaml", limit=1000)

    assert payload["total"] == 20


def test_shared_public_memory_skips_zero_result_search_observations(tmp_path):
    manager = SharedPublicMemoryManager(
        root_dir=tmp_path,
        repo_name="demo",
        repo_commit="a" * 40,
        producer_id="CVE-2026-0001",
    )

    persisted = manager.record_observation(
        "search_in_file",
        {"file_path": "./app.py", "pattern": "yaml.load"},
        {
            "file_path": "app.py",
            "pattern": "yaml.load",
            "match_count": 0,
            "matches": [],
        },
    )

    assert persisted is None
    assert manager.read_observations(query="yaml", limit=10)["total"] == 0
