import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli.agent_scanner as agent_scanner
import profiler.fingerprint as fingerprint_module
import scanner.agent.finder as finder_module
import source_snapshot
from llm.client import LLMRetryExhaustedError
from scanner.agent.toolkit import AgenticToolkit as RealAgenticToolkit


class DummyLLM:
    def __init__(self):
        self.config = SimpleNamespace(max_tokens=128)
        self.context_limit = 4096
        self._last_usage_summary = {}

    def chat(self, *args, **kwargs):
        raise RuntimeError("not expected")

    def get_last_usage_summary(self):
        return dict(self._last_usage_summary)


class DummyToolkit:
    def sanitize_invariant_model_value(self, value):
        return value

    def sanitize_scheduled_model_value(self, value, *, preserve_active=True):
        _ = preserve_active
        return value

    def __init__(self, repo_path, **kwargs):
        self.repo_path = repo_path

    def set_memory_manager(self, memory):
        self.memory = memory

    def set_software_profile(self, software_profile):
        self.software_profile = software_profile

    def get_available_tools(self):
        return []


class DummyMemory:
    def __init__(self):
        self.summary_called = False
        self.markdown_called = False
        self.completed = []

    def generate_summary(self):
        self.summary_called = True

    def save_markdown(self):
        self.markdown_called = True

    def get_progress(self):
        return {
            "completed": 1,
            "total_files": 2,
            "findings": 0,
            "priority_1": {"completed": 1, "total": 1},
        }

    def format_progress_info(self):
        progress = self.get_progress()
        return (
            f"{progress['completed']}/{progress['total_files']} files scanned, "
            f"{progress['findings']} findings. "
            f"Priority-1: {progress['priority_1']['completed']}/{progress['priority_1']['total']}, "
            f"Priority-2: {progress.get('priority_2', {}).get('completed', 0)}/"
            f"{progress.get('priority_2', {}).get('total', 0)}."
        )

    def is_critical_complete(self):
        return True

    def mark_file_completed(self, file_path: str, reason: str = ""):
        self.completed.append((file_path, reason))


class _CaptureScanSignatureMemory:
    def __init__(self, output_dir, llm_client=None):
        self.output_dir = output_dir
        self.llm_client = llm_client
        self.initialize_kwargs = None
        self.memory = SimpleNamespace(file_status={})

    def initialize(self, **kwargs):
        self.initialize_kwargs = dict(kwargs)
        return False


def _decoding_binding():
    payload = {
        "temperature": 0.2,
        "top_p": 0.9,
        "max_tokens": 1536,
        "enable_thinking": True,
        "reasoning_effort": "high",
        "service_tier": "priority",
    }
    return payload, finder_module.stable_data_hash(payload)


class _LLMWithFullConfig:
    def __init__(self):
        decoding, _sha256 = _decoding_binding()
        self.config = SimpleNamespace(
            provider="provider-x",
            model="model-x",
            base_url="https://api.example.com",
            **decoding,
            fallback_on_retry_exhausted=False,
            enforce_exact_decoding=True,
        )



def _make_finder(monkeypatch, tmp_path=None):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    llm = DummyLLM()
    software_profile = SimpleNamespace(version="target123", modules=[])
    vuln_profile = SimpleNamespace(cve_id="CVE-2025-0001", to_dict=lambda: {"cve_id": "CVE-2025-0001"})
    return finder_module.AgenticVulnFinder(
        llm_client=llm,
        repo_path=Path("/tmp/demo"),
        software_profile=software_profile,
        vulnerability_profile=vuln_profile,
        max_iterations=5,
        verbose=False,
        output_dir=tmp_path,
    )


def test_finder_defaults_max_tokens_from_llm_client(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    assert finder.max_tokens == 128


def test_init_memory_tracks_scan_signature(monkeypatch, tmp_path):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    monkeypatch.setattr(finder_module, "AgentMemoryManager", _CaptureScanSignatureMemory)
    monkeypatch.setattr(
        finder_module,
        "embedding_model_artifact_signature",
        lambda model_name: {
            "resolved_model_path": f"/models/{model_name or 'default'}",
            "artifact_hash": "artifact-hash",
        },
    )
    monkeypatch.setitem(
        finder_module._scanner_config["module_similarity"],
        "threshold",
        0.8,
    )

    endpoint_snapshot = {
        "snapshot_id": "deployment-2026-08-01-a",
        "base_url": "https://api.example.com",
        "api_family": "openai_compatible",
    }
    endpoint_snapshot_sha256 = finder_module.stable_data_hash(
        endpoint_snapshot
    )
    decoding_config, decoding_config_sha256 = _decoding_binding()
    attestation_binding = {
        "path": "rq2/inputs/model-revision-attestations/model-x.json",
        "file_sha256": "8" * 64,
        "payload_sha256": "9" * 64,
    }
    finder = finder_module.AgenticVulnFinder(
        llm_client=_LLMWithFullConfig(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=12,
        stop_when_critical_complete=True,
        critical_stop_mode="min",
        critical_stop_max_priority=1,
        verbose=False,
        output_dir=tmp_path,
        languages=["python", "java"],
        codeql_database_names={"python": "db-py", "java": "db-java"},
        model_revision="revision-a",
        model_revision_attestation_binding=attestation_binding,
        endpoint_snapshot=endpoint_snapshot,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_requested=decoding_config,
        decoding_config_requested_sha256=decoding_config_sha256,
        decoding_config_effective=decoding_config,
        decoding_config_effective_sha256=decoding_config_sha256,
    )

    signature = finder.memory.initialize_kwargs["scan_signature"]
    scan_config = signature["scan_config"]
    llm_config = signature["llm"]

    assert scan_config["max_iterations"] == 12
    assert scan_config["stop_when_critical_complete"] is True
    assert scan_config["critical_stop_mode"] == "min"
    assert scan_config["critical_stop_max_priority"] == 1
    assert set(scan_config["scan_languages"]) == {"python", "java"}
    assert scan_config["codeql_database_names"] == {
        "python": "db-py",
        "java": "db-java",
    }
    assert scan_config["shared_public_memory"] == {
        "enabled": False,
        "root_hash": "",
        "scope_key": "",
        "state_hash": "",
    }
    assert scan_config["reference_profile_hash"] == finder_module.stable_data_hash({"cve_id": "CVE-2025-0001"})
    assert scan_config["module_similarity"] == {
        "threshold": 0.8,
        "model_name": "jinaai--jina-code-embeddings-1.5b",
        "device": "cpu",
        "resolved_model_path": "/models/jinaai--jina-code-embeddings-1.5b",
        "artifact_hash": "artifact-hash",
    }
    assert scan_config["module_similarity_byte_binding"] == {
        "status": "unattested",
        "blocker_code": "consumed-embedding-bytes-unattested",
    }
    assert "scanner/similarity/retriever.py" in signature["source_hashes"]
    assert "scanner/similarity/embedding.py" in signature["source_hashes"]
    assert "scanner/agent/utils.py" in signature["source_hashes"]
    assert "scanner/agent/loaders.py" in signature["source_hashes"]
    assert "profiler/fingerprint.py" in signature["source_hashes"]
    assert "profiler/software/models.py" in signature["source_hashes"]
    assert "profiler/vulnerability/models.py" in signature["source_hashes"]
    for source_path in (
        "llm/__init__.py",
        "llm/client.py",
        "llm/tool_arguments.py",
        "utils/llm_usage.py",
        "utils/claude_cli.py",
        "utils/number_utils.py",
    ):
        assert source_path in signature["source_hashes"]
    assert "scanner/agent/toolkit_reporting.py" in signature["source_hashes"]
    assert "scanner/agent/toolkit_profile.py" in signature["source_hashes"]
    assert "config.py" in signature["source_hashes"]
    assert "utils/codeql_native.py" in signature["source_hashes"]
    config_root = Path(finder_module.__file__).resolve().parents[3] / "config"
    assert signature["config_hashes"] == {
        filename: hashlib.sha256(
            (config_root / filename).read_bytes()
        ).hexdigest()
        for filename in (
            "paths.yaml",
            "scanner_config.yaml",
            "codeql_config.yaml",
            "llm_config.yaml",
        )
    }
    assert llm_config["provider"] == "provider-x"
    assert llm_config["model"] == "model-x"
    assert llm_config["model_revision"] == "revision-a"
    assert llm_config["model_revision_attestation"] == attestation_binding
    assert (
        scan_config["model_revision_attestation"]
        == attestation_binding
    )
    assert llm_config["endpoint_snapshot"] == endpoint_snapshot
    assert (
        llm_config["endpoint_snapshot_sha256"]
        == endpoint_snapshot_sha256
    )
    assert scan_config["endpoint_snapshot"] == endpoint_snapshot
    assert (
        scan_config["endpoint_snapshot_sha256"]
        == endpoint_snapshot_sha256
    )
    assert llm_config["base_url"] == "https://api.example.com"
    assert llm_config["temperature"] == 0.2
    assert llm_config["reasoning_effort"] == "high"
    assert llm_config["service_tier"] == "priority"
    assert llm_config["exact_decoding_enforced"] is True
    for section in (llm_config, scan_config):
        assert section["decoding_config_requested"] == decoding_config
        assert (
            section["decoding_config_requested_sha256"]
            == decoding_config_sha256
        )
        assert section["decoding_config_effective"] == decoding_config
        assert (
            section["decoding_config_effective_sha256"]
            == decoding_config_sha256
        )

    outer = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=finder.vulnerability_profile,
        software_profile=finder.software_profile,
        llm_client=finder.llm_client,
        max_iterations=finder.max_iterations,
        stop_when_critical_complete=finder.stop_when_critical_complete,
        critical_stop_mode=finder.critical_stop_mode,
        critical_stop_max_priority=finder.critical_stop_max_priority,
        scan_languages=finder.scan_languages,
        codeql_database_names=finder.codeql_database_names,
        model_revision=finder.model_revision,
        model_revision_attestation_binding=attestation_binding,
        endpoint_snapshot=endpoint_snapshot,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_requested=decoding_config,
        decoding_config_requested_sha256=decoding_config_sha256,
        decoding_config_effective=decoding_config,
        decoding_config_effective_sha256=decoding_config_sha256,
    )
    source_root = Path(finder_module.__file__).resolve().parents[2]
    independently_hashed_sources = {
        source_path.relative_to(source_root).as_posix(): hashlib.sha256(
            source_path.read_bytes()
        ).hexdigest()
        for source_path in sorted(
            source_root.rglob("*.py"),
            key=lambda path: path.relative_to(source_root).as_posix().encode(
                "utf-8"
            ),
        )
    }
    assert len(independently_hashed_sources) >= 76
    assert "config_snapshot.py" in independently_hashed_sources
    assert "source_snapshot.py" in independently_hashed_sources
    assert "scanner/evaluation_contract.py" in independently_hashed_sources
    assert signature["source_hashes"] == independently_hashed_sources
    assert signature["source_hashes"] == outer["source_hashes"]
    assert signature["config_hashes"] == outer["config_hashes"]
    for section in ("llm", "scan_config"):
        assert (
            signature[section]["model_revision_attestation"]
            == outer[section]["model_revision_attestation"]
            == attestation_binding
        )


def test_finder_rejects_invalid_endpoint_snapshot_binding(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)

    with pytest.raises(ValueError, match="endpoint snapshot binding"):
        finder_module.AgenticVulnFinder(
            llm_client=DummyLLM(),
            repo_path=Path("/tmp/demo"),
            software_profile=SimpleNamespace(version="target123", modules=[]),
            vulnerability_profile=SimpleNamespace(cve_id="CVE-2025-0001"),
            verbose=False,
            output_dir=None,
            endpoint_snapshot={
                "snapshot_id": "deployment-a",
                "base_url": "https://api.example.com",
                "api_family": "openai_compatible",
            },
            endpoint_snapshot_sha256="0" * 64,
        )


def test_finder_rejects_non_exact_model_revision(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)

    with pytest.raises(ValueError, match="non-empty exact string"):
        finder_module.AgenticVulnFinder(
            llm_client=DummyLLM(),
            repo_path=Path("/tmp/demo"),
            software_profile=SimpleNamespace(version="target123", modules=[]),
            vulnerability_profile=SimpleNamespace(cve_id="CVE-2025-0001"),
            verbose=False,
            output_dir=None,
            model_revision=" revision-a ",
        )


@pytest.mark.parametrize(
    "binding",
    [
        {
            "path": "/absolute/attestation.json",
            "file_sha256": "8" * 64,
            "payload_sha256": "9" * 64,
        },
        {
            "path": "../attestation.json",
            "file_sha256": "8" * 64,
            "payload_sha256": "9" * 64,
        },
        {
            "path": "rq2/attestation.json",
            "file_sha256": "A" * 64,
            "payload_sha256": "9" * 64,
        },
        {
            "path": "rq2/attestation.json",
            "file_sha256": "8" * 64,
            "payload_sha256": " 9" + ("9" * 63),
        },
    ],
)
def test_finder_rejects_nonexact_model_revision_attestation_binding(
    monkeypatch,
    binding,
):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)

    with pytest.raises(ValueError, match="model revision attestation"):
        finder_module.AgenticVulnFinder(
            llm_client=DummyLLM(),
            repo_path=Path("/tmp/demo"),
            software_profile=SimpleNamespace(
                version="target123",
                modules=[],
            ),
            vulnerability_profile=SimpleNamespace(
                cve_id="CVE-2025-0001"
            ),
            verbose=False,
            output_dir=None,
            model_revision_attestation_binding=binding,
        )


def test_scanner_config_hashes_cover_exact_raw_files_and_mutations(
    tmp_path,
):
    config_root = tmp_path / "config"
    config_root.mkdir()
    filenames = (
        "paths.yaml",
        "scanner_config.yaml",
        "codeql_config.yaml",
        "llm_config.yaml",
    )
    for index, filename in enumerate(filenames):
        (config_root / filename).write_bytes(
            f"fixture-{index}\n".encode("utf-8")
        )

    before = fingerprint_module.hash_scanner_config_files(config_root)
    assert tuple(before) == filenames
    assert before == {
        filename: hashlib.sha256(
            (config_root / filename).read_bytes()
        ).hexdigest()
        for filename in filenames
    }

    (config_root / "codeql_config.yaml").write_bytes(
        b"mutated-codeql-config\n"
    )
    after = fingerprint_module.hash_scanner_config_files(config_root)
    assert after["codeql_config.yaml"] != before["codeql_config.yaml"]
    assert {
        key
        for key in filenames
        if after[key] != before[key]
    } == {"codeql_config.yaml"}

    incomplete_root = tmp_path / "incomplete-config"
    incomplete_root.mkdir()
    for filename in filenames[:-1]:
        (incomplete_root / filename).write_bytes(b"fixture\n")
    with pytest.raises(ValueError, match="llm_config.yaml"):
        fingerprint_module.hash_scanner_config_files(incomplete_root)


def test_python_source_tree_hashes_new_modules_and_rejects_symlinks(
    tmp_path,
):
    source_root = tmp_path / "src"
    nested = source_root / "scanner"
    nested.mkdir(parents=True)
    (source_root / "a.py").write_bytes(b"A = 1\n")
    (nested / "b.py").write_bytes(b"B = 2\n")

    before = finder_module.hash_python_source_tree(source_root)
    assert before == {
        "a.py": hashlib.sha256(b"A = 1\n").hexdigest(),
        "scanner/b.py": hashlib.sha256(b"B = 2\n").hexdigest(),
    }

    (nested / "new_runtime_module.py").write_bytes(b"C = 3\n")
    after = finder_module.hash_python_source_tree(source_root)
    assert set(after) == {
        "a.py",
        "scanner/b.py",
        "scanner/new_runtime_module.py",
    }
    assert after["a.py"] == before["a.py"]
    assert after["scanner/b.py"] == before["scanner/b.py"]

    (nested / "linked.py").symlink_to(source_root / "a.py")
    with pytest.raises(ValueError, match="symlinks"):
        finder_module.hash_python_source_tree(source_root)


def test_python_source_tree_rejects_symlinked_directory(tmp_path):
    source_root = tmp_path / "src"
    outside = tmp_path / "outside"
    source_root.mkdir()
    outside.mkdir()
    (source_root / "normal.py").write_bytes(b"NORMAL = True\n")
    (outside / "injected.py").write_bytes(b"INJECTED = True\n")
    (source_root / "linked").symlink_to(
        outside,
        target_is_directory=True,
    )

    with pytest.raises(ValueError, match="symlinks"):
        finder_module.hash_python_source_tree(source_root)


def test_python_source_tree_rejects_special_entry(tmp_path):
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "normal.py").write_bytes(b"NORMAL = True\n")
    os.mkfifo(source_root / "runtime.pipe")

    with pytest.raises(ValueError, match="special entries"):
        finder_module.hash_python_source_tree(source_root)


def test_python_source_tree_detects_directory_mutation(
    tmp_path,
    monkeypatch,
):
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "normal.py").write_bytes(b"NORMAL = True\n")
    original_snapshot = source_snapshot._scan_directory_snapshot
    calls = 0

    def mutate_after_initial_snapshot(directory_fd):
        nonlocal calls
        snapshot = original_snapshot(directory_fd)
        if calls == 0:
            (source_root / "injected.py").write_bytes(
                b"INJECTED = True\n"
            )
        calls += 1
        return snapshot

    monkeypatch.setattr(
        source_snapshot,
        "_scan_directory_snapshot",
        mutate_after_initial_snapshot,
    )

    with pytest.raises(ValueError, match="changed during traversal"):
        finder_module.hash_python_source_tree(source_root)


def test_python_source_tree_rechecks_completed_subtrees(
    tmp_path,
    monkeypatch,
):
    source_root = tmp_path / "src"
    first_dir = source_root / "a"
    second_dir = source_root / "b"
    first_dir.mkdir(parents=True)
    second_dir.mkdir()
    victim = first_dir / "x.py"
    victim.write_bytes(b"VALUE = 1\n")
    (second_dir / "y.py").write_bytes(b"VALUE = 2\n")
    original_walk = source_snapshot._hash_python_source_directory
    mutated = False

    def mutate_after_first_subtree(directory_fd, prefix, hashes):
        nonlocal mutated
        original_walk(directory_fd, prefix, hashes)
        if prefix == ("a",) and not mutated:
            file_fd = os.open(victim, os.O_RDWR | os.O_NOFOLLOW)
            try:
                os.pwrite(file_fd, b"VALUE = 9\n", 0)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            mutated = True

    monkeypatch.setattr(
        source_snapshot,
        "_hash_python_source_directory",
        mutate_after_first_subtree,
    )

    with pytest.raises(ValueError, match="changed after traversal"):
        finder_module.hash_python_source_tree(source_root)


def test_python_source_tree_rejects_hard_linked_files(tmp_path):
    source_root = tmp_path / "src"
    source_root.mkdir()
    first = source_root / "first.py"
    first.write_bytes(b"VALUE = 1\n")
    os.link(first, source_root / "second.py")

    with pytest.raises(ValueError, match="hard-linked"):
        finder_module.hash_python_source_tree(source_root)


@pytest.mark.parametrize(
    "mutation",
    ("missing", "same_bytes_replacement", "symlink_swap"),
)
def test_python_source_tree_detects_live_root_replacement(
    tmp_path,
    monkeypatch,
    mutation,
):
    source_root = tmp_path / "src"
    source_root.mkdir()
    source_bytes = b"NORMAL = True\n"
    (source_root / "normal.py").write_bytes(source_bytes)
    moved_root = tmp_path / "src.original"
    original_walk = source_snapshot._hash_python_source_directory
    replaced = False

    def replace_after_root_walk(directory_fd, prefix, hashes):
        nonlocal replaced
        original_walk(directory_fd, prefix, hashes)
        if prefix or replaced:
            return
        source_root.rename(moved_root)
        if mutation == "same_bytes_replacement":
            source_root.mkdir()
            (source_root / "normal.py").write_bytes(source_bytes)
        elif mutation == "symlink_swap":
            source_root.symlink_to(
                moved_root.name,
                target_is_directory=True,
            )
        replaced = True

    monkeypatch.setattr(
        source_snapshot,
        "_hash_python_source_directory",
        replace_after_root_walk,
    )

    with pytest.raises(ValueError, match="root changed during traversal"):
        finder_module.hash_python_source_tree(source_root)


def test_init_without_output_dir_still_calculates_module_priorities(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    captured = {}

    def fake_calculate_module_priorities(software_profile, vulnerability_profile):
        captured["software_profile"] = software_profile
        captured["vulnerability_profile"] = vulnerability_profile
        return {"cliui": 1}, {"cli.py": "cliui"}

    monkeypatch.setattr(finder_module, "calculate_module_priorities", fake_calculate_module_priorities)

    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(cve_id="CVE-2025-0001"),
        verbose=False,
        output_dir=None,
    )

    assert captured["software_profile"] is finder.software_profile
    assert captured["vulnerability_profile"] is finder.vulnerability_profile
    assert finder.module_priorities == {"cliui": 1}
    assert finder.file_to_module == {"cli.py": "cliui"}
    assert finder.memory is None


def test_extract_complementary_summary_structured(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    summarized = {
        "content": {
            "summary": "checked key path",
            "reasoning": {
                "motivation": "high-risk module",
                "analysis": "user input reaches sink",
                "conclusions": ["possible vuln"],
            },
            "shared_memory_hits": ["query=os.system hit src/api.py"],
            "rejected_hypotheses": ["subprocess path is sanitized"],
            "next_best_queries": ["shell=True"],
            "evidence_gaps": ["need source-to-sink trace"],
            "files_completed_this_iteration": ["src/api.py"],
        }
    }

    text = finder._extract_complementary_summary(summarized)

    assert "Summary" in text
    assert "Reasoning" in text
    assert "Shared Memory Hits" in text
    assert "query=os.system hit src/api.py" in text
    assert "Rejected Hypotheses" in text
    assert "subprocess path is sanitized" in text
    assert "Next Best Queries" in text
    assert "shell=True" in text
    assert "Evidence Gaps" in text
    assert "need source-to-sink trace" in text
    assert "Files Completed This Iteration" in text
    assert "src/api.py" in text


def test_extract_complementary_summary_non_dict_fallback(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    assert finder._extract_complementary_summary({"content": "plain text"}) == "plain text"


def test_get_user_message_iteration_uses_progress_context(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1
    finder.shared_public_memory_scope = {"observation_count": 4}

    captured = {}
    pending_priorities = []

    def fake_get_pending_files(max_priority=2):
        pending_priorities.append(max_priority)
        return ["a.py", "b.py"]

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
    ):
        captured["scanned_files"] = scanned_files
        captured["findings"] = findings
        captured["progress_info"] = progress_info
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["shared_observation_count"] = shared_observation_count
        captured["has_priority_one"] = has_priority_one
        captured["has_related"] = has_related
        return "intermediate"

    finder.memory = SimpleNamespace(
        get_progress=lambda: {
            "completed": 3,
            "total_files": 10,
            "findings": 1,
            "priority_1": {"completed": 1, "total": 2},
            "priority_2": {"completed": 1, "total": 3},
        },
        format_progress_info=lambda: (
            "3/10 files scanned, 1 findings. "
            "Priority-1: 1/2, Priority-2: 1/3."
        ),
        get_pending_files=fake_get_pending_files,
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [{"file": "x.py", "type": "cmd", "confidence": "high"}],
    )

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    msg = finder._get_user_message(iteration=1)

    assert msg == "intermediate"
    assert captured["scanned_files"] == ["done.py"]
    assert captured["findings"][0]["type"] == "cmd"
    assert captured["critical_stop_max_priority"] == 1
    assert captured["shared_observation_count"] == 4
    assert captured["has_priority_one"] is False
    assert captured["has_related"] is False
    assert "3/10 files scanned" in captured["progress_info"]
    assert "Critical scope: priority-1 modules only" in captured["progress_info"]
    assert pending_priorities == [1]


def test_get_user_message_iteration_skips_priority_one_progress_prefix_when_no_priority_one_pending(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1

    captured = {}

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
    ):
        captured["progress_info"] = progress_info
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["has_priority_one"] = has_priority_one
        captured["has_related"] = has_related
        return "intermediate"

    finder.memory = SimpleNamespace(
        format_progress_info=lambda: "3/10 files scanned, 1 findings. Priority-1: 0/0, Priority-2: 1/3.",
        get_pending_files=lambda max_priority=2: [],
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [],
    )

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    msg = finder._get_user_message(iteration=1)

    assert msg == "intermediate"
    assert captured["critical_stop_max_priority"] == 1
    assert captured["has_priority_one"] is False
    assert captured["has_related"] is False
    assert "Critical scope: priority-1 modules only" not in captured["progress_info"]


def test_get_user_message_initial_passes_critical_stop_priority(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.critical_stop_max_priority = 1
    finder.shared_public_memory_scope = {"observation_count": 2}
    captured = {}

    def fake_build_initial_user_message(
        software_profile,
        module_priorities,
        critical_stop_max_priority=2,
        shared_observation_count=0,
    ):
        captured["software_profile"] = software_profile
        captured["module_priorities"] = module_priorities
        captured["critical_stop_max_priority"] = critical_stop_max_priority
        captured["shared_observation_count"] = shared_observation_count
        return "initial"

    monkeypatch.setattr(finder_module, "build_initial_user_message", fake_build_initial_user_message)

    msg = finder._get_user_message(iteration=0)

    assert msg == "initial"
    assert captured["software_profile"] is finder.software_profile
    assert captured["module_priorities"] == finder.module_priorities
    assert captured["critical_stop_max_priority"] == 1
    assert captured["shared_observation_count"] == 2


def test_get_user_message_initial_includes_structured_vulnerability_guidance(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.vulnerability_profile = SimpleNamespace(
        to_dict=lambda: {
            "query_terms": ["os.system", "request.args"],
            "dangerous_apis": ["os.system"],
            "source_indicators": ["request.args.get"],
            "sink_indicators": ["os.system(cmd)"],
            "negative_constraints": ["feature flag disabled"],
            "scan_start_points": ["src/api.py:entry"],
            "variant_hypotheses": ["subprocess.run(..., shell=True)"],
            "likely_false_positive_patterns": ["fixed literal command"],
        }
    )
    finder._model_visible_vulnerability_profile = (
        finder.vulnerability_profile.to_dict()
    )

    message = finder._get_user_message(iteration=0)

    assert "Structured Vulnerability Guidance" in message
    assert '"query_terms": [' in message
    assert '"scan_start_points": [' in message
    assert "subprocess.run(..., shell=True)" in message


def test_get_user_message_iteration_does_not_repeat_structured_vulnerability_guidance(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.vulnerability_profile = SimpleNamespace(
        to_dict=lambda: {
            "query_terms": ["pickle.loads"],
            "dangerous_apis": ["pickle.loads"],
            "scan_start_points": ["src/api.py:load_model"],
        }
    )
    finder._model_visible_vulnerability_profile = (
        finder.vulnerability_profile.to_dict()
    )
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [],
        format_progress_info=lambda: "1/3 files scanned, 0 findings. Priority-1: 0/0, Priority-2: 0/0.",
        get_scanned_files=lambda: ["done.py"],
        get_findings_summary=lambda: [],
    )

    message = finder._get_user_message(iteration=1)

    assert "Structured Vulnerability Guidance" not in message
    assert '"query_terms": [' not in message
    assert '"scan_start_points": [' not in message
    assert "Continue your vulnerability analysis:" in message


def test_run_passes_shared_observation_count_to_system_prompt(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.shared_public_memory_scope = {"observation_count": 6}
    captured = {}

    def fake_build_system_prompt(vulnerability_profile, toolkit, shared_observation_count=0):
        captured["vulnerability_profile"] = vulnerability_profile
        captured["toolkit"] = toolkit
        captured["shared_observation_count"] = shared_observation_count
        return "system"

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "analysis complete"})
        return 1

    monkeypatch.setattr(finder_module, "build_system_prompt", fake_build_system_prompt)
    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    finder.run()

    assert captured["vulnerability_profile"] is finder.vulnerability_profile
    assert captured["toolkit"] is finder.toolkit
    assert captured["shared_observation_count"] == 6


def test_run_stops_when_assistant_says_analysis_complete(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "Analysis complete"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 1
    assert result["vulnerabilities"] == []


def test_run_ignores_previous_turn_completion_when_current_turn_has_no_assistant(
    monkeypatch,
    tmp_path,
):
    finder = _make_finder(monkeypatch, tmp_path=tmp_path)
    finder.max_iterations = 3
    finder.stop_when_critical_complete = False

    def fake_run_turn(iteration):
        if iteration == 0:
            finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    def fake_compress(*args, **kwargs):
        _ = args
        _ = kwargs
        return {"content": {"summary": "analysis complete"}}

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)
    monkeypatch.setattr(finder_module, "compress_iteration_conversation", fake_compress)

    result = finder.run()

    assert result["iterations"] == 3


def test_run_trims_iteration_history_when_compression_fails(monkeypatch, tmp_path):
    finder = _make_finder(monkeypatch, tmp_path=tmp_path)
    finder.max_iterations = 1
    finder.stop_when_critical_complete = False

    def fake_run_turn(iteration):
        _ = iteration
        finder.conversation_history.extend(
            [
                {"role": "assistant", "content": "investigating"},
                {"role": "tool", "content": "tool output"},
            ]
        )
        return 1

    def fake_compress(*args, **kwargs):
        _ = args
        _ = kwargs
        return {
            "iteration_number": 0,
            "error": "boom",
            "summary": "Compression failed",
            "raw_message_count": 2,
        }

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)
    monkeypatch.setattr(finder_module, "compress_iteration_conversation", fake_compress)

    result = finder.run()

    assert result["iterations"] == 1
    assert all(message.get("role") != "tool" for message in finder.conversation_history)
    assert finder.conversation_history[-1] == {
        "role": "assistant",
        "content": "**Summary**: Compression failed",
    }


def test_run_hits_max_iterations_without_stop(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_iterations = 2

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 2


def test_finalize_memory_triggers_summary_and_markdown(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    memory = DummyMemory()
    finder.memory = memory

    finder._finalize_memory()

    assert memory.summary_called is True
    assert memory.markdown_called is True


class _ToolAwareToolkit:
    def __init__(self):
        self.executed = []

    def get_available_tools(self):
        return [{"type": "function", "function": {"name": "mock_tool"}}]

    def execute_tool(self, tool_name, parameters):
        self.executed.append((tool_name, parameters))
        return SimpleNamespace(success=True, content=json.dumps(parameters), error=None)


class _LargeToolAwareToolkit(_ToolAwareToolkit):
    def execute_tool(self, tool_name, parameters):
        self.executed.append((tool_name, parameters))
        return SimpleNamespace(success=True, content="X" * (600 * 1024), error=None)


class _UsageDrivenLLM:
    def __init__(self, responses, input_tokens, *, context_limit=4096, max_tokens=256):
        self._responses = list(responses)
        self._input_tokens = list(input_tokens)
        self._response_index = 0
        self._last_usage_summary = {}
        self.context_limit = context_limit
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.chat_calls = 0

    def chat(self, messages, tools=None, **kwargs):
        _ = messages
        _ = tools
        _ = kwargs
        self.chat_calls += 1
        response = self._responses[self._response_index]
        input_tokens = self._input_tokens[self._response_index]
        self._response_index += 1
        self._last_usage_summary = {
            "selected_model_usage": {
                "input_tokens": input_tokens,
                "output_tokens": 11,
                "context_window": self.context_limit,
            }
        }
        if isinstance(response, Exception):
            raise response
        return response

    def get_last_usage_summary(self):
        return dict(self._last_usage_summary)

    def get_last_request_input_tokens(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("input_tokens", 0)

    def get_last_request_output_tokens(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("output_tokens", 0)

    def get_last_request_context_limit(self) -> int:
        usage = self._last_usage_summary.get("selected_model_usage", {})
        return usage.get("context_window", 0)


class _SequencedLLM:
    def __init__(self, responses, *, context_limit=4096, max_tokens=256):
        self._responses = list(responses)
        self._response_index = 0
        self.chat_calls = 0
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.context_limit = context_limit

    def chat(self, messages, tools=None, **kwargs):
        _ = messages
        _ = tools
        _ = kwargs
        self.chat_calls += 1
        response = self._responses[self._response_index]
        if self._response_index < len(self._responses) - 1:
            self._response_index += 1
        return response

    def get_last_usage_summary(self):
        return {}

    def get_last_request_input_tokens(self) -> int:
        return 0

    def get_last_request_output_tokens(self) -> int:
        return 0

    def get_last_request_context_limit(self) -> int:
        return self.context_limit


class _RecordingLLM:
    def __init__(self, response, *, context_limit=4096, max_tokens=256):
        self._response = response
        self.context_limit = context_limit
        self.config = SimpleNamespace(max_tokens=max_tokens)
        self.chat_calls = []

    def chat(self, messages, tools=None, **kwargs):
        self.chat_calls.append(
            {
                "messages": list(messages),
                "tools": list(tools) if isinstance(tools, list) else tools,
                "kwargs": kwargs,
            }
        )
        return self._response

    def get_last_usage_summary(self):
        return {}

    def get_last_request_input_tokens(self) -> int:
        return 0

    def get_last_request_output_tokens(self) -> int:
        return 0

    def get_last_request_context_limit(self) -> int:
        return self.context_limit


def test_run_turn_stops_on_invalid_model_message(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    bad_llm = _SequencedLLM(
        [
            SimpleNamespace(content=None, tool_calls=None, reasoning_content=None),
            SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        ]
    )
    finder.llm_client = bad_llm

    result = finder._run_turn(iteration=0)

    assert result == 1
    assert bad_llm.chat_calls == 1


def test_run_turn_compacts_history_and_current_user_before_query(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    llm = _RecordingLLM(
        SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        context_limit=4096,
        max_tokens=256,
    )
    finder.llm_client = llm
    finder.max_tokens = 256
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [f"pending_{idx}.py" for idx in range(100)],
        format_progress_info=lambda: "10/200 files scanned, 1 findings.",
        get_scanned_files=lambda: [f"scanned_{idx}.py" for idx in range(500)],
        get_findings_summary=lambda: [
            {"file": f"finding_{idx}.py", "type": "cmd", "confidence": "high"}
            for idx in range(20)
        ],
    )

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
        compact=False,
    ):
        _ = (
            scanned_files,
            findings,
            progress_info,
            critical_stop_max_priority,
            shared_observation_count,
            has_priority_one,
            has_related,
        )
        return "COMPACT USER" if compact else "FULL USER"

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "old user"},
        {"role": "assistant", "content": "X" * 120_000},
        {"role": "user", "content": "FULL USER " + ("Y" * 30_000)},
    ]

    sub_turns = finder._run_turn(iteration=1)

    assert sub_turns == 1
    assert len(llm.chat_calls) == 1
    sent_messages = llm.chat_calls[0]["messages"]
    assert sent_messages[-1]["content"] == "COMPACT USER"
    assert all(message.get("content") != "X" * 120_000 for message in sent_messages if isinstance(message, dict))


def test_run_stops_on_completion_after_preflight_compaction(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _SequencedLLM(
        [
            SimpleNamespace(role="assistant", content="large intermediate " + ("X" * 120_000), tool_calls=None, reasoning_content=None),
            SimpleNamespace(role="assistant", content="analysis complete", tool_calls=None, reasoning_content=None),
        ],
        context_limit=4096,
        max_tokens=256,
    )

    finder.run()

    assert finder.llm_client.chat_calls == 2


def test_run_turn_skips_query_when_preflight_budget_still_exceeded_after_compaction(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    llm = _RecordingLLM(
        SimpleNamespace(content="done", tool_calls=None, reasoning_content=None),
        context_limit=2048,
        max_tokens=512,
    )
    finder.llm_client = llm
    finder.max_tokens = 512
    finder.memory = SimpleNamespace(
        get_pending_files=lambda max_priority=2: [],
        format_progress_info=lambda: "progress",
        get_scanned_files=lambda: [],
        get_findings_summary=lambda: [],
    )

    def fake_build_intermediate_user_message(
        scanned_files,
        findings,
        progress_info,
        critical_stop_max_priority=2,
        shared_observation_count=0,
        has_priority_one=True,
        has_related=True,
        compact=False,
    ):
        _ = (
            scanned_files,
            findings,
            progress_info,
            critical_stop_max_priority,
            shared_observation_count,
            has_priority_one,
            has_related,
        )
        if compact:
            return "Y" * 50_000
        return "FULL USER"

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_build_intermediate_user_message)

    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "assistant", "content": "X" * 80_000},
        {"role": "user", "content": "FULL USER " + ("Z" * 50_000)},
    ]

    sub_turns = finder._run_turn(iteration=1)

    assert sub_turns == 1
    assert llm.chat_calls == []


def _tool_call(name="mock_tool", arguments="{}"):
    return SimpleNamespace(
        id="tool_1",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def test_run_turn_rejects_malformed_tool_arguments_without_executing_tool(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments='{"file_path":',
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed == []
    assert finder.found_vulnerabilities == []
    assert finder.conversation_history[-1]["role"] == "tool"
    assert "Failed to parse tool arguments" in finder.conversation_history[-1]["content"]


def test_run_turn_accepts_dict_tool_arguments(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments={
                            "file_path": "app.py",
                            "vulnerability_type": "cmd-injection",
                            "description": "desc",
                            "evidence": "evidence",
                            "similarity_to_known": "same sink",
                            "confidence": "high",
                        },
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed and toolkit.executed[0][0] == "report_vulnerability"
    assert finder.found_vulnerabilities[0]["file_path"] == "app.py"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_defers_file_completion_until_other_calls_finish(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="mark_file_completed",
                        arguments={"file_path": "app.py", "reason": "inspected"},
                    ),
                    _tool_call(
                        name="report_vulnerability",
                        arguments={
                            "file_path": "app.py",
                            "vulnerability_type": "cmd-injection",
                            "description": "desc",
                            "evidence": "evidence",
                            "similarity_to_known": "same sink",
                            "confidence": "high",
                        },
                    ),
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert [name for name, _params in toolkit.executed] == [
        "report_vulnerability",
        "mark_file_completed",
    ]
    assert finder.found_vulnerabilities[0]["file_path"] == "app.py"


def test_init_memory_restores_agent_findings_but_not_codeql_candidates(
    monkeypatch,
    tmp_path,
):
    class _ResumedMemory:
        def __init__(self, output_dir, llm_client=None):
            self.output_dir = output_dir
            self.llm_client = llm_client
            self.memory = SimpleNamespace(
                file_status={},
                findings=[
                    {"file_path": "agent.py", "vulnerability_type": "cmd"},
                    {
                        "file_path": "candidate.py",
                        "vulnerability_type": "codeql-candidate",
                        "source": "codeql",
                    },
                ],
            )

        def initialize(self, **_kwargs):
            return True

        def get_pending_files(self):
            return []

    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    monkeypatch.setattr(finder_module, "AgentMemoryManager", _ResumedMemory)

    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=5,
        verbose=False,
        output_dir=tmp_path,
    )
    finder.max_iterations = 0
    monkeypatch.setattr(finder, "_finalize_memory", lambda: None)

    result = finder.run()

    assert finder.found_vulnerabilities == [
        {"file_path": "agent.py", "vulnerability_type": "cmd"}
    ]
    assert result["vulnerabilities"] == finder.found_vulnerabilities


def test_run_turn_rejects_mismatched_vulnerability_type(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    toolkit = _ToolAwareToolkit()
    finder.toolkit = toolkit
    finder.vulnerability_profile = SimpleNamespace(
        cve_id="CVE-2025-0001",
        to_dict=lambda: {"cve_id": "CVE-2025-0001", "sink_features": {"type": "command_injection"}},
    )
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="reporting",
                reasoning_content=None,
                tool_calls=[
                    _tool_call(
                        name="report_vulnerability",
                        arguments={
                            "file_path": "app.py",
                            "vulnerability_type": "code_injection",
                            "description": "desc",
                            "evidence": "evidence",
                            "similarity_to_known": "same impact but different sink type",
                            "confidence": "medium",
                        },
                    )
                ],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert toolkit.executed and toolkit.executed[0][0] == "report_vulnerability"
    assert finder.found_vulnerabilities == []
    assert finder.conversation_history[-1]["role"] == "tool"
    assert "same vulnerability type" in finder.conversation_history[-1]["content"]


def test_get_user_message_does_not_rescan_related_scope_when_no_related_files_pending(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.module_priorities = {"p2": 2}
    finder.file_to_module = {"b.py": "p2"}

    class _Memory:
        def get_pending_files(self, max_priority=None):
            assert max_priority == 2
            return []

        def format_progress_info(self):
            return "1/1 files scanned, 0 findings. Priority-1: 0/0, Priority-2: 1/1."

        def get_scanned_files(self):
            return ["b.py"]

        def get_findings_summary(self):
            return []

    finder.memory = _Memory()

    message = finder._get_user_message(iteration=1)

    assert "scan ALL files in 🟡 RELATED modules before any repo-wide widening" not in message
    assert "Priority-2: 1/1" in message


def test_run_turn_uses_api_usage_to_stop_before_next_request(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            )
        ],
        input_tokens=[3500],
        context_limit=4096,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert finder.llm_client.chat_calls == 1
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2].content == "need tool"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_turn_continues_when_actual_usage_is_well_below_context_limit(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            SimpleNamespace(
                content="done",
                reasoning_content=None,
                tool_calls=None,
            ),
        ],
        input_tokens=[128, 192],
        context_limit=65536,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 2
    assert finder.llm_client.chat_calls == 2
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2]["role"] == "tool"
    assert finder.conversation_history[-1].content == "done"


def test_run_turn_commits_progress_when_next_request_hits_context_limit(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            RuntimeError("maximum context length exceeded"),
        ],
        input_tokens=[1200, 0],
        context_limit=4096,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 2
    assert finder.llm_client.chat_calls == 2
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2].content == "need tool"
    assert finder.conversation_history[-1]["role"] == "tool"


def test_run_propagates_retry_exhaustion_without_starting_next_iteration(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_iterations = 20

    class _RetryExhaustedLLM:
        def __init__(self):
            self.config = SimpleNamespace(
                max_tokens=256,
                enforce_exact_decoding=True,
            )
            self.context_limit = 4096
            self.chat_calls = 0

        def chat(self, messages, tools=None, **kwargs):
            _ = messages, tools, kwargs
            self.chat_calls += 1
            raise LLMRetryExhaustedError("retry budget exhausted")

        def get_last_request_input_tokens(self):
            return 0

        def get_last_request_output_tokens(self):
            return 0

        def get_last_request_context_limit(self):
            return self.context_limit

    finder.llm_client = _RetryExhaustedLLM()

    with pytest.raises(LLMRetryExhaustedError, match="retry budget exhausted"):
        finder.run()

    assert finder.llm_client.chat_calls == 1


def test_run_turn_propagates_context_limit_in_exact_decoding_mode(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.llm_client = _UsageDrivenLLM(
        responses=[RuntimeError("maximum context length exceeded")],
        input_tokens=[0],
        context_limit=4096,
        max_tokens=256,
    )
    finder.llm_client.config.enforce_exact_decoding = True
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    with pytest.raises(RuntimeError, match="maximum context length"):
        finder._run_turn(iteration=0)

    assert finder.llm_client.chat_calls == 1


def test_run_turn_ignores_request_size_soft_limit_and_continues_to_second_request(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    monkeypatch.setattr(finder_module, "_REQUEST_SIZE_SOFT_LIMIT_BYTES", 8 * 1024, raising=False)
    finder.max_tokens = 256
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="need tool",
                reasoning_content=None,
                tool_calls=[_tool_call()],
            ),
            SimpleNamespace(
                content="done",
                reasoning_content=None,
                tool_calls=None,
            ),
        ],
        input_tokens=[1200, 100],
        context_limit=65536,
        max_tokens=256,
    )
    finder.toolkit = _LargeToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 2
    assert finder.llm_client.chat_calls == 2
    assert finder.toolkit.executed == [("mock_tool", {})]
    assert finder.conversation_history[-2]["role"] == "tool"
    assert finder.conversation_history[-1].content == "done"


def test_run_turn_stops_after_max_sub_turns(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.max_sub_turns = 3
    finder.max_tokens = 256
    finder.llm_client = _SequencedLLM(
        [
            SimpleNamespace(content="need tool", reasoning_content=None, tool_calls=[_tool_call()]),
        ],
        context_limit=65536,
        max_tokens=256,
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 3
    assert finder.llm_client.chat_calls == 3
    assert finder.toolkit.executed == [
        ("mock_tool", {}),
        ("mock_tool", {}),
        ("mock_tool", {}),
    ]
    assert finder.conversation_history[-1]["role"] == "tool"


def test_is_context_limit_error_does_not_match_413_entity_too_large(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)

    assert not finder._is_context_limit_error(RuntimeError("413 Request Entity Too Large"))
    assert not finder._is_context_limit_error(RuntimeError("APIStatusError: entity too large"))


def test_run_turn_treats_empty_tool_calls_as_completed_turn(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.llm_client = _UsageDrivenLLM(
        responses=[
            SimpleNamespace(
                content="Analysis complete",
                reasoning_content=None,
                tool_calls=[],
            )
        ],
        input_tokens=[512],
    )
    finder.toolkit = _ToolAwareToolkit()
    finder.conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "user"},
    ]

    sub_turns = finder._run_turn(iteration=0)

    assert sub_turns == 1
    assert finder.llm_client.chat_calls == 1
    assert finder.toolkit.executed == []
    assert finder.conversation_history[-1].content == "Analysis complete"


def test_run_invalid_critical_stop_mode_falls_back_to_max(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=1,
        stop_when_critical_complete=True,
        critical_stop_mode="unexpected",
        verbose=False,
        output_dir=None,
    )
    finder.memory = DummyMemory()

    def fake_run_turn(iteration):
        finder.conversation_history.append({"role": "assistant", "content": "keep going"})
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert finder.critical_stop_mode == "max"
    assert result["iterations"] == 1


def test_run_ignores_analysis_complete_until_critical_scope_finishes(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.stop_when_critical_complete = True
    finder.critical_stop_mode = "min"

    class ToggleMemory:
        def __init__(self):
            self.complete = False

        def is_critical_complete(self):
            return self.complete

        def get_pending_files(self, max_priority=2):
            return ["a.py"] if not self.complete else []

        def format_progress_info(self):
            return "pending critical scope"

        def get_scanned_files(self):
            return []

        def get_findings_summary(self):
            return []

        def get_progress(self):
            return {
                "completed": 1 if self.complete else 0,
                "total_files": 1,
                "findings": 0,
                "priority_1": {"completed": 1 if self.complete else 0, "total": 1},
                "priority_2": {"completed": 0, "total": 0},
            }

    memory = ToggleMemory()
    finder.memory = memory
    turn_count = {"value": 0}

    def fake_run_turn(iteration):
        turn_count["value"] += 1
        finder.conversation_history.append({"role": "assistant", "content": "Analysis complete"})
        if turn_count["value"] >= 2:
            memory.complete = True
        return 1

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)

    result = finder.run()

    assert result["iterations"] == 2


def test_finalize_iteration_progress_does_not_auto_complete_whole_file_reads(monkeypatch):
    class TrackingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self._touched = []

        def consume_tracked_files(self):
            touched = list(self._touched)
            self._touched = []
            return touched

    monkeypatch.setattr(finder_module, "AgenticToolkit", TrackingToolkit)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        max_iterations=1,
        verbose=False,
        output_dir=None,
    )

    class MemoryWithStatus(DummyMemory):
        def __init__(self):
            super().__init__()
            self.memory = SimpleNamespace(file_status={"a.py": "pending", "b.py": "completed"})

    memory = MemoryWithStatus()
    finder.memory = memory
    finder.toolkit._touched = ["a.py", "b.py"]

    finder._finalize_iteration_progress(0)

    assert memory.completed == []
    assert finder.toolkit.consume_tracked_files() == []


def test_memory_ablation_disables_resume_and_llm_facing_history(monkeypatch, tmp_path):
    class CapturingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self.init_kwargs = dict(kwargs)

    monkeypatch.setattr(finder_module, "AgenticToolkit", CapturingToolkit)
    monkeypatch.setattr(finder_module, "AgentMemoryManager", _CaptureScanSignatureMemory)
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=Path("/tmp/demo"),
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2025-0001",
            to_dict=lambda: {"cve_id": "CVE-2025-0001"},
        ),
        output_dir=tmp_path,
        verbose=False,
        shared_public_memory_scope={"observation_count": 9},
        ablation_config={"memory": True},
    )

    assert finder.memory.initialize_kwargs["resume_enabled"] is False
    assert finder.toolkit.init_kwargs["memory_guidance_enabled"] is False

    class ExplodingHistoryMemory:
        def get_pending_files(self, **kwargs):
            raise AssertionError("pending history must not be exposed")

        def format_progress_info(self):
            raise AssertionError("progress history must not be exposed")

        def get_scanned_files(self):
            raise AssertionError("scanned history must not be exposed")

        def get_findings_summary(self):
            raise AssertionError("finding history must not be exposed")

    finder.memory = ExplodingHistoryMemory()
    captured = {}

    def fake_intermediate(**kwargs):
        captured.update(kwargs)
        return "memory-free"

    monkeypatch.setattr(finder_module, "build_intermediate_user_message", fake_intermediate)
    assert finder._get_user_message(iteration=1) == "memory-free"
    assert captured["shared_observation_count"] == 0
    assert captured["progress_info"] == ""
    assert captured["scanned_files"] == []
    assert captured["findings"] == []


def test_memory_ablation_skips_llm_summary_but_keeps_private_ledger_report(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    finder.memory_guidance_enabled = False
    memory = DummyMemory()
    finder.memory = memory

    finder._finalize_memory()

    assert memory.summary_called is False
    assert memory.markdown_called is True

def test_candidate_priority_ablation_reports_durable_host_coverage(
    monkeypatch,
    tmp_path,
):
    class OrderedToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self.scheduled = []
            self.observed = []

        def set_file_enumeration_order(self, file_paths):
            self.scheduled = list(file_paths)

        def set_active_file_window(self, file_paths, **kwargs):
            self.active_window = list(file_paths)
            self.active_window_kwargs = dict(kwargs)

        def get_observed_first_touches(self):
            return list(self.observed)

    monkeypatch.setattr(finder_module, "AgenticToolkit", OrderedToolkit)
    host_plan = {
        "schema_version": 1,
        "module_priorities": {"api": 1, "worker": 2},
        "file_to_module": {"a.py": "api", "b.py": "worker"},
    }
    schedule = {
        "files": ["b.py", "a.py"],
        "provenance": {
            "seed_sha256": "seed",
            "order_sha256": finder_module.stable_data_hash(["b.py", "a.py"]),
            "universe_sha256": finder_module.stable_data_hash(["a.py", "b.py"]),
        },
    }
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(), repo_path=tmp_path,
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile={"card_id": "card-1", "weaknesses": ["CWE-78"]},
        verbose=False, output_dir=tmp_path / "output", host_priority_plan=host_plan,
        unprioritized_file_schedule=schedule,
        ablation_config={"candidate_priority": True, "reference_semantics": True},
    )
    assert finder.module_priorities == {"__frozen_global_file_schedule__": 1}
    assert list(finder.file_to_module) == ["b.py", "a.py"]
    assert set(finder.file_to_module.values()) == {"__frozen_global_file_schedule__"}
    assert finder.module_similarity_provenance == {
        "source": "frozen_unprioritized_file_schedule",
        "universe_sha256": finder_module.stable_data_hash(["a.py", "b.py"]),
        "order_sha256": finder_module.stable_data_hash(["b.py", "a.py"]),
    }
    assert finder.toolkit.scheduled == ["b.py", "a.py"]
    finder._record_presented_schedule_page()
    finder.memory.mark_file_completed("b.py", reason="inspected")
    finder.toolkit.observed = ["b.py"]
    provenance = finder._build_candidate_order_provenance()
    coverage = provenance["host_schedule_coverage"]
    assert coverage["first_touch_order"] == ["b.py"]
    assert coverage["first_touch_count"] == 1
    assert coverage["completed_file_count"] == 1
    assert coverage["presented_page_indices"] == [0]
    assert coverage["presented_work_item_count"] == 2
    assert coverage["untouched_file_count"] == 1
    ledger = finder._build_host_coverage_ledger("max_iterations")
    assert ledger["reached_work_items"] == 1
    assert ledger["completed_work_items"] == 1
    assert ledger["untouched_work_items"] == 1
    assert ledger["all_work_exhausted"] is False

    captured = {}
    def fake_intermediate(**kwargs):
        captured.update(kwargs)
        return "scheduled-continuation"

    monkeypatch.setattr(
        finder_module,
        "build_intermediate_user_message",
        fake_intermediate,
    )
    assert finder._get_user_message(iteration=1) == "scheduled-continuation"
    assert captured["candidate_priority_enabled"] is False
    assert captured["candidate_file_order"] == ["b.py", "a.py"]
    assert captured["pending_files"] == ["a.py"]
    assert captured["candidate_schedule_page"]["completed_window_offsets"] == [0]
    assert captured["candidate_schedule_page"]["files"] == ["a.py"]
    assert "b.py" not in captured["progress_info"]
    assert "a.py" not in captured["progress_info"]
    assert "Priority" not in captured["progress_info"]
    assert "module" not in captured["progress_info"]


def test_candidate_priority_ablation_rejects_missing_frozen_schedule(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)

    with pytest.raises(
        ValueError,
        match="requires a frozen global file schedule",
    ):
        finder_module.AgenticVulnFinder(
            llm_client=DummyLLM(),
            repo_path=Path("/tmp/demo"),
            software_profile=SimpleNamespace(version="target123", modules=[]),
            vulnerability_profile={"card_id": "card-1", "weaknesses": ["CWE-78"]},
            verbose=False,
            output_dir=None,
            ablation_config={"candidate_priority": True},
        )


def _direct_schedule_snapshot_finder(*, touches, findings=None, presented=None):
    files = [f"src/page0_{index:04d}.py" for index in range(1024)] + [
        "src/page1_0000.py"
    ]
    statuses = {path: "pending" for path in files}
    presented = [0] if presented is None else list(presented)
    events = []
    for page_index in presented:
        cursor = page_index * finder_module.FROZEN_SCHEDULE_PAGE_SIZE
        page_files = files[cursor:cursor + finder_module.FROZEN_SCHEDULE_PAGE_SIZE]
        events.append({
            "schema_version": 1,
            "cursor_index": cursor,
            "window_end_index_exclusive": cursor + len(page_files),
            "window_file_count": len(page_files),
            "active_pending_file_count": len(page_files),
            "completed_window_count": 0,
            "window_sha256": finder_module.stable_data_hash(page_files),
        })
    finder = object.__new__(finder_module.AgenticVulnFinder)
    finder.candidate_priority_enabled = False
    finder.candidate_order_provenance = {"files": files}
    finder.memory = SimpleNamespace(
        memory=SimpleNamespace(
            file_status=statuses,
            file_completion_reasons={},
            findings=list(findings or []),
            coverage_first_touches=list(touches),
            schedule_presented_page_indices=presented,
            schedule_window_events=events,
        )
    )
    return finder, files


def test_schedule_resume_rejects_cross_page_touch_reversal():
    finder, files = _direct_schedule_snapshot_finder(
        touches=["src/page1_0000.py", "src/page0_0001.py"],
        presented=[0, 1],
    )
    assert files[-1] == "src/page1_0000.py"
    with pytest.raises(ValueError, match="not chronological"):
        finder._schedule_status_snapshot()


def test_schedule_resume_accepts_arbitrary_within_page_touch_order():
    finder, files = _direct_schedule_snapshot_finder(
        touches=["src/page0_0900.py", "src/page0_0001.py"],
    )
    snapshot = finder._schedule_status_snapshot()
    assert list(snapshot) == files


@pytest.mark.parametrize(
    "finding",
    [
        {"vulnerability_type": "x"},
        {"file_path": "", "vulnerability_type": "x"},
        {"file_path": "src/page0_0001.py", "file": "src/page0_0002.py"},
    ],
)
def test_schedule_resume_rejects_missing_empty_or_conflicting_finding_locator(finding):
    finder, _ = _direct_schedule_snapshot_finder(
        touches=["src/page0_0001.py"],
        findings=[finding],
    )
    with pytest.raises(ValueError, match="finding path is invalid"):
        finder._schedule_status_snapshot()


def test_schedule_resume_rejects_finding_without_first_touch():
    finder, _ = _direct_schedule_snapshot_finder(
        touches=["src/page0_0002.py"],
        findings=[{"file_path": "src/page0_0001.py", "vulnerability_type": "x"}],
    )
    with pytest.raises(ValueError, match="missing a durable first touch"):
        finder._schedule_status_snapshot()


def test_schedule_resume_accepts_touched_finding_with_consistent_locators():
    path = "src/page0_0001.py"
    finder, _ = _direct_schedule_snapshot_finder(
        touches=[path],
        findings=[{"file_path": path, "file": path, "vulnerability_type": "x"}],
    )
    assert finder._schedule_status_snapshot()[path] == "pending"


class _HostCoverageMemory:
    def __init__(self, statuses, file_to_module, module_priorities, touches):
        self.memory = SimpleNamespace(
            file_status=dict(statuses),
            coverage_first_touches=list(touches),
        )
        self._file_to_module = dict(file_to_module)
        self._module_priorities = dict(module_priorities)

    def is_critical_complete(self, max_priority=2):
        return all(
            status == "completed"
            for path, status in self.memory.file_status.items()
            if self._module_priorities[self._file_to_module[path]] <= max_priority
        )

    def get_pending_files(self, max_priority=3):
        return [
            path
            for path, status in self.memory.file_status.items()
            if status == "pending"
            and self._module_priorities[self._file_to_module[path]] <= max_priority
        ]

    def get_scanned_files(self):
        return [
            path
            for path, status in self.memory.file_status.items()
            if status == "completed"
        ]

    def get_findings_summary(self):
        return []

    def get_progress(self):
        priority = {
            1: {"completed": 0, "total": 0},
            2: {"completed": 0, "total": 0},
        }
        for path, status in self.memory.file_status.items():
            rank = self._module_priorities[self._file_to_module[path]]
            if rank in priority:
                priority[rank]["total"] += 1
                if status == "completed":
                    priority[rank]["completed"] += 1
        completed = sum(
            status == "completed" for status in self.memory.file_status.values()
        )
        return {
            "completed": completed,
            "total_files": len(self.memory.file_status),
            "findings": 0,
            "priority_1": priority[1],
            "priority_2": priority[2],
        }

    def format_progress_info(self):
        progress = self.get_progress()
        return f"{progress['completed']}/{progress['total_files']} files scanned"

    def generate_summary(self):
        return ""

    def save_markdown(self):
        return None


def _install_prioritized_host_ledger(finder, statuses, touches):
    finder.module_priorities = {"p1": 1, "p2": 2, "p3": 3}
    finder.file_to_module = {
        "p1.py": "p1",
        "p2.py": "p2",
        "p3.py": "p3",
    }
    finder._host_priority_plan = {
        "schema_version": 1,
        "module_priorities": dict(finder.module_priorities),
        "file_to_module": dict(finder.file_to_module),
    }
    finder.memory = _HostCoverageMemory(
        statuses,
        finder.file_to_module,
        finder.module_priorities,
        touches,
    )


def test_prioritized_full_universe_cap_is_partial_and_ignores_completion_signal(
    monkeypatch,
):
    finder = _make_finder(monkeypatch, tmp_path=None)
    _install_prioritized_host_ledger(
        finder,
        {"p1.py": "completed", "p2.py": "pending", "p3.py": "pending"},
        ["p1.py"],
    )
    finder.require_full_universe_completion = True
    finder.max_iterations = 1

    def signal_too_early(iteration):
        assert iteration == 0
        finder.conversation_history.append(
            {"role": "assistant", "content": "Analysis complete"}
        )
        return 1

    monkeypatch.setattr(finder, "_run_turn", signal_too_early)
    result = finder.run()

    assert result["iterations"] == 1
    assert result["termination_reason"] == "full_universe_iteration_cap"
    assert result["host_coverage_evidence"]["coverage_status"] == "partial"
    assert result["host_coverage_ledger"] == {
        "schema_version": 1,
        "source": "frozen_host_priority_plan_host_ledger",
        "total_work_items": 3,
        "reached_work_items": 1,
        "completed_work_items": 1,
        "untouched_work_items": 2,
        "all_work_exhausted": False,
        "termination_reason": "full_universe_iteration_cap",
        "evidence_sha256": result["host_coverage_ledger"]["evidence_sha256"],
    }


def test_prioritized_default_critical_p1_p2_stop_remains_partial(monkeypatch):
    finder = _make_finder(monkeypatch, tmp_path=None)
    assert finder.require_full_universe_completion is False
    _install_prioritized_host_ledger(
        finder,
        {"p1.py": "completed", "p2.py": "completed", "p3.py": "pending"},
        ["p1.py", "p2.py", "extra.py"],
    )
    finder.stop_when_critical_complete = True
    finder.critical_stop_mode = "min"
    finder.critical_stop_max_priority = 2

    def keep_going(iteration):
        assert iteration == 0
        finder.conversation_history.append(
            {"role": "assistant", "content": "No completion signal"}
        )
        return 1

    monkeypatch.setattr(finder, "_run_turn", keep_going)
    result = finder.run()

    assert result["iterations"] == 1
    assert result["termination_reason"] == "critical_scope_complete"
    assert result["host_coverage_evidence"]["coverage_status"] == "partial"
    assert result["host_coverage_ledger"]["reached_work_items"] == 2
    assert result["host_coverage_ledger"]["completed_work_items"] == 2
    assert result["host_coverage_ledger"]["untouched_work_items"] == 1
    assert result["host_coverage_evidence"]["out_of_universe_first_touches"] == [
        "extra.py"
    ]


def test_unprioritized_full_universe_cap_uses_same_partial_ledger(monkeypatch, tmp_path):
    class ScheduledToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self.observed = []

        def set_file_enumeration_order(self, file_paths):
            self.schedule = list(file_paths)

        def set_active_file_window(self, file_paths, **kwargs):
            self.active_page = list(file_paths)
            self.active_kwargs = dict(kwargs)

        def get_observed_first_touches(self):
            return list(self.observed)

    monkeypatch.setattr(finder_module, "AgenticToolkit", ScheduledToolkit)
    schedule_files = ["b.py", "a.py"]
    schedule = {
        "files": schedule_files,
        "provenance": {
            "order_sha256": finder_module.stable_data_hash(schedule_files),
            "universe_sha256": finder_module.stable_data_hash(sorted(schedule_files)),
        },
    }
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=tmp_path,
        software_profile=SimpleNamespace(version="target123", modules=[]),
        vulnerability_profile={"card_id": "card-1"},
        max_iterations=1,
        require_full_universe_completion=True,
        verbose=False,
        output_dir=tmp_path / "output",
        unprioritized_file_schedule=schedule,
        ablation_config={"candidate_priority": True},
    )
    monkeypatch.setattr(finder, "_finalize_memory", lambda: None)

    def signal_too_early(iteration):
        assert iteration == 0
        finder.conversation_history.append(
            {"role": "assistant", "content": "Analysis complete"}
        )
        return 1

    monkeypatch.setattr(finder, "_run_turn", signal_too_early)
    result = finder.run()

    assert result["termination_reason"] == "full_universe_iteration_cap"
    assert result["host_coverage_evidence"]["coverage_status"] == "partial"
    assert result["host_coverage_ledger"]["total_work_items"] == 2
    assert result["host_coverage_ledger"]["reached_work_items"] == 0
    assert result["host_coverage_ledger"]["completed_work_items"] == 0
    assert result["host_coverage_ledger"]["untouched_work_items"] == 2
    assert result["host_coverage_ledger"]["all_work_exhausted"] is False


def test_scheduled_model_payloads_hide_nested_future_paths(monkeypatch, tmp_path):
    class ScheduledSanitizingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self._scheduled_mode = False
            self._scheduled_path_token_pattern = None
            self._active_file_window_rank = {}
            self._model_path_projection_order = ()
            self._model_path_projection_pattern = None

        def set_model_path_projection_order(self, file_paths):
            self._model_path_projection_order = tuple(file_paths)
            self._model_path_projection_pattern = (
                RealAgenticToolkit._compile_model_path_projection_pattern(
                    self._model_path_projection_order
                )
            )

        def sanitize_invariant_model_value(self, value):
            return RealAgenticToolkit.sanitize_invariant_model_value(
                self, value
            )

        def set_file_enumeration_order(self, file_paths):
            self.schedule = list(file_paths)
            self._scheduled_mode = True
            self._scheduled_path_token_pattern = (
                RealAgenticToolkit._compile_scheduled_path_token_pattern(
                    tuple(self.schedule)
                )
            )

        def set_active_file_window(self, file_paths, **kwargs):
            completed = set(kwargs.get("completed_files", []))
            self._active_file_window_rank = {
                path: index
                for index, path in enumerate(file_paths)
                if path not in completed
            }

        @staticmethod
        def _sanitize_structured_path_tokens(
            value, *, token_pattern, replacement
        ):
            return RealAgenticToolkit._sanitize_structured_path_tokens(
                value,
                token_pattern=token_pattern,
                replacement=replacement,
            )

        def sanitize_scheduled_model_value(
            self, value, *, preserve_active=True
        ):
            return RealAgenticToolkit._sanitize_scheduled_structured_value(
                self,
                value,
                preserve_active=preserve_active,
            )

        def get_observed_first_touches(self):
            return []

    monkeypatch.setattr(
        finder_module,
        "AgenticToolkit",
        ScheduledSanitizingToolkit,
    )
    active_path = "src/component.spec.tsx"
    filler = [f"src/page0_{index:04d}.py" for index in range(1023)]
    future_path = "src/component.spec.ts"
    schedule_files = [active_path, *filler, future_path]
    schedule = {
        "files": schedule_files,
        "provenance": {
            "order_sha256": finder_module.stable_data_hash(schedule_files),
            "universe_sha256": finder_module.stable_data_hash(
                sorted(schedule_files)
            ),
        },
    }
    vulnerability_profile = {
        "cve_id": "CVE-2026-4242",
        "source_features": {future_path: {"evidence": future_path}},
        "sink_features": {"type": "path_traversal", "evidence": future_path},
        "flow_features": {"call_path": ["prefix " + future_path]},
        "evidence": [{"file": future_path}],
        "query_terms": ["inspect " + future_path],
        "dangerous_apis": [future_path],
    }
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=tmp_path,
        software_profile={
            "version": "target123",
            "basic_info": {"name": "target " + future_path},
            "modules": [],
        },
        vulnerability_profile=vulnerability_profile,
        max_iterations=1,
        verbose=False,
        output_dir=tmp_path / "output",
        unprioritized_file_schedule=schedule,
        target_path_projection={
            "files": schedule_files,
            "provenance": {"artifact_sha256": "a" * 64},
        },
        ablation_config={"candidate_priority": True},
    )

    system_prompt = finder_module.build_system_prompt(
        finder.vulnerability_profile,
        finder.toolkit,
        candidate_priority_enabled=False,
        candidate_file_order=schedule_files,
        candidate_schedule_provenance=schedule["provenance"],
    )
    initial_user = finder._get_user_message(0)
    compact_user = finder._get_user_message(1, compact=True)
    token_pattern = RealAgenticToolkit._compile_scheduled_path_token_pattern(
        tuple(schedule_files)
    )

    assert token_pattern.search(system_prompt) is None
    assert "<TARGET_PATH>" in system_prompt
    assert "<TARGET_PATH>" in initial_user
    for user_prompt in (initial_user, compact_user):
        visible_tokens = token_pattern.findall(user_prompt)
        assert future_path not in visible_tokens
        assert active_path in visible_tokens
        assert set(visible_tokens).issubset(set(schedule_files[:1024]))



def test_scheduled_compressor_projects_hostile_input_and_output(
    monkeypatch, tmp_path
):
    class CompressionSanitizingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self._scheduled_mode = False
            self._scheduled_path_token_pattern = None
            self._active_file_window_rank = {}

        def set_file_enumeration_order(self, file_paths):
            self._scheduled_mode = True
            self._scheduled_path_token_pattern = (
                RealAgenticToolkit._compile_scheduled_path_token_pattern(
                    tuple(file_paths)
                )
            )

        def set_active_file_window(self, file_paths, **kwargs):
            completed = set(kwargs.get("completed_files", []))
            self._active_file_window_rank = {
                path: index
                for index, path in enumerate(file_paths)
                if path not in completed
            }

        def sanitize_scheduled_model_value(
            self, value, *, preserve_active=True
        ):
            return RealAgenticToolkit._sanitize_structured_path_tokens(
                value,
                token_pattern=self._scheduled_path_token_pattern,
                replacement=lambda match: (
                    match.group(0)
                    if preserve_active
                    and match.group(0) in self._active_file_window_rank
                    else "<inactive-schedule-path>"
                ),
            )

        def get_observed_first_touches(self):
            return []

    monkeypatch.setattr(
        finder_module,
        "AgenticToolkit",
        CompressionSanitizingToolkit,
    )
    active_path = "src/active.py"
    filler = [f"src/page0_{index:04d}.py" for index in range(1023)]
    future_path = "src/future.py"
    schedule_files = [active_path, *filler, future_path]
    output_dir = tmp_path / "output"
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=tmp_path,
        software_profile={"version": "target123", "modules": []},
        vulnerability_profile={"cve_id": "CVE-2026-9000"},
        max_iterations=1,
        stop_when_critical_complete=False,
        verbose=False,
        output_dir=output_dir,
        unprioritized_file_schedule={
            "files": schedule_files,
            "provenance": {
                "order_sha256": finder_module.stable_data_hash(schedule_files),
                "universe_sha256": finder_module.stable_data_hash(
                    sorted(schedule_files)
                ),
            },
        },
        ablation_config={"candidate_priority": True},
    )
    captured = {}

    def fake_run_turn(_iteration):
        finder.conversation_history.append(
            {
                "role": "assistant",
                "content": f"active={active_path}; future={future_path}",
            }
        )
        return 1

    def fake_compress(_client, _iteration, iteration_history, **_kwargs):
        serialized = json.dumps(iteration_history, sort_keys=True)
        captured["input"] = serialized
        assert active_path in serialized
        assert future_path not in serialized
        assert "<inactive-schedule-path>" in serialized
        return {
            "content": {
                "summary": f"active={active_path}; future={future_path}",
                "next_best_queries": [future_path],
            }
        }

    monkeypatch.setattr(finder, "_run_turn", fake_run_turn)
    monkeypatch.setattr(
        finder_module,
        "compress_iteration_conversation",
        fake_compress,
    )

    finder.run()

    summary_path = output_dir / "conversations" / "iteration_0_output_summary.json"
    persisted = summary_path.read_text(encoding="utf-8")
    history = json.dumps(finder.conversation_history, sort_keys=True)
    assert active_path in captured["input"]
    assert active_path in persisted
    assert active_path in history
    assert future_path not in persisted
    assert future_path not in history
    assert "<inactive-schedule-path>" in persisted
    assert "<inactive-schedule-path>" in history


def test_finder_rejects_decoding_binding_drift(monkeypatch):
    monkeypatch.setattr(finder_module, "AgenticToolkit", DummyToolkit)
    requested, requested_sha256 = _decoding_binding()
    effective = {**requested, "temperature": 0.3}
    effective_sha256 = finder_module.stable_data_hash(effective)

    with pytest.raises(
        ValueError,
        match="requested decoding config does not match effective",
    ):
        finder_module.AgenticVulnFinder(
            llm_client=_LLMWithFullConfig(),
            repo_path=Path("/tmp/demo"),
            software_profile=SimpleNamespace(
                version="target123",
                modules=[],
            ),
            vulnerability_profile=SimpleNamespace(
                cve_id="CVE-2099-0001"
            ),
            verbose=False,
            output_dir=None,
            decoding_config_requested=requested,
            decoding_config_requested_sha256=requested_sha256,
            decoding_config_effective=effective,
            decoding_config_effective_sha256=effective_sha256,
        )


def test_projection_runtime_signature_is_detached_and_policy_visible(
    monkeypatch,
    tmp_path,
):
    class ProjectingToolkit(DummyToolkit):
        def __init__(self, repo_path, **kwargs):
            super().__init__(repo_path, **kwargs)
            self._model_path_projection_order = ()
            self._model_path_projection_pattern = None

        def set_model_path_projection_order(self, file_paths):
            self._model_path_projection_order = tuple(file_paths)
            self._model_path_projection_pattern = (
                RealAgenticToolkit._compile_model_path_projection_pattern(
                    self._model_path_projection_order
                )
            )

        def sanitize_invariant_model_value(self, value):
            return RealAgenticToolkit.sanitize_invariant_model_value(
                self,
                value,
            )

    monkeypatch.setattr(
        finder_module,
        "AgenticToolkit",
        ProjectingToolkit,
    )
    target_path = "src/private_target.py"
    projection_provenance = {
        "schema_version": 2,
        "artifact_sha256": "a" * 64,
        "model_input_stage_hashes": {
            "invariant_preprocessing": "b" * 64,
            "policy_specific_eligibility": "c" * 64,
        },
    }
    software_profile = {
        "version": "d" * 40,
        "description": f"target uses {target_path}",
        "modules": [
            {
                "name": "core",
                "description": f"core contains {target_path}",
                "files": [target_path],
            }
        ],
    }
    finder = finder_module.AgenticVulnFinder(
        llm_client=DummyLLM(),
        repo_path=tmp_path,
        software_profile=software_profile,
        vulnerability_profile={
            "cve_id": "CVE-2099-0001",
            "description": f"inspect {target_path}",
        },
        max_iterations=1,
        verbose=False,
        output_dir=None,
        host_priority_plan={
            "module_priorities": {"core": 1},
            "file_to_module": {target_path: "core"},
        },
        target_path_projection={
            "files": [target_path],
            "provenance": projection_provenance,
        },
    )

    runtime = finder.model_visible_input_runtime_projection
    expected_runtime_keys = {
        "raw_reference_sha256",
        "projected_reference_sha256",
        "raw_static_input_sha256",
        "projected_static_input_sha256",
        "invariant_projected_static_input_sha256",
        "policy_visible_static_input_sha256",
        "policy_preserved_fields",
    }
    assert set(runtime) == expected_runtime_keys
    assert (
        runtime["projected_static_input_sha256"]
        == runtime["invariant_projected_static_input_sha256"]
    )
    assert (
        runtime["invariant_projected_static_input_sha256"]
        != runtime["policy_visible_static_input_sha256"]
    )
    assert finder._model_visible_software_profile["modules"][0][
        "files"
    ] == [target_path]
    assert (
        finder.model_visible_input_projection_provenance[
            "invariant_projected_static_input_sha256"
        ]
        == runtime["invariant_projected_static_input_sha256"]
    )

    signature = finder._build_scan_signature()
    assert (
        signature["scan_config"]["model_visible_input_projection"]
        == projection_provenance
    )
    assert (
        signature["scan_config"][
            "model_visible_input_runtime_projection"
        ]
        == runtime
    )
