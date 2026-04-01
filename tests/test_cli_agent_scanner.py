from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
import json
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import cli.agent_scanner as agent_scanner
from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME
from scanner.similarity.retriever import (
    ProfileRef,
    ProfileSimilarityMetrics,
    SimilarProfileCandidate,
)


def _mk_profile(name: str, version: str = "", repo_analysis=None, metadata=None):
    repo_info = {"repo_analysis": repo_analysis} if isinstance(repo_analysis, dict) else {}
    return SoftwareProfile(
        name=name,
        version=version,
        repo_info=repo_info,
        modules=[ModuleInfo(name="m")],
        metadata=metadata or {},
    )


def _mk_complete_finder_memory():
    return SimpleNamespace(
        get_progress=lambda: {
            "completed": 1,
            "pending": 0,
            "findings": 0,
            "priority_1": {"completed": 1, "total": 1},
            "priority_2": {"completed": 0, "total": 0},
        },
        is_critical_complete=lambda max_priority=2: True,
    )


def test_validate_args_rejects_target_commit_without_repo():
    args = Namespace(target_repo=None, target_commit="abc", top_k=3)
    assert agent_scanner._validate_args(args) is False


def test_validate_args_rejects_non_positive_top_k():
    args = Namespace(target_repo="repo", target_commit=None, top_k=0)
    assert agent_scanner._validate_args(args) is False


def test_validate_args_rejects_out_of_range_similarity_threshold():
    args = Namespace(target_repo="repo", target_commit=None, top_k=1, similarity_threshold=1.2)
    assert agent_scanner._validate_args(args) is False


def test_parse_args_defaults_similarity_model_to_embedding_default(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["agent-scanner", "--vuln-repo", "repo", "--cve", "CVE-2025-0001"])

    args = agent_scanner.parse_args()

    assert args.similarity_model_name == DEFAULT_EMBEDDING_MODEL_NAME


def test_resolve_output_dir_anchors_relative_base_to_repo_root(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", repo_root)

    resolved = agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001",
        target_repo="demo",
        target_commit="a" * 40,
        output_base="results/scan-out",
    )

    assert resolved == repo_root / "results" / "scan-out" / "CVE-2026-0001" / "demo-aaaaaaaaaaaa"


def test_resolve_output_dir_uses_repo_root_default_when_output_base_is_omitted(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", repo_root)

    resolved = agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001",
        target_repo="demo",
        target_commit="a" * 40,
        output_base=None,
    )

    assert resolved == repo_root / "scan-results" / "CVE-2026-0001" / "demo-aaaaaaaaaaaa"


def test_resolve_manual_targets_prefers_vuln_commit_for_same_repo(monkeypatch, tmp_path):
    args = Namespace(target_repo="repo-a", target_commit=None, vuln_repo="repo-a")
    vuln = SimpleNamespace(repo_name="repo-a", affected_version="deadbeef1234")

    captured = {}

    def fake_resolve(repo_profiles_dir, repo_name, commit_hint):
        captured["repo_name"] = repo_name
        captured["hint"] = commit_hint
        return "deadbeef1234aaaa"

    monkeypatch.setattr(agent_scanner, "resolve_profile_commit", fake_resolve)

    targets = agent_scanner._resolve_manual_targets(args, vuln, tmp_path)

    assert len(targets) == 1
    assert targets[0].repo_name == "repo-a"
    assert captured["repo_name"] == "repo-a"
    assert captured["hint"] == "deadbeef1234"


def test_resolve_manual_targets_falls_back_to_current_git_commit(monkeypatch, tmp_path):
    args = Namespace(target_repo="repo-b", target_commit=None, vuln_repo="repo-a")
    vuln = SimpleNamespace(repo_name="repo-a", affected_version="sourcecommit")

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", tmp_path)
    (tmp_path / "repo-b").mkdir(parents=True)

    captured = {"events": []}

    @contextmanager
    def fake_hold_repo_lock(repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        captured["repo_path"] = repo_path
        captured["purpose"] = purpose
        captured["events"].append("lock-enter")
        yield
        captured["events"].append("lock-exit")

    def fake_get_git_commit(repo_path):
        captured["events"].append("get_git_commit")
        return "headcommit123456"

    monkeypatch.setattr(agent_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(agent_scanner, "get_git_commit", fake_get_git_commit)
    monkeypatch.setattr(agent_scanner, "resolve_profile_commit", lambda *_: "headcommit123456ffff")

    targets = agent_scanner._resolve_manual_targets(args, vuln, tmp_path)

    assert len(targets) == 1
    assert targets[0].commit_hash.startswith("headcommit")
    assert captured["repo_path"] == tmp_path / "repo-b"
    assert captured["purpose"] == "resolve_manual_target_commit"
    assert captured["events"] == ["lock-enter", "get_git_commit", "lock-exit"]


def test_resolve_auto_targets_uses_ranked_candidates(monkeypatch, tmp_path):
    args = Namespace(
        vuln_repo="src-repo",
        top_k=2,
        include_same_repo=False,
        similarity_model_name="model",
        similarity_device="cpu",
    )
    source_profile = _mk_profile("src-repo", version="1111")
    candidate_profile = _mk_profile("target-repo", version="2222")

    source_ref = ProfileRef("src-repo", "111122223333", source_profile)
    candidate_ref = ProfileRef("target-repo", "222233334444", candidate_profile)
    similarity = SimilarProfileCandidate(
        profile_ref=candidate_ref,
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    vuln = SimpleNamespace(repo_name="src-repo", affected_version="1111")

    monkeypatch.setattr(agent_scanner, "load_all_software_profiles", lambda _: [source_ref, candidate_ref])
    monkeypatch.setattr(agent_scanner, "select_profile_ref", lambda refs, repo, commit_hint: source_ref)
    monkeypatch.setattr(agent_scanner, "build_text_retriever", lambda **kwargs: None)
    monkeypatch.setattr(agent_scanner, "rank_similar_profiles", lambda **kwargs: [similarity])

    targets = agent_scanner._resolve_auto_targets(args, vuln, tmp_path)

    assert len(targets) == 1
    assert targets[0].repo_name == "target-repo"
    assert targets[0].commit_hash == "222233334444"
    assert targets[0].similarity is similarity


def test_resolve_auto_targets_respects_top_k_when_similarity_threshold_is_set(monkeypatch, tmp_path):
    args = Namespace(
        vuln_repo="src-repo",
        top_k=1,
        include_same_repo=False,
        similarity_model_name="model",
        similarity_device="cpu",
        similarity_threshold=0.7,
    )
    source_profile = _mk_profile("src-repo", version="1111")
    candidate_profile = _mk_profile("target-repo", version="2222")
    source_ref = ProfileRef("src-repo", "111122223333", source_profile)
    candidate_ref = ProfileRef("target-repo", "222233334444", candidate_profile)
    similarity = SimilarProfileCandidate(
        profile_ref=candidate_ref,
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    vuln = SimpleNamespace(repo_name="src-repo", affected_version="1111")
    captured = {}

    monkeypatch.setattr(agent_scanner, "load_all_software_profiles", lambda _: [source_ref, candidate_ref])
    monkeypatch.setattr(agent_scanner, "select_profile_ref", lambda refs, repo, commit_hint: source_ref)
    monkeypatch.setattr(agent_scanner, "build_text_retriever", lambda **kwargs: None)

    def fake_rank(**kwargs):
        captured["top_k"] = kwargs["top_k"]
        return [similarity]

    monkeypatch.setattr(agent_scanner, "rank_similar_profiles", fake_rank)

    targets = agent_scanner._resolve_auto_targets(args, vuln, tmp_path)

    assert captured["top_k"] == 1
    assert len(targets) == 1


def test_resolve_codeql_database_names_uses_profile_repo_path_hash():
    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")
    profile_repo_path = Path("/tmp/target-profile").resolve()
    software_profile = _mk_profile(
        "target-repo",
        version="targethash1234",
        repo_analysis={"codeql_languages": ["python", "javascript"]},
        metadata={"profile_repo_path": str(profile_repo_path)},
    )
    expected_path_hash = agent_scanner.stable_data_hash(str(profile_repo_path))[:12]

    first_names = agent_scanner._resolve_codeql_database_names(
        target,
        ["python"],
        software_profile,
    )
    second_names = agent_scanner._resolve_codeql_database_names(
        target,
        ["python"],
        software_profile,
    )

    assert first_names == second_names == {
        "python": f"target-repo-{expected_path_hash}-targetha-python",
        "javascript": f"target-repo-{expected_path_hash}-targetha-javascript",
    }


def test_save_scan_outputs_writes_similarity_file(tmp_path):
    finder = SimpleNamespace(conversation_history=[{"role": "assistant", "content": "ok"}])
    results = {"vulnerabilities": []}

    profile_ref = ProfileRef("repo", "abcd", _mk_profile("repo"))
    similarity = SimilarProfileCandidate(
        profile_ref=profile_ref,
        metrics=ProfileSimilarityMetrics(1, 1, 1, 1, 1, 1),
    )
    target = agent_scanner.ScanTarget(repo_name="repo", commit_hash="abcd", similarity=similarity)

    agent_scanner._save_scan_outputs(
        tmp_path,
        finder,
        results,
        target,
        scan_fingerprint={"hash": "expected"},
    )

    assert (tmp_path / "agentic_vuln_findings.json").exists()
    assert (tmp_path / "conversation_history.json").exists()
    assert (tmp_path / "target_similarity.json").exists()
    payload = json.loads((tmp_path / "agentic_vuln_findings.json").read_text(encoding="utf-8"))
    assert payload["coverage_status"] == "unknown"
    assert payload["scan_fingerprint"]["hash"] == "expected"


def test_build_scan_quality_metadata_marks_complete_when_critical_scope_is_done():
    finder = SimpleNamespace(
        memory=SimpleNamespace(
            get_progress=lambda: {
                "completed": 12,
                "pending": 0,
                "findings": 2,
                "priority_1": {"completed": 2, "total": 2},
                "priority_2": {"completed": 3, "total": 3},
            },
            is_critical_complete=lambda max_priority=2: True,
        )
    )

    metadata = agent_scanner._build_scan_quality_metadata(finder)

    assert metadata["coverage_status"] == "complete"
    assert metadata["critical_scope_present"] is True
    assert metadata["critical_scope_total_files"] == 5
    assert metadata["critical_scope_completed_files"] == 5


def test_build_scan_quality_metadata_marks_complete_for_zero_scope_without_pending_files():
    finder = SimpleNamespace(
        memory=SimpleNamespace(
            get_progress=lambda: {
                "completed": 7,
                "pending": 0,
                "findings": 0,
                "priority_1": {"completed": 0, "total": 0},
                "priority_2": {"completed": 0, "total": 0},
            },
            is_critical_complete=lambda max_priority=2: True,
        )
    )

    metadata = agent_scanner._build_scan_quality_metadata(finder)

    assert metadata["coverage_status"] == "complete"
    assert metadata["critical_scope_present"] is False
    assert metadata["critical_scope_total_files"] == 0
    assert metadata["critical_scope_completed_files"] == 0


def test_build_scan_quality_metadata_treats_affected_only_empty_scope_as_complete():
    finder = SimpleNamespace(
        critical_stop_max_priority=1,
        memory=SimpleNamespace(
            get_progress=lambda: {
                "completed": 0,
                "pending": 4,
                "findings": 0,
                "priority_1": {"completed": 0, "total": 0},
                "priority_2": {"completed": 0, "total": 4},
            },
            is_critical_complete=lambda max_priority=2: max_priority == 1,
        ),
    )

    metadata = agent_scanner._build_scan_quality_metadata(finder)

    assert metadata["coverage_status"] == "complete"
    assert metadata["critical_scope_present"] is False
    assert metadata["critical_complete"] is True


def test_build_scan_quality_metadata_marks_empty_when_no_progress_exists():
    finder = SimpleNamespace(
        memory=SimpleNamespace(
            get_progress=lambda: {
                "completed": 0,
                "pending": 10,
                "findings": 0,
                "priority_1": {"completed": 0, "total": 0},
                "priority_2": {"completed": 0, "total": 0},
            },
            is_critical_complete=lambda max_priority=2: False,
        )
    )

    metadata = agent_scanner._build_scan_quality_metadata(finder)

    assert metadata["coverage_status"] == "empty"
    assert metadata["critical_scope_present"] is False


def test_build_scan_fingerprint_includes_scanner_and_codeql_sources():
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )
    fingerprint = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2026-0001",
            to_dict=lambda: {"cve_id": "CVE-2026-0001"},
        ),
        software_profile=_mk_profile("repo", version="abc"),
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    assert "scanner/agent/utils.py" in fingerprint["source_hashes"]
    assert fingerprint["source_hashes"]["scanner/agent/utils.py"]
    assert "utils/codeql_native.py" in fingerprint["source_hashes"]
    assert fingerprint["source_hashes"]["utils/codeql_native.py"]
    assert "scanner/agent/shared_memory.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_fs.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_codeql.py" in fingerprint["source_hashes"]
    assert "scanner/similarity/retriever.py" in fingerprint["source_hashes"]
    assert "scanner/similarity/embedding.py" in fingerprint["source_hashes"]
    assert "config.py" in fingerprint["source_hashes"]


def test_build_scan_fingerprint_changes_when_llm_thinking_settings_change():
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")

    enabled = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=SimpleNamespace(
            config=SimpleNamespace(
                provider="deepseek",
                model="deepseek-chat",
                temperature=0.1,
                top_p=0.9,
                max_tokens=4096,
                enable_thinking=True,
            )
        ),
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )
    disabled = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=SimpleNamespace(
            config=SimpleNamespace(
                provider="deepseek",
                model="deepseek-chat",
                temperature=0.1,
                top_p=0.9,
                max_tokens=4096,
                enable_thinking=False,
            )
        ),
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    assert enabled["hash"] != disabled["hash"]


def test_build_scan_fingerprint_changes_when_llm_base_url_changes():
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")

    primary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=SimpleNamespace(
            config=SimpleNamespace(
                provider="deepseek",
                model="deepseek-chat",
                base_url="https://primary.example/v1",
                temperature=0.1,
                top_p=0.9,
                max_tokens=4096,
                enable_thinking=True,
            )
        ),
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )
    secondary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=SimpleNamespace(
            config=SimpleNamespace(
                provider="deepseek",
                model="deepseek-chat",
                base_url="https://secondary.example/v1",
                temperature=0.1,
                top_p=0.9,
                max_tokens=4096,
                enable_thinking=True,
            )
        ),
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    assert primary["hash"] != secondary["hash"]


def test_build_scan_fingerprint_changes_when_module_similarity_config_changes(monkeypatch):
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    monkeypatch.setitem(agent_scanner._scanner_config["module_similarity"], "threshold", 0.8)
    primary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    monkeypatch.setitem(agent_scanner._scanner_config["module_similarity"], "threshold", 0.81)
    secondary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    assert primary["hash"] != secondary["hash"]


def test_build_scan_fingerprint_uses_module_similarity_override(monkeypatch):
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    monkeypatch.setitem(agent_scanner._path_config, "repo_root", Path("/tmp"))
    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", Path("/tmp"))
    monkeypatch.setattr(
        agent_scanner,
        "embedding_model_artifact_signature",
        lambda model_name: {"artifact_hash": f"artifact::{model_name}"},
    )

    fingerprint = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        module_similarity_config={"threshold": 0.8, "model_name": "mini-model", "device": "cuda"},
    )

    assert fingerprint["scan_config"]["module_similarity"] == {
        "threshold": 0.8,
        "model_name": "mini-model",
        "device": "cuda",
        "artifact_hash": "artifact::mini-model",
    }


def test_build_scan_fingerprint_changes_when_shared_public_memory_is_enabled():
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    disabled = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": False, "root_hash": "", "scope_key": "", "state_hash": ""},
    )
    enabled = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": True, "root_hash": "run-a", "scope_key": "repo-a", "state_hash": "scope-a"},
    )

    assert disabled["hash"] != enabled["hash"]


def test_build_scan_fingerprint_changes_when_shared_public_memory_scope_changes():
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    first = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": True, "root_hash": "run-a", "scope_key": "repo-a", "state_hash": "scope-a"},
    )
    second = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": True, "root_hash": "run-a", "scope_key": "repo-a", "state_hash": "scope-b"},
    )

    assert first["hash"] != second["hash"]


def test_build_scan_fingerprint_changes_when_embedding_model_artifact_changes(monkeypatch):
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    monkeypatch.setattr(
        agent_scanner,
        "embedding_model_artifact_signature",
        lambda _model_name: {
            "resolved_model_path": "/models/demo",
            "artifact_hash": "hash-a",
        },
    )
    primary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    monkeypatch.setattr(
        agent_scanner,
        "embedding_model_artifact_signature",
        lambda _model_name: {
            "resolved_model_path": "/models/demo",
            "artifact_hash": "hash-b",
        },
    )
    secondary = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
    )

    assert primary["hash"] != secondary["hash"]


def test_build_scan_fingerprint_changes_when_shared_public_memory_root_changes():
    base_profile = SimpleNamespace(
        cve_id="CVE-2026-0001",
        to_dict=lambda: {"cve_id": "CVE-2026-0001"},
    )
    software_profile = _mk_profile("repo", version="abc")
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="deepseek",
            model="deepseek-chat",
            base_url="https://primary.example/v1",
            temperature=0.1,
            top_p=0.9,
            max_tokens=4096,
            enable_thinking=True,
        )
    )

    first = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": True, "root_hash": "run-a", "scope_key": "repo-a", "state_hash": ""},
    )
    second = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=base_profile,
        software_profile=software_profile,
        llm_client=llm_client,
        max_iterations=5,
        stop_when_critical_complete=True,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "db"},
        shared_public_memory_scope={"enabled": True, "root_hash": "run-b", "scope_key": "repo-a", "state_hash": ""},
    )

    assert first["hash"] != second["hash"]


def test_resolve_scan_languages_returns_empty_for_removed_csharp_support(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Program.cs").write_text("public class Program {}\n", encoding="utf-8")

    assert agent_scanner._resolve_scan_languages(repo, _mk_profile("repo")) == []


def test_resolve_soft_profiles_dir_for_scan_prefers_base_plus_dirname(tmp_path):
    resolved = agent_scanner._resolve_soft_profiles_dir_for_scan(
        profile_base_path=str(tmp_path / "profiles"),
        software_profile_dirname="soft-nvidia",
    )

    assert resolved == tmp_path / "profiles" / "soft-nvidia"


def test_resolve_soft_profiles_dir_for_scan_uses_default_dirname(tmp_path):
    resolved = agent_scanner._resolve_soft_profiles_dir_for_scan(
        profile_base_path=str(tmp_path / "profiles"),
        software_profile_dirname=None,
    )

    assert resolved == tmp_path / "profiles" / agent_scanner.DEFAULT_SOFTWARE_PROFILE_DIRNAME


def test_run_single_target_scan_success_restores_original_commit(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    captured_lock = {}

    checkout_calls = []

    def fake_checkout(repo_path, commit):
        checkout_calls.append(commit)
        return True

    restore_calls = []

    def fake_restore(repo_path, restore_target):
        restore_calls.append(restore_target)
        return True

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", fake_restore)
    monkeypatch.setattr(agent_scanner, "checkout_commit", fake_checkout)

    @contextmanager
    def fake_hold_repo_lock(repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        captured_lock["repo_path"] = repo_path
        captured_lock["purpose"] = purpose
        yield

    monkeypatch.setattr(agent_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": [{"id": 1}]}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
    )

    assert ok is True
    assert captured_lock["repo_path"] == repo_dir
    assert captured_lock["purpose"] == "agent_scan:CVE-2025-0001:targethash12"
    assert checkout_calls[0] == "targethash1234"
    assert restore_calls == ["master"]


def test_run_single_target_scan_uses_attempt_unique_shared_memory_producer_id(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda repo_path, restore_target: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda repo_path, commit: True)

    @contextmanager
    def fake_hold_repo_lock(repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        yield

    monkeypatch.setattr(agent_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    captured = {}

    class DummySharedPublicMemoryManager:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def describe_scope(self):
            return {"enabled": True, "scope_key": "scope", "state_hash": "state"}

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": [{"id": 1}]}

    monkeypatch.setattr(agent_scanner, "SharedPublicMemoryManager", DummySharedPublicMemoryManager)
    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
        shared_public_memory_dir=tmp_path / "scan-out" / "_runs" / "run-1" / "shared-public-memory",
    )

    assert ok is True
    assert captured["producer_id"].startswith("CVE-2025-0001:")
    assert captured["producer_id"] != "CVE-2025-0001"


def test_run_single_target_scan_locks_scan_output_writes_between_concurrent_scans(monkeypatch, tmp_path):
    repo_base_a = tmp_path / "repos-a"
    repo_base_b = tmp_path / "repos-b"
    (repo_base_a / "target-repo").mkdir(parents=True)
    (repo_base_b / "target-repo").mkdir(parents=True)
    target_output_commit = "targethash1234567890abcdef1234567890abcdef12"

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: target_output_commit)
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(
        agent_scanner,
        "restore_git_position",
        lambda repo_path, restore_target: True,
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", target_output_commit),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: [])

    overlap_guard = threading.Lock()
    lifecycle_overlap = {"detected": False}
    lifecycle_state = {
        "init": {"count": 0, "gate": threading.Event()},
        "run": {"count": 0, "gate": threading.Event()},
    }
    lifecycle_count_lock = threading.Lock()

    def _assert_no_concurrent_lifecycle_access(phase: str) -> None:
        with lifecycle_count_lock:
            lifecycle_state[phase]["count"] += 1
            is_first = lifecycle_state[phase]["count"] == 1
        if is_first:
            lifecycle_state[phase]["gate"].wait(timeout=0.5)
        else:
            lifecycle_state[phase]["gate"].set()

        acquired = overlap_guard.acquire(blocking=False)
        if not acquired:
            lifecycle_overlap["detected"] = True
        try:
            time.sleep(0.05)
        finally:
            if acquired:
                overlap_guard.release()

    class DummyFinder:
        def __init__(self, **kwargs):
            _assert_no_concurrent_lifecycle_access("init")
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            _assert_no_concurrent_lifecycle_access("run")
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    save_lock = threading.Lock()
    overlap = {"detected": False}

    def fake_save_scan_outputs(*args, **kwargs):
        acquired = save_lock.acquire(blocking=False)
        if not acquired:
            overlap["detected"] = True
        try:
            time.sleep(0.05)
        finally:
            if acquired:
                save_lock.release()

    monkeypatch.setattr(agent_scanner, "_save_scan_outputs", fake_save_scan_outputs)

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=target_output_commit,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_a = executor.submit(
            agent_scanner.run_single_target_scan,
            cve_id="CVE-2026-0001",
            output_base=tmp_path / "scan-output",
            repo_base_path=repo_base_a,
            max_iterations=1,
            vulnerability_profile=SimpleNamespace(),
            llm_client=object(),
            target=target,
            verbose=False,
        )
        future_b = executor.submit(
            agent_scanner.run_single_target_scan,
            cve_id="CVE-2026-0001",
            output_base=tmp_path / "scan-output",
            repo_base_path=repo_base_b,
            max_iterations=1,
            vulnerability_profile=SimpleNamespace(),
            llm_client=object(),
            target=target,
            verbose=False,
        )
        assert future_a.result(timeout=3.0) is True
        assert future_b.result(timeout=3.0) is True

    assert lifecycle_overlap["detected"] is False
    assert overlap["detected"] is False


def test_run_single_target_scan_checks_out_when_original_commit_is_unknown(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)

    checkout_calls = []
    restore_calls = []

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: None)
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "main")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda repo_path, commit: checkout_calls.append(commit) or True)
    monkeypatch.setattr(
        agent_scanner,
        "restore_git_position",
        lambda repo_path, restore_target: restore_calls.append(restore_target) or True,
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
    )

    assert ok is True
    assert checkout_calls == ["targethash1234"]
    assert restore_calls == ["main"]


def test_run_single_target_scan_refuses_checkout_without_restore_target(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)

    checkout_calls = []

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: None)
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(
        agent_scanner,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
    )

    assert ok is False
    assert checkout_calls == []


def test_run_single_target_scan_refuses_dirty_repo_even_without_checkout(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "targethash1234")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("dirty repo should fail before loading profile")),
    )

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
    )

    assert ok is False


def test_run_single_target_scan_fails_when_profile_missing(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "orig")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "load_software_profile", lambda *args, **kwargs: None)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        verbose=False,
    )

    assert ok is False


def test_run_single_target_scan_passes_critical_stop_flag(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile(
            "target-repo",
            "targethash",
            repo_analysis={
                "languages": ["python", "javascript"],
                "codeql_languages": ["python", "javascript"],
            },
            metadata={"profile_repo_path": str(Path("/tmp/target-profile").resolve())},
        ),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    captured = {}

    class DummyFinder:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=2,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        stop_when_critical_complete=True,
        critical_stop_mode="min",
        critical_stop_max_priority=1,
        verbose=False,
    )

    assert ok is True
    assert captured["stop_when_critical_complete"] is True
    assert captured["critical_stop_mode"] == "min"
    assert captured["critical_stop_max_priority"] == 1
    assert captured["languages"] == ["python", "javascript"]
    expected_path_hash = agent_scanner.stable_data_hash(str(Path("/tmp/target-profile").resolve()))[:12]
    assert captured["codeql_database_names"] == {
        "python": f"target-repo-{expected_path_hash}-targetha-python",
        "javascript": f"target-repo-{expected_path_hash}-targetha-javascript",
    }


def test_run_single_target_scan_passes_module_similarity_override(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    captured = {}
    captured_fingerprint = {}

    class DummyFinder:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    def fake_build_scan_fingerprint(**kwargs):
        captured_fingerprint.update(kwargs)
        return {"hash": "scan"}

    monkeypatch.setattr(agent_scanner, "build_scan_fingerprint", fake_build_scan_fingerprint)

    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=2,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
        module_similarity_config={"threshold": 0.8, "model_name": "mini-model", "device": "cuda"},
        verbose=False,
    )

    assert ok is True
    assert captured["module_similarity_config"] == {
        "threshold": 0.8,
        "model_name": "mini-model",
        "device": "cuda",
    }
    assert captured_fingerprint["module_similarity_config"] == {
        "threshold": 0.8,
        "model_name": "mini-model",
        "device": "cuda",
    }


def test_run_single_target_scan_fails_when_coverage_is_incomplete(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = SimpleNamespace(
                get_progress=lambda: {
                    "completed": 1,
                    "pending": 1,
                    "findings": 0,
                    "priority_1": {"completed": 1, "total": 2},
                    "priority_2": {"completed": 0, "total": 0},
                },
                is_critical_complete=lambda: False,
            )

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=2,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234"),
        verbose=False,
    )

    assert ok is False


def test_run_single_target_scan_fails_when_restore_fails(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2025-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234"),
        verbose=False,
    )

    assert ok is False


def test_main_initializes_logging_before_validation(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        agent_scanner,
        "parse_args",
        lambda: Namespace(
            target_repo=None,
            target_commit=None,
            top_k=0,
            similarity_threshold=None,
            verbose=True,
        ),
    )
    monkeypatch.setattr(
        agent_scanner,
        "setup_logging",
        lambda verbose: captured.setdefault("verbose", verbose),
    )

    result = agent_scanner.main()

    assert result == 1
    assert captured["verbose"] is True
