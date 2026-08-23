import hashlib
import json
import re
import time
import sys
import threading
from argparse import Namespace
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner import output_commit
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME
from scanner.similarity.retriever import ProfileRef, ProfileSimilarityMetrics, SimilarProfileCandidate

import cli.batch_scanner_cache as batch_scanner_cache
import cli.batch_scanner_execution as batch_scanner_execution
import cli.batch_scanner as batch_scanner


@pytest.mark.parametrize(
    "payload, error",
    [
        ('[{"cve_id":"CVE-1","cve_id":"CVE-2"}]', "duplicate JSON key"),
        ('[{"cve_id":"CVE-1","score":NaN}]', "non-finite JSON number"),
        ('[{"cve_id":"CVE-1","score":Infinity}]', "non-finite JSON number"),
        ('[{"cve_id":"CVE-1","score":1e9999}]', "non-finite JSON number"),
    ],
)
def test_load_vuln_entries_rejects_ambiguous_json(tmp_path, payload, error):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        batch_scanner_cache._load_vuln_entries(vuln_json)


def _mk_profile(name: str):
    return SoftwareProfile(name=name, modules=[ModuleInfo(name="m")])


def _terminal_coverage(status: str = "complete"):
    complete = status == "complete"
    return {
        "coverage_status": "complete" if complete else "partial",
        "critical_scope_present": True,
        "critical_complete": complete,
        "critical_scope_total_files": 2,
        "critical_scope_completed_files": 2 if complete else 1,
        "full_universe_required": True,
        "full_universe_complete": complete,
        "full_universe_total_files": 2,
        "full_universe_completed_files": 2 if complete else 1,
        "scan_progress": {
            "total_files": 2,
            "completed": 2 if complete else 1,
            "pending": 0 if complete else 1,
            "findings": 0,
        },
    }


def _complete_saved_scan_quality(output_dir, **_kwargs):
    return {
        "coverage_status": "complete",
        "terminal_commit_valid": True,
        "headline_eligible": True,
        "scan_output_commit_sha256": hashlib.sha256(
            str(output_dir).encode("utf-8")
        ).hexdigest(),
    }


def _write_terminal_scan_output(

    output_dir: Path,
    *,
    reference_id: str = "CVE-2026-0001",
    repo_name: str = "target-repo",
    commit_hash: str = "a" * 40,
    status: str = "complete",
    fingerprint_payload=None,
):
    """写入测试用的完整 scanner 终态。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"fixture-{status}"
    raw_fingerprint = fingerprint_payload or {
        "schema_version": 1,
        "scan_config": {"run_id": run_id},
    }
    raw_fingerprint = dict(raw_fingerprint)
    raw_fingerprint.pop("hash", None)
    fingerprint = {
        **raw_fingerprint,
        "hash": batch_scanner.agent_scanner.stable_data_hash(raw_fingerprint),
    }
    coverage = _terminal_coverage(status)
    provenance = {
        "run_id": run_id,
        "reference_id": reference_id,
        "repo": {
            "name": repo_name,
            "requested_commit": commit_hash,
            "actual_commit": commit_hash,
        },
        "execution": {
            "status": status,
            "termination": "finished",
            "partial": status == "partial",
            "failure_reason": None,
        },
        "coverage": coverage,
        "scan_fingerprint": fingerprint,
    }
    findings = {
        **coverage,
        "vulnerabilities": [],
        "run_provenance": provenance,
        "scan_fingerprint": fingerprint,
    }
    texts = {
        output_commit.SCAN_FINDINGS_FILENAME: json.dumps(findings, indent=2),
        output_commit.SCAN_PROVENANCE_FILENAME: json.dumps(provenance, indent=2),
        output_commit.SCAN_CONVERSATION_FILENAME: json.dumps([], indent=2),
    }
    artifact_bytes = {}
    for name, text in texts.items():
        raw = text.encode("utf-8")
        (output_dir / name).write_bytes(raw)
        artifact_bytes[name] = raw
    marker = output_commit.build_scan_output_commit(
        reference_id=reference_id,
        terminal_status=status,
        run_id=run_id,
        scan_fingerprint_hash=fingerprint["hash"],
        artifact_bytes=artifact_bytes,
    )
    marker_raw = json.dumps(marker, indent=2).encode("utf-8")
    (output_dir / output_commit.SCAN_OUTPUT_COMMIT_FILENAME).write_bytes(
        marker_raw
    )
    return hashlib.sha256(marker_raw).hexdigest(), fingerprint


def _write_terminal_scan_for_kwargs(kwargs, *, captured=None):
    """按 fake scanner 入参写入终态。"""
    if captured is not None:
        captured.update(kwargs)
    output_dir = batch_scanner.agent_scanner.resolve_output_dir(
        cve_id=kwargs["cve_id"],
        target_repo=kwargs["target"].repo_name,
        target_commit=kwargs["target"].commit_hash,
        output_base=str(kwargs["output_base"]),
    )
    marker_sha256, _fingerprint = _write_terminal_scan_output(
        output_dir,
        reference_id=kwargs["cve_id"],
        repo_name=kwargs["target"].repo_name,
        commit_hash=kwargs["target"].commit_hash,
    )
    return {
        "succeeded": True,
        "cve_id": kwargs["cve_id"],
        "repo_name": kwargs["target"].repo_name,
        "commit": kwargs["target"].commit_hash,
        "scan_output_commit_sha256": marker_sha256,
        "terminal_status": "complete",
    }


def _reseal_terminal_output_with_finding(output_dir: Path) -> str:
    findings_path = output_dir / output_commit.SCAN_FINDINGS_FILENAME
    provenance_path = output_dir / output_commit.SCAN_PROVENANCE_FILENAME
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    findings["vulnerabilities"] = [{"forged": True}]
    provenance["coverage"]["scan_progress"]["findings"] = 1
    findings["scan_progress"]["findings"] = 1
    findings["run_provenance"] = provenance
    findings_path.write_text(
        json.dumps(findings, indent=2), encoding="utf-8"
    )
    provenance_path.write_text(
        json.dumps(provenance, indent=2), encoding="utf-8"
    )
    artifact_bytes = {
        name: (output_dir / name).read_bytes()
        for name in (
            output_commit.SCAN_FINDINGS_FILENAME,
            output_commit.SCAN_PROVENANCE_FILENAME,
            output_commit.SCAN_CONVERSATION_FILENAME,
        )
    }
    marker = output_commit.build_scan_output_commit(
        reference_id=provenance["reference_id"],
        terminal_status="complete",
        run_id=provenance["run_id"],
        scan_fingerprint_hash=provenance["scan_fingerprint"]["hash"],
        artifact_bytes=artifact_bytes,
    )
    marker_raw = json.dumps(marker, indent=2).encode("utf-8")
    (output_dir / output_commit.SCAN_OUTPUT_COMMIT_FILENAME).write_bytes(
        marker_raw
    )
    return hashlib.sha256(marker_raw).hexdigest()


def test_batch_scanner_reexports_cache_helpers_from_split_module():
    assert (
        batch_scanner._load_cached_software_profile_if_compatible
        is batch_scanner_cache._load_cached_software_profile_if_compatible
    )
    assert (
        batch_scanner._cached_vulnerability_profile_matches_current_inputs
        is batch_scanner_cache._cached_vulnerability_profile_matches_current_inputs
    )


def test_batch_scanner_reexports_execution_helpers_from_split_module():
    assert batch_scanner._run_target_scan is batch_scanner_execution._run_target_scan
    assert batch_scanner._run_selected_target_scans is batch_scanner_execution._run_selected_target_scans


def test_normalize_cve_id_fallback():
    assert batch_scanner._normalize_cve_id({"cve_id": ""}, 3) == "vuln-3"
    assert batch_scanner._normalize_cve_id({"cve_id": "CVE-2025-0001"}, 3) == "CVE-2025-0001"


def test_parse_args_accepts_explicit_source_and_target_flags(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--source-repos-root",
            "/source",
            "--target-repos-root",
            "/target",
            "--source-soft-profiles-dir",
            "soft-source",
            "--target-soft-profiles-dir",
            "soft-target",
        ],
    )

    args = batch_scanner.parse_args()

    assert args.source_repos_root == "/source"
    assert args.target_repos_root == "/target"
    assert args.source_soft_profiles_dir == "soft-source"
    assert args.target_soft_profiles_dir == "soft-target"


def test_parse_args_accepts_skip_any_existing_scan_result(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--skip-existing-scans",
            "--skip-any-existing-scan-result",
        ],
    )

    args = batch_scanner.parse_args()

    assert args.skip_existing_scans is True
    assert args.skip_any_existing_scan_result is True


def test_parse_args_defaults_critical_stop_mode_to_max(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["batch-scanner"])

    args = batch_scanner.parse_args()

    assert args.critical_stop_mode == "max"


def test_parse_args_defaults_similarity_model_to_embedding_default(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["batch-scanner"])

    args = batch_scanner.parse_args()

    assert args.similarity_model_name == DEFAULT_EMBEDDING_MODEL_NAME


def test_parse_args_accepts_run_id(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["batch-scanner", "--run-id", "run-manual"])

    args = batch_scanner.parse_args()

    assert args.run_id == "run-manual"


def test_parse_args_help_describes_skip_existing_scan_validation(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["batch-scanner", "--help"])

    with pytest.raises(SystemExit):
        batch_scanner.parse_args()

    captured = capsys.readouterr()
    assert "--skip-existing-scans" in captured.out
    assert "complete coverage" in captured.out
    assert "matching fingerprint" in captured.out


def test_parse_args_rejects_legacy_shared_target_flags(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--repos-root",
            "/target",
            "--soft-profiles-dir",
            "soft-target",
        ],
    )

    with pytest.raises(SystemExit):
        batch_scanner.parse_args()


def test_resolve_shared_public_memory_dir_scopes_by_run_id(tmp_path):
    resolved = batch_scanner.resolve_shared_public_memory_dir(
        scan_output_dir=tmp_path / "scan-results",
        run_id="run-123",
    )

    assert resolved == tmp_path / "scan-results" / "_runs" / "run-123" / "shared-public-memory"


def test_build_shared_public_memory_scope_does_not_hide_previous_attempts(tmp_path, monkeypatch):
    captured = {}

    class DummySharedPublicMemoryManager:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def describe_scope(self):
            return {"enabled": True, "root_hash": "root", "scope_key": "scope", "state_hash": "state"}

    monkeypatch.setattr(
        batch_scanner_execution,
        "SharedPublicMemoryManager",
        DummySharedPublicMemoryManager,
    )
    monkeypatch.setitem(batch_scanner_execution._path_config, "repo_root", tmp_path)

    scope = batch_scanner_execution._build_shared_public_memory_scope(
        batch_args=Namespace(
            shared_public_memory_dir=str(tmp_path / "shared"),
            run_id="run-1",
            scan_output_dir=str(tmp_path / "scan-results"),
        ),
        cve_id="CVE-2026-0001",
        repo_path=tmp_path / "repos" / "target-repo",
        repo_name="target-repo",
        repo_commit="a" * 40,
    )

    assert scope == {"enabled": True, "root_hash": "root", "scope_key": "scope", "state_hash": "state"}
    assert captured["producer_id"] == ""
    assert captured["visibility_scope_id"]


def test_validate_args_rejects_negative_limit():
    args = Namespace(
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=3,
        max_iterations_cap=10,
        jobs=1,
        limit=-1,
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-target",
        vuln_profiles_dir="vuln",
    )

    assert batch_scanner._validate_args(args) is False


def test_validate_args_rejects_non_positive_jobs():
    args = Namespace(
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=3,
        max_iterations_cap=10,
        jobs=0,
        limit=None,
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-target",
        vuln_profiles_dir="vuln",
    )

    assert batch_scanner._validate_args(args) is False


def test_select_similar_targets_applies_threshold_and_sort(monkeypatch):
    source = ProfileRef("src", "a" * 40, _mk_profile("src"))
    cand_a = ProfileRef("repo-a", "b" * 40, _mk_profile("a"))
    cand_b = ProfileRef("repo-b", "c" * 40, _mk_profile("b"))

    score_map = {
        "a": ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.5, 0.9, 0.8),
        "b": ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.7, 0.8, 0.8),
    }

    def fake_compute(source_profile, target_profile, text_retriever=None, weights=None):
        return score_map[target_profile.name]

    monkeypatch.setattr(batch_scanner, "compute_profile_similarity", fake_compute)

    ranked = batch_scanner._rank_similar_candidates(
        source_ref=source,
        candidate_refs=[cand_b, cand_a],
        text_retriever=None,
    )
    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=3,
    )

    assert [item.profile_ref.repo_name for item in selected] == ["repo-a", "repo-b"]
    assert fallback_used is True


def test_select_similar_targets_fallback_top_n_when_all_below_threshold(monkeypatch):
    source = ProfileRef("src", "a" * 40, _mk_profile("src"))
    cand_a = ProfileRef("repo-a", "b" * 40, _mk_profile("a"))
    cand_b = ProfileRef("repo-b", "c" * 40, _mk_profile("b"))
    cand_c = ProfileRef("repo-c", "d" * 40, _mk_profile("c"))

    score_map = {
        "a": ProfileSimilarityMetrics(0.6, 0.6, 0.6, 0.5, 0.6, 0.6),
        "b": ProfileSimilarityMetrics(0.5, 0.5, 0.5, 0.5, 0.5, 0.5),
        "c": ProfileSimilarityMetrics(0.4, 0.4, 0.4, 0.5, 0.4, 0.4),
    }

    def fake_compute(source_profile, target_profile, text_retriever=None, weights=None):
        return score_map[target_profile.name]

    monkeypatch.setattr(batch_scanner, "compute_profile_similarity", fake_compute)

    ranked = batch_scanner._rank_similar_candidates(
        source_ref=source,
        candidate_refs=[cand_b, cand_c, cand_a],
        text_retriever=None,
    )
    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=2,
    )

    assert fallback_used is True
    assert [item.profile_ref.repo_name for item in selected] == ["repo-a", "repo-b"]


def test_select_similar_targets_supplements_sparse_threshold_hits(monkeypatch):
    source = ProfileRef("src", "a" * 40, _mk_profile("src"))
    cand_a = ProfileRef("repo-a", "b" * 40, _mk_profile("a"))
    cand_b = ProfileRef("repo-b", "c" * 40, _mk_profile("b"))
    cand_c = ProfileRef("repo-c", "d" * 40, _mk_profile("c"))

    score_map = {
        "a": ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        "b": ProfileSimilarityMetrics(0.6, 0.6, 0.6, 0.6, 0.6, 0.6),
        "c": ProfileSimilarityMetrics(0.5, 0.5, 0.5, 0.5, 0.5, 0.5),
    }

    def fake_compute(source_profile, target_profile, text_retriever=None, weights=None):
        return score_map[target_profile.name]

    monkeypatch.setattr(batch_scanner, "compute_profile_similarity", fake_compute)

    ranked = batch_scanner._rank_similar_candidates(
        source_ref=source,
        candidate_refs=[cand_c, cand_b, cand_a],
        text_retriever=None,
    )
    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=2,
    )

    assert fallback_used is True
    assert [item.profile_ref.repo_name for item in selected] == ["repo-a", "repo-b"]


def test_resolve_source_software_profile_dir_from_args_with_relative_dirname(tmp_path):
    args = Namespace(
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
    )

    soft_dir = batch_scanner._resolve_source_software_profile_dir_from_args(args)

    assert soft_dir == tmp_path / "profiles" / "soft"


def test_resolve_target_and_vuln_profile_dirs_from_args_with_relative_dirnames(tmp_path):
    args = Namespace(
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft",
        vuln_profiles_dir="vuln",
    )

    soft_dir, vuln_dir = batch_scanner._resolve_target_and_vuln_profile_dirs_from_args(args)

    assert soft_dir == tmp_path / "profiles" / "soft"
    assert vuln_dir == tmp_path / "profiles" / "vuln"


def test_resolve_target_and_vuln_profile_dirs_from_args_with_absolute_paths(tmp_path):
    soft_abs = tmp_path / "custom-soft"
    vuln_abs = tmp_path / "custom-vuln"
    args = Namespace(
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir=str(soft_abs),
        vuln_profiles_dir=str(vuln_abs),
    )

    soft_dir, vuln_dir = batch_scanner._resolve_target_and_vuln_profile_dirs_from_args(args)

    assert soft_dir == soft_abs
    assert vuln_dir == vuln_abs


def test_resolve_batch_scan_paths_anchors_relative_cli_paths_to_repo_root(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    (repo_root / "data").mkdir()
    (repo_root / "data" / "vuln.json").write_text("[]", encoding="utf-8")
    (repo_root / "source-repos").mkdir()
    (repo_root / "target-repos").mkdir()
    monkeypatch.setitem(batch_scanner._path_config, "repo_root", repo_root)

    args = Namespace(
        vuln_json="data/vuln.json",
        source_repos_root="source-repos",
        target_repos_root="target-repos",
        profile_base_path="profiles",
        source_soft_profiles_dir="soft-source",
        target_soft_profiles_dir="soft-target",
        vuln_profiles_dir="vuln",
        scan_output_dir="results/scan-out",
    )

    paths = batch_scanner._resolve_batch_scan_paths(args)

    assert paths is not None
    assert paths.vuln_json == repo_root / "data" / "vuln.json"
    assert paths.source_repos_root == repo_root / "source-repos"
    assert paths.target_repos_root == repo_root / "target-repos"
    assert paths.source_repo_profiles_dir == repo_root / "profiles" / "soft-source"
    assert paths.target_repo_profiles_dir == repo_root / "profiles" / "soft-target"
    assert paths.vuln_profiles_dir == repo_root / "profiles" / "vuln"
    assert paths.scan_output_dir == repo_root / "results" / "scan-out"


def test_resolve_batch_scan_paths_rejects_non_directory_target_root(monkeypatch, tmp_path):
    repo_root = tmp_path / "llm-vulvariant"
    repo_root.mkdir()
    (repo_root / "data").mkdir()
    (repo_root / "data" / "vuln.json").write_text("[]", encoding="utf-8")
    (repo_root / "source-repos").mkdir()
    (repo_root / "target-repos").write_text("not-a-dir", encoding="utf-8")
    monkeypatch.setitem(batch_scanner._path_config, "repo_root", repo_root)

    args = Namespace(
        vuln_json="data/vuln.json",
        source_repos_root="source-repos",
        target_repos_root="target-repos",
        profile_base_path="profiles",
        source_soft_profiles_dir="soft-source",
        target_soft_profiles_dir="soft-target",
        vuln_profiles_dir="vuln",
        scan_output_dir="results/scan-out",
    )

    assert batch_scanner._resolve_batch_scan_paths(args) is None


def test_ensure_source_inputs_available_rejects_non_directory_source_root(tmp_path):
    source_root = tmp_path / "source-repos"
    source_root.write_text("not-a-dir", encoding="utf-8")
    paths = batch_scanner.BatchScanPaths(
        vuln_json=tmp_path / "vuln.json",
        source_repos_root=source_root,
        target_repos_root=tmp_path / "target-repos",
        source_repo_profiles_dir=tmp_path / "soft-source",
        target_repo_profiles_dir=tmp_path / "soft-target",
        vuln_profiles_dir=tmp_path / "vuln",
        scan_output_dir=tmp_path / "scan-out",
    )

    ok = batch_scanner._ensure_source_inputs_available(
        args=Namespace(force_regenerate_profiles=False),
        paths=paths,
        entries=[],
    )

    assert ok is False


def test_run_target_scan_passes_profile_base_path_and_dirname(monkeypatch, tmp_path):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=False,
        run_id="run-123",
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
        similarity_model_name="mini-model",
        similarity_device="cuda",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    ok = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert ok == "ok"
    assert captured["profile_base_path"] == str(tmp_path / "profiles")
    assert captured["software_profile_dirname"] == "soft-nvidia"
    assert captured["repo_base_path"] == tmp_path / "repos"
    assert captured["max_iterations"] == 3
    assert captured["cve_id"] == "CVE-2026-0001"
    assert captured["shared_public_memory_dir"] == (
        tmp_path / "scan-out" / "_runs" / "run-123" / "shared-public-memory"
    )
    assert captured["module_similarity_config"] == {
        "model_name": "mini-model",
        "device": "cuda",
        "require_embedding": False,
    }


def test_ensure_software_profile_delegates_cache_validation_to_generator(monkeypatch, tmp_path):
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "demo"
    repo_dir.mkdir(parents=True)
    profiles_dir = tmp_path / "profiles"
    generated = []
    loaded_profile = _mk_profile("demo")

    monkeypatch.setattr(
        batch_scanner,
        "run_software_profile_generation",
        lambda **kwargs: generated.append(kwargs),
    )
    monkeypatch.setattr(batch_scanner, "load_software_profile", lambda *args, **kwargs: loaded_profile)

    profile = batch_scanner._ensure_software_profile(
        repo_name="demo",
        commit_hash="a" * 40,
        repos_root=repo_root,
        repo_profiles_dir=profiles_dir,
        llm_client=object(),
        force_regenerate=False,
        cache={},
        regenerated_keys=set(),
    )

    assert profile is loaded_profile
    assert len(generated) == 1


def test_ensure_software_profile_missing_repo_uses_fingerprint_validated_cache(monkeypatch, tmp_path):
    profiles_dir = tmp_path / "profiles"
    cached_profile = _mk_profile("demo")
    captured = {}

    def fake_load_cached(**kwargs):
        captured.update(kwargs)
        return cached_profile

    monkeypatch.setattr(
        batch_scanner,
        "_load_cached_software_profile_if_compatible",
        fake_load_cached,
    )
    monkeypatch.setattr(
        batch_scanner,
        "load_software_profile",
        lambda *args, **kwargs: pytest.fail("missing-repo reuse must not bypass fingerprint validation"),
    )

    profile = batch_scanner._ensure_software_profile(
        repo_name="demo",
        commit_hash="a" * 40,
        repos_root=tmp_path / "repos",
        repo_profiles_dir=profiles_dir,
        llm_client=object(),
        force_regenerate=False,
        cache={},
        regenerated_keys=set(),
    )

    assert profile is cached_profile
    assert captured["repo_name"] == "demo"
    assert captured["commit_hash"] == "a" * 40
    assert captured["repo_profiles_dir"] == profiles_dir


def test_ensure_software_profile_dirty_repo_uses_fingerprint_validated_cache(monkeypatch, tmp_path):
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "demo"
    repo_dir.mkdir(parents=True)
    profiles_dir = tmp_path / "profiles"
    cached_profile = _mk_profile("demo")
    captured = {}

    def fake_load_cached(**kwargs):
        captured.update(kwargs)
        return cached_profile

    monkeypatch.setattr(batch_scanner, "has_uncommitted_changes", lambda _path: True)
    monkeypatch.setattr(batch_scanner, "_is_git_worktree_root", lambda _path: True)
    monkeypatch.setattr(
        batch_scanner,
        "_load_cached_software_profile_if_compatible",
        fake_load_cached,
    )
    monkeypatch.setattr(
        batch_scanner,
        "load_software_profile",
        lambda *args, **kwargs: pytest.fail("dirty-repo reuse must not bypass fingerprint validation"),
    )

    profile = batch_scanner._ensure_software_profile(
        repo_name="demo",
        commit_hash="a" * 40,
        repos_root=repo_root,
        repo_profiles_dir=profiles_dir,
        llm_client=object(),
        force_regenerate=False,
        cache={},
        regenerated_keys=set(),
    )

    assert profile is cached_profile
    assert captured["repo_name"] == "demo"
    assert captured["commit_hash"] == "a" * 40
    assert captured["repo_profiles_dir"] == profiles_dir


def test_run_target_scan_reports_skipped_for_existing_findings(monkeypatch, tmp_path):
    expected_fingerprint = {}

    def fake_run_single_target_scan(**kwargs):
        raise AssertionError("existing result should have been skipped")

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_scan_languages", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_codeql_database_names", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        lambda **_kwargs: {"hash": "expected"},
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: dict(expected_fingerprint),
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    marker_sha256, fingerprint = _write_terminal_scan_output(output_dir)
    expected_fingerprint.update(fingerprint)
    batch_args.scan_output_commit_hashes = {
        batch_scanner_execution.scan_output_binding_key(
            "CVE-2026-0001", "target-repo", "a" * 40
        ): marker_sha256
    }

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "skipped"


def test_run_target_scan_skips_any_existing_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **_kwargs: pytest.fail("existing findings should be skipped"),
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        skip_any_existing_scan_result=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps({"coverage_status": "partial"}),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "skipped"


def test_run_target_scan_does_not_skip_legacy_findings_when_live_validation_is_unavailable(
    monkeypatch,
    tmp_path,
):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: None,
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps({"coverage_status": "complete"}),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_reuses_complete_saved_findings_when_live_validation_is_unavailable(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **kwargs: pytest.fail("complete saved findings should be reused"),
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: None,
    )
    expected_fingerprint = {}
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_profile_based_scan_fingerprint_for_skip",
        lambda **_kwargs: dict(expected_fingerprint),
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    marker_sha256, fingerprint = _write_terminal_scan_output(output_dir)
    expected_fingerprint.update(fingerprint)
    batch_args.scan_output_commit_hashes = {
        batch_scanner_execution.scan_output_binding_key(
            "CVE-2026-0001", "target-repo", "a" * 40
        ): marker_sha256
    }

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "skipped"


def test_run_target_scan_does_not_reuse_saved_findings_when_live_validation_fails_on_existing_repo(
    monkeypatch,
    tmp_path,
):
    repo_dir = tmp_path / "repos" / "target-repo"
    repo_dir.mkdir(parents=True)
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        fake_run_single_target_scan,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_profile_based_scan_fingerprint_for_skip",
        lambda **_kwargs: pytest.fail("existing target checkout must not use profile-only fallback"),
    )
    monkeypatch.setattr(batch_scanner, "has_uncommitted_changes", lambda _path: False)

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps(
            {
                "coverage_status": "complete",
                "scan_fingerprint": {
                    "hash": "saved",
                    "scan_config": {"max_iterations": 3},
                },
            }
        ),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_rescans_when_profile_based_skip_fingerprint_is_stale(
    monkeypatch,
    tmp_path,
):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_profile_based_scan_fingerprint_for_skip",
        lambda **_kwargs: {"hash": "current"},
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps(
            {
                "coverage_status": "complete",
                "scan_fingerprint": {
                    "hash": "saved",
                    "scan_config": {"max_iterations": 3},
                },
            }
        ),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_does_not_reuse_profile_only_skip_validation_for_dirty_target_repo(
    monkeypatch,
    tmp_path,
):
    repo_dir = tmp_path / "repos" / "target-repo"
    repo_dir.mkdir(parents=True)
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        fake_run_single_target_scan,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_profile_based_scan_fingerprint_for_skip",
        lambda **_kwargs: pytest.fail("dirty target with existing checkout must not use profile-only fallback"),
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps(
            {
                "coverage_status": "complete",
                "scan_fingerprint": {
                    "hash": "saved",
                    "scan_config": {"max_iterations": 3},
                },
            }
        ),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_builds_skip_existing_fingerprint_from_checked_out_target_tree(
    monkeypatch,
    tmp_path,
):
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "target-repo"
    repo_dir.mkdir(parents=True)
    marker_path = repo_dir / "marker.txt"
    marker_path.write_text("current", encoding="utf-8")

    state = {"commit": "current"}

    monkeypatch.setattr(batch_scanner_execution, "get_git_commit", lambda _path: state["commit"])
    monkeypatch.setattr(batch_scanner_execution, "get_git_restore_target", lambda _path: "current")
    monkeypatch.setattr(batch_scanner_execution, "has_uncommitted_changes", lambda _path: False)

    def _fake_checkout(_path, commit):
        state["commit"] = commit
        marker_path.write_text("target", encoding="utf-8")
        return True

    def _fake_restore(_path, _target):
        state["commit"] = "current"
        marker_path.write_text("current", encoding="utf-8")
        return True

    monkeypatch.setattr(batch_scanner_execution, "checkout_commit", _fake_checkout)
    monkeypatch.setattr(batch_scanner_execution, "restore_git_position", _fake_restore)
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "_resolve_scan_languages",
        lambda repo_path, _profile: [marker_path.read_text(encoding="utf-8")],
    )
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_codeql_database_names", lambda *_args, **_kwargs: {})
    captured_fingerprint = {}
    expected_fingerprint = {}

    def _fake_build_scan_fingerprint(**kwargs):
        captured_fingerprint.update(kwargs)
        return dict(expected_fingerprint)

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        _fake_build_scan_fingerprint,
    )
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **kwargs: pytest.fail("matching target-tree fingerprint should skip rescans"),
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=repo_root,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        critical_stop_max_priority=1,
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
        similarity_model_name="mini-model",
        similarity_device="cuda",
    )
    target_commit = "d" * 40
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", target_commit, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = (
        tmp_path
        / "scan-out"
        / "CVE-2026-0001"
        / f"target-repo-{target_commit[:12]}"
    )
    marker_sha256, fingerprint = _write_terminal_scan_output(
        output_dir,
        commit_hash=target_commit,
    )
    expected_fingerprint.update(fingerprint)
    batch_args.scan_output_commit_hashes = {
        batch_scanner_execution.scan_output_binding_key(
            "CVE-2026-0001", "target-repo", target_commit
        ): marker_sha256
    }

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "skipped"
    assert marker_path.read_text(encoding="utf-8") == "current"
    assert captured_fingerprint["critical_stop_max_priority"] == 1
    assert captured_fingerprint["module_similarity_config"] == {
        "model_name": "mini-model",
        "device": "cuda",
        "require_embedding": False,
    }


def test_build_expected_scan_fingerprint_for_skip_raises_when_restore_fails(
    monkeypatch,
    tmp_path,
):
    repo_dir = tmp_path / "repos" / "target-repo"
    repo_dir.mkdir(parents=True)

    @contextmanager
    def _fake_lock(*_args, **_kwargs):
        yield

    state = {"commit": "current"}
    monkeypatch.setattr(batch_scanner_execution, "hold_repo_lock", _fake_lock)
    monkeypatch.setattr(batch_scanner_execution, "get_git_commit", lambda _path: state["commit"])
    monkeypatch.setattr(batch_scanner_execution, "get_git_restore_target", lambda _path: "current")
    monkeypatch.setattr(batch_scanner_execution, "has_uncommitted_changes", lambda _path: False)
    monkeypatch.setattr(
        batch_scanner_execution,
        "checkout_commit",
        lambda _path, commit: state.__setitem__("commit", commit) or True,
    )
    monkeypatch.setattr(batch_scanner_execution, "restore_git_position", lambda _path, _target: False)
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_scan_languages", lambda *_args, **_kwargs: ["python"])
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_codeql_database_names", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        lambda **_kwargs: {"hash": "expected"},
    )

    batch_args = Namespace(
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
    )
    target_commit = "t" * 40
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", target_commit, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    scan_target = batch_scanner.agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=target_commit,
        similarity=target,
    )

    with pytest.raises(RuntimeError, match="Failed to restore target-repo"):
        batch_scanner._build_expected_scan_fingerprint_for_skip(
            batch_args=batch_args,
            cve_id="CVE-2026-0001",
            vulnerability_profile=object(),
            llm_client=object(),
            target=target,
            scan_target=scan_target,
            target_repo_path=repo_dir,
        )


def test_build_profile_based_scan_fingerprint_for_skip_uses_profile_repo_path_hashed_codeql_database_names(monkeypatch):
    captured = {}

    def _fake_build_scan_fingerprint(**kwargs):
        captured.update(kwargs)
        return {"hash": "expected"}

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        _fake_build_scan_fingerprint,
    )

    batch_args = Namespace(
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
    )
    target_commit = "t" * 40
    profile_repo_path = Path("/tmp/target-profile").resolve()
    target_profile = _mk_profile("target-repo")
    target_profile.repo_info = {"repo_analysis": {"codeql_languages": ["python", "javascript"]}}
    target_profile.metadata = {"profile_repo_path": str(profile_repo_path)}
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            "target-repo",
            target_commit,
            target_profile,
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    scan_target = batch_scanner.agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=target_commit,
        similarity=target,
    )

    fingerprint = batch_scanner._build_profile_based_scan_fingerprint_for_skip(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
        scan_target=scan_target,
    )

    assert fingerprint == {"hash": "expected"}
    expected_path_hash = batch_scanner.agent_scanner.stable_data_hash(str(profile_repo_path))[:12]
    assert captured["codeql_database_names"] == {
        "python": f"target-repo-{expected_path_hash}-tttttttt-python",
        "javascript": f"target-repo-{expected_path_hash}-tttttttt-javascript",
    }


def test_build_profile_based_scan_fingerprint_for_skip_includes_shared_memory_scope(monkeypatch, tmp_path):
    captured = {}

    def _fake_build_scan_fingerprint(**kwargs):
        captured.update(kwargs)
        return {"hash": "expected"}

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        _fake_build_scan_fingerprint,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_shared_public_memory_scope",
        lambda **kwargs: {
            "enabled": True,
            "root_hash": "run-root",
            "scope_key": "repo-scope",
            "state_hash": "shared-state",
        },
    )

    batch_args = Namespace(
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        target_repos_root=str(tmp_path / "repos"),
        scan_output_dir=str(tmp_path / "scan-out"),
        run_id="run-1",
        shared_public_memory_dir=str(
            tmp_path / "scan-out" / "_runs" / "run-1" / "shared-public-memory"
        ),
    )
    target_commit = "t" * 40
    target_profile = _mk_profile("target-repo")
    target_profile.repo_info = {"repo_analysis": {"languages": ["python"]}}
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", target_commit, target_profile),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    scan_target = batch_scanner.agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=target_commit,
        similarity=target,
    )

    fingerprint = batch_scanner._build_profile_based_scan_fingerprint_for_skip(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
        scan_target=scan_target,
    )

    assert fingerprint == {"hash": "expected"}
    assert captured["shared_public_memory_scope"] == {
        "enabled": True,
        "root_hash": "run-root",
        "scope_key": "repo-scope",
        "state_hash": "shared-state",
    }


def test_run_target_scan_rescans_existing_findings_without_complete_coverage(monkeypatch, tmp_path):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_scan_languages", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_codeql_database_names", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        lambda **_kwargs: {"hash": "expected"},
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: {"hash": "expected"},
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text("{}", encoding="utf-8")

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_rescans_existing_findings_when_scan_fingerprint_is_stale(monkeypatch, tmp_path):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_scan_languages", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(batch_scanner.agent_scanner, "_resolve_codeql_database_names", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "build_scan_fingerprint",
        lambda **_kwargs: {"hash": "expected"},
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_expected_scan_fingerprint_for_skip",
        lambda **_kwargs: {"hash": "expected"},
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps({"coverage_status": "complete", "scan_fingerprint": {"hash": "stale"}}),
        encoding="utf-8",
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["target"].repo_name == "target-repo"


def test_run_target_scan_does_not_skip_existing_when_profiles_are_regenerated(monkeypatch, tmp_path):
    captured = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(kwargs, captured=captured)

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=True,
        force_regenerate_profiles=True,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-aaaaaaaaaaaa"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text("{}", encoding="utf-8")

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "ok"
    assert captured["repo_base_path"] == tmp_path / "repos"


def test_run_target_scan_reports_incomplete_for_partial_coverage(monkeypatch, tmp_path):
    def fake_run_single_target_scan(**kwargs):
        output_dir = batch_scanner.agent_scanner.resolve_output_dir(
            cve_id=kwargs["cve_id"],
            target_repo=kwargs["target"].repo_name,
            target_commit=kwargs["target"].commit_hash,
            output_base=str(kwargs["output_base"]),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "agentic_vuln_findings.json").write_text(
            json.dumps({"coverage_status": "partial"}),
            encoding="utf-8",
        )
        return False

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "incomplete"


def test_run_target_scan_reports_failed_when_stale_partial_output_was_not_updated(monkeypatch, tmp_path):
    output_dir = batch_scanner.agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001",
        target_repo="target-repo",
        target_commit="a" * 40,
        output_base=str(tmp_path / "scan-out"),
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    findings_path = output_dir / "agentic_vuln_findings.json"
    findings_path.write_text(
        json.dumps({"coverage_status": "partial"}),
        encoding="utf-8",
    )
    original_mtime_ns = findings_path.stat().st_mtime_ns

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **_kwargs: False,
    )

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    status = batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert status == "failed"
    assert findings_path.stat().st_mtime_ns == original_mtime_ns


def test_load_saved_scan_quality_reads_legacy_coverage_without_trusting_fingerprint(tmp_path):
    output_dir = tmp_path / "scan-out"
    output_dir.mkdir()
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps(
            {
                "coverage_status": "partial",
                "critical_scope_present": True,
                "critical_complete": False,
                "critical_scope_total_files": 12,
                "critical_scope_completed_files": 4,
                "scan_progress": {"completed": 4, "pending": 8, "findings": 1},
                "scan_fingerprint": {"hash": "expected"},
            }
        ),
        encoding="utf-8",
    )

    saved = batch_scanner._load_saved_scan_quality(output_dir)

    assert saved["coverage_status"] == "partial"
    assert saved["critical_scope_total_files"] == 12
    assert saved["scan_progress"]["completed"] == 4
    assert saved["scan_fingerprint_hash"] == ""
    assert saved["terminal_commit_valid"] is False


def test_ensure_vulnerability_profile_uses_source_repos_root_for_vuln_loading(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    source_repos_root = tmp_path / "repos"
    (source_repos_root / repo_name).mkdir(parents=True)

    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "load_vulnerability_profile", lambda *args, **kwargs: None)
    monkeypatch.setattr(batch_scanner, "has_uncommitted_changes", lambda _path: False)

    captured = {}

    def fake_read_vuln_data(index, verbose=False, vuln_json_path=None, repo_base_path=None):
        captured["index"] = index
        captured["repo_base_path"] = repo_base_path
        captured["vuln_json_path"] = vuln_json_path
        return [
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": [{"vuln_sink": "eval"}],
                "payload": "payload",
                "cve_id": cve_id,
            }
        ]

    monkeypatch.setattr(batch_scanner, "read_vuln_data", fake_read_vuln_data)
    monkeypatch.setattr(
        batch_scanner,
        "run_vulnerability_profile_generation",
        lambda *, repo_path, output_dir, llm_client, repo_profile, vuln_entry, force_regenerate: captured.update(
            {
                "output_dir": output_dir,
                "vuln_entry_cve": vuln_entry.cve_id,
                "repo_path": str(repo_path),
                "force_regenerate": force_regenerate,
            }
        ),
    )

    profile = batch_scanner._ensure_vulnerability_profile(
        vuln_index=4,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=source_repos_root,
        repo_profiles_dir=tmp_path / "profiles" / "soft",
        vuln_profiles_dir=tmp_path / "profiles" / "vuln",
        llm_client=None,
        force_regenerate=False,
        software_cache={},
        regenerated_software_keys=set(),
        cache={},
        verbose=False,
        vuln_json_path=str(tmp_path / "vuln.json"),
    )

    assert profile is None
    assert captured["index"] == 4
    assert captured["repo_base_path"] == source_repos_root
    assert captured["vuln_json_path"] == str(tmp_path / "vuln.json")
    assert captured["repo_path"] == str(source_repos_root / repo_name)
    assert captured["vuln_entry_cve"] == cve_id
    assert captured["force_regenerate"] is False


def test_ensure_software_profile_force_regenerate_preserves_existing_profile_until_success(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "a" * 40
    repo_profiles_dir = tmp_path / "profiles" / "soft"
    profile_path = repo_profiles_dir / repo_name / commit_hash / "software_profile.json"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(json.dumps({"marker": "old"}), encoding="utf-8")
    repos_root = tmp_path / "repos"
    (repos_root / repo_name).mkdir(parents=True)

    def fake_load(repo_name_arg, commit_hash_arg, base_dir):
        if profile_path.exists():
            return {"marker": json.loads(profile_path.read_text(encoding="utf-8"))["marker"]}
        return None

    captured = {}

    def fake_generate(**kwargs):
        captured["profile_exists_during_regen"] = profile_path.exists()

    monkeypatch.setattr(batch_scanner, "load_software_profile", fake_load)
    monkeypatch.setattr(batch_scanner, "run_software_profile_generation", fake_generate)

    profile = batch_scanner._ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=None,
        force_regenerate=True,
        cache={},
        regenerated_keys=set(),
    )

    assert captured["profile_exists_during_regen"] is True
    assert profile == {"marker": "old"}
    assert json.loads(profile_path.read_text(encoding="utf-8"))["marker"] == "old"


def test_ensure_vulnerability_profile_force_regenerate_preserves_existing_profile_until_success(
    monkeypatch,
    tmp_path,
):
    repo_name = "demo"
    commit_hash = "a" * 40
    cve_id = "CVE-2026-0001"
    vuln_profiles_dir = tmp_path / "profiles" / "vuln"
    profile_path = vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json"
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(json.dumps({"marker": "old"}), encoding="utf-8")
    repos_root = tmp_path / "repos"
    (repos_root / repo_name).mkdir(parents=True)

    def fake_load(repo_name_arg, cve_id_arg, base_dir):
        if profile_path.exists():
            return {"marker": json.loads(profile_path.read_text(encoding="utf-8"))["marker"]}
        return None

    monkeypatch.setattr(batch_scanner, "load_vulnerability_profile", fake_load)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "has_uncommitted_changes", lambda _path: False)
    monkeypatch.setattr(
        batch_scanner,
        "read_vuln_data",
        lambda *args, **kwargs: [
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": [{"vuln_sink": "eval"}],
                "payload": "payload",
                "cve_id": cve_id,
            }
        ],
    )
    monkeypatch.setattr(batch_scanner, "build_vulnerability_entry", lambda vuln_data: object())
    captured = {}

    def fake_generate(**kwargs):
        captured["profile_exists_during_regen"] = profile_path.exists()

    monkeypatch.setattr(batch_scanner, "run_vulnerability_profile_generation", fake_generate)

    profile = batch_scanner._ensure_vulnerability_profile(
        vuln_index=0,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=repos_root,
        repo_profiles_dir=tmp_path / "profiles" / "soft",
        vuln_profiles_dir=vuln_profiles_dir,
        llm_client=None,
        force_regenerate=True,
        software_cache={},
        regenerated_software_keys=set(),
        cache={},
        verbose=False,
        vuln_json_path=str(tmp_path / "vuln.json"),
    )

    assert captured["profile_exists_during_regen"] is True
    assert profile == {"marker": "old"}
    assert json.loads(profile_path.read_text(encoding="utf-8"))["marker"] == "old"


def test_build_batch_summary_records_run_selection_knobs(tmp_path):
    args = Namespace(
        similarity_threshold=0.7,
        max_targets=3,
        fallback_top_n=2,
        include_same_repo=True,
        limit=5,
        max_iterations_cap=10,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=True,
        skip_existing_scans=False,
        skip_any_existing_scan_result=True,
        jobs=4,
        llm_provider="deepseek",
        llm_name="deepseek-chat",
    )
    paths = batch_scanner.BatchScanPaths(
        vuln_json=tmp_path / "vuln.json",
        source_repos_root=tmp_path / "source-repos",
        target_repos_root=tmp_path / "target-repos",
        source_repo_profiles_dir=tmp_path / "soft-source",
        target_repo_profiles_dir=tmp_path / "soft-target",
        vuln_profiles_dir=tmp_path / "vuln",
        scan_output_dir=tmp_path / "scan-out",
    )

    summary = batch_scanner._build_batch_summary(args, paths)

    assert summary["max_targets"] == 3
    assert summary["min_threshold_hits"] == 3
    assert summary["fallback_top_n"] == 2
    assert summary["include_same_repo"] is True
    assert summary["limit"] == 5
    assert summary["force_regenerate_profiles"] is True
    assert summary["skip_any_existing_scan_result"] is True
    assert summary["jobs"] == 4
    assert summary["llm_name"] == "deepseek-chat"


def test_ensure_vulnerability_profile_cache_isolated_by_commit(tmp_path):
    repo_name = "source-repo"
    cve_id = "CVE-2026-0001"
    first_commit = "a" * 40
    second_commit = "b" * 40
    first_profile = object()
    second_profile = object()
    cache = {
        (repo_name, first_commit, cve_id): first_profile,
        (repo_name, second_commit, cve_id): second_profile,
    }

    def load_cached_profile(commit_hash):
        return batch_scanner._ensure_vulnerability_profile(
            vuln_index=0,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            repos_root=tmp_path / "repos",
            repo_profiles_dir=tmp_path / "profiles" / "soft",
            vuln_profiles_dir=tmp_path / "profiles" / "vuln",
            llm_client=None,
            force_regenerate=False,
            software_cache={},
            regenerated_software_keys=set(),
            cache=cache,
            verbose=False,
        )

    assert load_cached_profile(first_commit) is first_profile
    assert load_cached_profile(second_commit) is second_profile


@pytest.mark.parametrize("jobs", [1, 2])
def test_run_selected_target_scans_records_unexpected_task_exception(
    monkeypatch,
    jobs,
):
    targets = [
        SimilarProfileCandidate(
            profile_ref=ProfileRef("broken-target", "a" * 40, _mk_profile("broken")),
            metrics=ProfileSimilarityMetrics(0.9, 0.9, 0.9, 0.9, 0.9, 0.9),
        ),
        SimilarProfileCandidate(
            profile_ref=ProfileRef("healthy-target", "b" * 40, _mk_profile("healthy")),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    ]

    def fake_run_task(*, target, **_kwargs):
        if target.profile_ref.repo_name == "broken-target":
            raise RuntimeError("boom")
        return {
            "status": "ok",
            "started_at": "2026-08-22T00:00:00",
            "finished_at": "2026-08-22T00:00:01",
            "duration_seconds": 1.0,
        }

    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan_task", fake_run_task)

    results = batch_scanner._run_selected_target_scans(
        batch_args=Namespace(jobs=jobs),
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        similar_targets=targets,
    )

    assert [item["repo_name"] for item in results] == [
        "broken-target",
        "healthy-target",
    ]
    assert [item["commit_hash"] for item in results] == ["a" * 40, "b" * 40]
    assert [item["status"] for item in results] == ["failed", "ok"]
    assert results[0]["coverage_status"] == "unknown"
    assert results[0]["termination"] == "worker_exception"
    assert "RuntimeError: boom" in results[0]["failure_reason"]


def test_run_selected_target_scans_preserves_target_order_with_parallel_workers(monkeypatch):
    targets = [
        SimilarProfileCandidate(
            profile_ref=ProfileRef("target-a", "a" * 40, _mk_profile("target-a")),
            metrics=ProfileSimilarityMetrics(0.9, 0.9, 0.9, 0.9, 0.9, 0.9),
        ),
        SimilarProfileCandidate(
            profile_ref=ProfileRef("target-b", "b" * 40, _mk_profile("target-b")),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    ]

    slow_started = threading.Event()
    release_slow = threading.Event()

    def fake_run_task(*, batch_args, cve_id, vulnerability_profile, target):
        if target.profile_ref.repo_name == "target-a":
            slow_started.set()
            assert release_slow.wait(timeout=1.0) is True
        else:
            assert slow_started.wait(timeout=1.0) is True
            release_slow.set()
        status = "ok" if target.profile_ref.repo_name == "target-a" else "failed"
        return {
            "status": status,
            "failure_reason": "synthetic failure" if status == "failed" else None,
            "started_at": f"start-{target.profile_ref.repo_name}",
            "finished_at": f"finish-{target.profile_ref.repo_name}",
            "duration_seconds": 0.02,
        }

    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan_task", fake_run_task)

    results = batch_scanner._run_selected_target_scans(
        batch_args=Namespace(jobs=2),
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        similar_targets=targets,
    )

    assert [item["repo_name"] for item in results] == ["target-a", "target-b"]
    assert [item["status"] for item in results] == ["ok", "failed"]
    assert results[0]["started_at"] == "start-target-a"
    assert results[1]["finished_at"] == "finish-target-b"
    assert results[1]["failure_reason"] == "synthetic failure"


def test_discover_latest_repo_refs_reads_head_under_repo_lock(monkeypatch, tmp_path):
    repos_root = tmp_path / "repos"
    repo_dir = repos_root / "demo-repo"
    repo_dir.mkdir(parents=True)
    captured = {}

    @contextmanager
    def fake_hold_repo_lock(repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        captured["repo_path"] = repo_path
        captured["purpose"] = purpose
        yield

    monkeypatch.setattr(batch_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(batch_scanner, "get_git_commit", lambda repo_path: "a" * 40)
    monkeypatch.setattr(
        batch_scanner,
        "_ensure_software_profile",
        lambda **kwargs: _mk_profile("demo-repo"),
    )

    refs = batch_scanner._discover_latest_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=tmp_path / "profiles" / "soft",
        llm_client=None,
        force_regenerate_profiles=False,
        software_cache={},
        regenerated_software_keys=set(),
    )

    assert "demo-repo" in refs
    assert captured["repo_path"] == repo_dir
    assert captured["purpose"] == "discover_latest_repo_ref"


def test_main_uses_separate_source_and_target_roots_and_profile_dirs(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
    )
    source_profile = _mk_profile("source")
    vulnerability_profile = object()
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    captured = {}

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)

    def fake_create_profile_llm_client(provider, model):
        captured["profile_llm"] = (provider, model)
        return object()

    monkeypatch.setattr(
        batch_scanner,
        "create_profile_llm_client",
        fake_create_profile_llm_client,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "create_llm_client",
        lambda config: object(),
    )
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )

    def fake_discover_latest_repo_refs(
        *,
        repos_root,
        repo_profiles_dir,
        llm_client,
        force_regenerate_profiles,
        software_cache,
        regenerated_software_keys,
    ):
        captured["target_repos_root"] = repos_root
        captured["target_repo_profiles_dir"] = repo_profiles_dir
        return {"target-repo": target_candidate.profile_ref}

    def fake_ensure_software_profile(
        *,
        repo_name,
        commit_hash,
        repos_root,
        repo_profiles_dir,
        llm_client,
        force_regenerate,
        reuse_existing_profiles_without_validation,
        cache,
        regenerated_keys,
    ):
        captured["source_repos_root"] = repos_root
        captured["source_repo_profiles_dir"] = repo_profiles_dir
        return source_profile

    def fake_ensure_vulnerability_profile(
        *,
        vuln_index,
        repo_name,
        commit_hash,
        cve_id,
        repos_root,
        repo_profiles_dir,
        vuln_profiles_dir,
        llm_client,
        force_regenerate,
        reuse_existing_profiles_without_validation,
        software_cache,
        regenerated_software_keys,
        cache,
        verbose,
        vuln_json_path=None,
    ):
        captured["vuln_source_repos_root"] = repos_root
        captured["vuln_source_repo_profiles_dir"] = repo_profiles_dir
        captured["resolved_vuln_profiles_dir"] = vuln_profiles_dir
        return vulnerability_profile

    monkeypatch.setattr(batch_scanner, "_discover_latest_repo_refs", fake_discover_latest_repo_refs)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", fake_ensure_software_profile)
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", fake_ensure_vulnerability_profile)
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_candidate])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "ok")
    monkeypatch.setattr(
        batch_scanner_execution,
        "_load_saved_scan_quality",
        _complete_saved_scan_quality,
    )


    exit_code = batch_scanner.main()

    assert exit_code == 0
    assert captured["source_repos_root"] == source_repos_root
    assert captured["target_repos_root"] == target_repos_root
    assert captured["source_repo_profiles_dir"] == tmp_path / "profiles" / "soft"
    assert captured["target_repo_profiles_dir"] == tmp_path / "profiles" / "soft-nvidia"
    assert captured["vuln_source_repos_root"] == source_repos_root
    assert captured["vuln_source_repo_profiles_dir"] == tmp_path / "profiles" / "soft"
    assert captured["resolved_vuln_profiles_dir"] == tmp_path / "profiles" / "vuln"
    assert captured["profile_llm"] == ("deepseek", None)


def test_main_records_skipped_status_in_summary(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    scan_output_dir = tmp_path / "scan-out"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        skip_any_existing_scan_result=True,
        limit=None,
        verbose=False,
    )
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_candidate])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "skipped")

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["incomplete_scans"] == 0
    assert summary["failed_scans"] == 0
    assert summary["coverage_complete_scans"] == 0
    assert summary["coverage_partial_scans"] == 0
    assert summary["coverage_empty_scans"] == 0
    assert summary["coverage_unknown_scans"] == 1
    assert summary["status"] == "partial"
    assert summary["failure_reason"] == "coverage_unknown_scans=1"
    assert summary["entries"][0]["scan_results"][0]["status"] == "skipped"


def test_main_returns_failure_when_only_skipped_and_failed_scans_remain(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    scan_output_dir = tmp_path / "scan-out"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        skip_any_existing_scan_result=True,
        limit=None,
        verbose=False,
    )
    target_a = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-a", "b" * 40, _mk_profile("target-a")),
        metrics=ProfileSimilarityMetrics(0.9, 0.9, 0.9, 0.9, 0.9, 0.9),
    )
    target_b = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-b", "c" * 40, _mk_profile("target-b")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    scan_results = iter(["skipped", "failed"])

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {
            "target-a": target_a.profile_ref,
            "target-b": target_b.profile_ref,
        },
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_a, target_b])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: next(scan_results))

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["incomplete_scans"] == 0
    assert summary["failed_scans"] == 1
    assert summary["coverage_complete_scans"] == 0
    assert summary["coverage_partial_scans"] == 0
    assert summary["coverage_empty_scans"] == 0
    assert summary["coverage_unknown_scans"] == 2
    assert [item["status"] for item in summary["entries"][0]["scan_results"]] == ["skipped", "failed"]


def test_main_returns_failure_when_skipped_scans_and_profile_generation_failure_coexist(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    scan_output_dir = tmp_path / "scan-out"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        skip_any_existing_scan_result=True,
        limit=None,
        verbose=False,
    )
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [
            (0, {"repo_name": "source-repo-a", "commit": "a" * 40, "cve_id": "CVE-2026-0001"}),
            (1, {"repo_name": "source-repo-b", "commit": "c" * 40, "cve_id": "CVE-2026-0002"}),
        ],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))

    def fake_ensure_vulnerability_profile(*, vuln_index, **kwargs):
        return object() if vuln_index == 0 else None

    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", fake_ensure_vulnerability_profile)
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_candidate])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "skipped")

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["total_scans"] == 1
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["incomplete_scans"] == 0
    assert summary["failed_profile_generation"] == 1
    assert summary["failed_scans"] == 0
    assert summary["coverage_complete_scans"] == 0
    assert summary["coverage_partial_scans"] == 0
    assert summary["coverage_empty_scans"] == 0
    assert summary["coverage_unknown_scans"] == 1
    assert (
        summary["total_scans"]
        == summary["successful_scans"]
        + summary["skipped_scans"]
        + summary["incomplete_scans"]
        + summary["failed_scans"]
    )
    assert summary["entries"][1]["status"] == "failed_profile_generation"


def test_main_returns_failure_when_incomplete_scan_exists(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    scan_output_dir = tmp_path / "scan-out"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=False,
        limit=None,
        verbose=False,
    )
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_candidate])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "incomplete")

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 0
    assert summary["incomplete_scans"] == 1
    assert summary["failed_scans"] == 0


def test_main_excludes_same_named_cross_root_target_when_same_repo_not_included(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    source_repos_root = tmp_path / "source-repos"
    target_repos_root = tmp_path / "target-repos"
    source_repos_root.mkdir()
    target_repos_root.mkdir()

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(source_repos_root),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
    )
    same_named_target = SimilarProfileCandidate(
        profile_ref=ProfileRef("source-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    other_target = SimilarProfileCandidate(
        profile_ref=ProfileRef("other-repo", "c" * 40, _mk_profile("other-target")),
        metrics=ProfileSimilarityMetrics(0.7, 0.7, 0.7, 0.7, 0.7, 0.7),
    )
    captured = {}

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {
            "source-repo": same_named_target.profile_ref,
            "other-repo": other_target.profile_ref,
        },
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())

    def fake_rank_similar_candidates(*, source_ref, candidate_refs, text_retriever):
        captured["candidate_repo_names"] = [ref.repo_name for ref in candidate_refs]
        return [other_target]

    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", fake_rank_similar_candidates)
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "ok")
    monkeypatch.setattr(
        batch_scanner_execution,
        "_load_saved_scan_quality",
        _complete_saved_scan_quality,
    )


    exit_code = batch_scanner.main()

    assert exit_code == 0
    assert captured["candidate_repo_names"] == ["other-repo"]


def test_main_reuses_target_profile_state_for_source_when_paths_match(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    shared_repos_root = tmp_path / "repos"
    shared_repos_root.mkdir()
    scan_output_dir = tmp_path / "scan-out"

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(shared_repos_root),
        target_repos_root=str(shared_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=True,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
    )
    source_key = ("source-repo", "a" * 40)
    other_target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    captured = {}

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": source_key[0], "commit": source_key[1], "cve_id": "CVE-2026-0001"})],
    )

    def fake_discover_latest_repo_refs(
        *,
        repos_root,
        repo_profiles_dir,
        llm_client,
        force_regenerate_profiles,
        software_cache,
        regenerated_software_keys,
    ):
        software_cache[source_key] = _mk_profile("cached-source")
        regenerated_software_keys.add(source_key)
        captured["target_cache_id"] = id(software_cache)
        captured["target_regenerated_id"] = id(regenerated_software_keys)
        return {
            source_key[0]: ProfileRef(source_key[0], source_key[1], software_cache[source_key]),
            "target-repo": other_target.profile_ref,
        }

    def fake_ensure_software_profile(
        *,
        repo_name,
        commit_hash,
        repos_root,
        repo_profiles_dir,
        llm_client,
        force_regenerate,
        reuse_existing_profiles_without_validation,
        cache,
        regenerated_keys,
    ):
        captured["source_cache_id"] = id(cache)
        captured["source_regenerated_id"] = id(regenerated_keys)
        captured["source_cache_prepopulated"] = source_key in cache
        captured["source_regenerated_prepopulated"] = source_key in regenerated_keys
        return cache[source_key]

    monkeypatch.setattr(batch_scanner, "_discover_latest_repo_refs", fake_discover_latest_repo_refs)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", fake_ensure_software_profile)
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [other_target])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "ok")
    monkeypatch.setattr(
        batch_scanner_execution,
        "_load_saved_scan_quality",
        _complete_saved_scan_quality,
    )


    exit_code = batch_scanner.main()

    assert exit_code == 0
    assert captured["source_cache_id"] == captured["target_cache_id"]
    assert captured["source_regenerated_id"] == captured["target_regenerated_id"]
    assert captured["source_cache_prepopulated"] is True
    assert captured["source_regenerated_prepopulated"] is True


def test_main_allows_missing_source_root_when_cached_profiles_are_reused(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    target_repos_root = tmp_path / "target-repos"
    target_repos_root.mkdir()
    profile_base_path = tmp_path / "profiles"
    source_profile_path = profile_base_path / "soft" / "source-repo" / ("a" * 40) / "software_profile.json"
    vuln_profile_path = profile_base_path / "vuln" / "source-repo" / "CVE-2026-0001" / "vulnerability_profile.json"
    source_profile_path.parent.mkdir(parents=True, exist_ok=True)
    vuln_profile_path.parent.mkdir(parents=True, exist_ok=True)
    source_profile_path.write_text("{}", encoding="utf-8")
    vuln_profile_path.write_text("{}", encoding="utf-8")

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "missing-source-repos"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(profile_base_path),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
    )
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", lambda **kwargs: [target_candidate])
    monkeypatch.setattr(batch_scanner_execution, "_run_target_scan", lambda **kwargs: "ok")
    monkeypatch.setattr(
        batch_scanner_execution,
        "_load_saved_scan_quality",
        _complete_saved_scan_quality,
    )


    exit_code = batch_scanner.main()

    assert exit_code == 0


def test_main_rejects_missing_source_root_when_cached_vulnerability_profile_is_missing(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    target_repos_root = tmp_path / "target-repos"
    target_repos_root.mkdir()
    profile_base_path = tmp_path / "profiles"
    source_profile_path = profile_base_path / "soft" / "source-repo" / ("a" * 40) / "software_profile.json"
    source_profile_path.parent.mkdir(parents=True, exist_ok=True)
    source_profile_path.write_text("{}", encoding="utf-8")

    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "missing-source-repos"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(profile_base_path),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(
        batch_scanner,
        "create_profile_llm_client",
        lambda provider, model: (_ for _ in ()).throw(AssertionError("should fail before creating llm clients")),
    )

    exit_code = batch_scanner.main()

    assert exit_code == 1


def test_parse_args_accepts_max_workers_and_scan_workers(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--max-workers",
            "4",
            "--scan-workers",
            "2",
        ],
    )

    args = batch_scanner.parse_args()

    assert args.max_workers == 4
    assert args.scan_workers == 2


def test_resolve_scan_workers_inherits_max_workers_when_not_set():
    args = Namespace(max_workers=4, scan_workers=None)
    assert batch_scanner._resolve_scan_workers(args) == 4


def test_resolve_scan_workers_uses_explicit_scan_workers():
    args = Namespace(max_workers=4, scan_workers=2)
    assert batch_scanner._resolve_scan_workers(args) == 2


def test_resolve_scan_workers_guarantees_at_least_one():
    args = Namespace(max_workers=0, scan_workers=0)
    assert batch_scanner._resolve_scan_workers(args) == 1


def test_validate_args_rejects_nonpositive_target_scan_timeout(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch_scanner.py",
            "--target-scan-timeout",
            "0",
        ],
    )
    args = batch_scanner.parse_args()

    assert batch_scanner._validate_args(args) is False


def test_parse_args_supports_scan_all_profiled_targets(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch_scanner.py",
            "--vuln-json",
            "vuln.json",
            "--source-repos-root",
            "source",
            "--target-repos-root",
            "target",
            "--profile-base-path",
            "profiles",
            "--scan-all-profiled-targets",
        ],
    )
    args = batch_scanner.parse_args()

    assert args.scan_all_profiled_targets is True


def test_build_scan_tasks_deduplicates_duplicate_target_candidates():
    target = ProfileRef(
        repo_name="target-repo",
        commit_hash="b" * 40,
        profile=_mk_profile("target"),
    )
    candidate = SimilarProfileCandidate(
        profile_ref=target,
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    tasks = batch_scanner._build_scan_tasks(
        cve_id="CVE-2026-0001",
        similar_targets=[candidate, candidate],
        vulnerability_profile=object(),
    )

    assert len(tasks) == 1
    assert tasks[0]["cve_id"] == "CVE-2026-0001"
    assert tasks[0]["target"].profile_ref.repo_name == "target-repo"


def test_run_target_scan_task_creates_independent_llm_client_per_worker(monkeypatch, tmp_path):
    task = {
        "task_id": "CVE-2026-0001:target-repo:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cve_id": "CVE-2026-0001",
        "vulnerability_profile": object(),
        "target": SimilarProfileCandidate(
            profile_ref=ProfileRef(
                repo_name="target-repo",
                commit_hash="b" * 40,
                profile=_mk_profile("target"),
            ),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    }
    batch_args = Namespace(
        llm_provider="deepseek",
        llm_name=None,
        scan_output_dir=tmp_path / "scan-out",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
    )
    created_clients = []

    def fake_create_llm_client(config):
        client = object()
        created_clients.append(client)
        return client

    used_clients = []

    def fake_run_target_scan(**kwargs):
        used_clients.append(kwargs["llm_client"])
        output_dir = batch_scanner.agent_scanner.resolve_output_dir(
            cve_id=kwargs["cve_id"],
            target_repo=kwargs["target"].profile_ref.repo_name,
            target_commit=kwargs["target"].profile_ref.commit_hash,
            output_base=str(kwargs["batch_args"].scan_output_dir),
        )
        marker_sha256, _fingerprint = _write_terminal_scan_output(
            output_dir,
            reference_id=kwargs["cve_id"],
            repo_name=kwargs["target"].profile_ref.repo_name,
            commit_hash=kwargs["target"].profile_ref.commit_hash,
        )
        kwargs["terminal_binding_out"][
            "scan_output_commit_sha256"
        ] = marker_sha256
        return "ok"

    monkeypatch.setattr(batch_scanner, "create_llm_client", fake_create_llm_client)
    monkeypatch.setattr(batch_scanner, "_run_target_scan", fake_run_target_scan)

    manager = batch_scanner.RepoPathLockManager()
    first = batch_scanner._run_target_scan_task(
        task=task,
        batch_args=batch_args,
        target_repos_root=tmp_path,
        repo_lock_manager=manager,
    )
    second = batch_scanner._run_target_scan_task(
        task=task,
        batch_args=batch_args,
        target_repos_root=tmp_path,
        repo_lock_manager=manager,
    )

    assert created_clients[0] is used_clients[0]
    assert created_clients[1] is used_clients[1]
    assert len(created_clients) == 2
    assert first["status"] == "ok"
    assert second["status"] == "ok"


def test_run_target_scan_task_includes_saved_coverage_metadata(monkeypatch, tmp_path):
    task = {
        "task_id": "CVE-2026-0001:target-repo:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cve_id": "CVE-2026-0001",
        "vulnerability_profile": object(),
        "target": SimilarProfileCandidate(
            profile_ref=ProfileRef(
                repo_name="target-repo",
                commit_hash="b" * 40,
                profile=_mk_profile("target"),
            ),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    }
    batch_args = Namespace(
        llm_provider="deepseek",
        llm_name=None,
        scan_output_dir=tmp_path / "scan-out",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
    )

    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())

    def fake_run_target_scan(**kwargs):
        output_dir = batch_scanner.agent_scanner.resolve_output_dir(
            cve_id=kwargs["cve_id"],
            target_repo=kwargs["target"].profile_ref.repo_name,
            target_commit=kwargs["target"].profile_ref.commit_hash,
            output_base=str(kwargs["batch_args"].scan_output_dir),
        )
        marker_sha256, _fingerprint = _write_terminal_scan_output(
            output_dir,
            reference_id=kwargs["cve_id"],
            repo_name=kwargs["target"].profile_ref.repo_name,
            commit_hash=kwargs["target"].profile_ref.commit_hash,
        )
        kwargs["terminal_binding_out"][
            "scan_output_commit_sha256"
        ] = marker_sha256
        return "skipped"

    monkeypatch.setattr(batch_scanner, "_run_target_scan", fake_run_target_scan)

    result = batch_scanner._run_target_scan_task(
        task=task,
        batch_args=batch_args,
        target_repos_root=tmp_path,
        repo_lock_manager=batch_scanner.RepoPathLockManager(),
    )

    assert result["status"] == "skipped"
    assert result["coverage_status"] == "complete"
    assert result["critical_scope_present"] is True
    assert result["critical_complete"] is True
    assert result["critical_scope_total_files"] == 2
    assert result["critical_scope_completed_files"] == 2
    assert result["scan_progress"] == {
        "total_files": 2,
        "completed": 2,
        "pending": 0,
        "findings": 0,
    }
    assert result["started_at"]
    assert result["finished_at"]
    assert result["duration_seconds"] >= 0.0


def test_run_target_scan_task_records_failure_reason(monkeypatch, tmp_path):
    task = {
        "task_id": "CVE-2026-0001:target-repo:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cve_id": "CVE-2026-0001",
        "vulnerability_profile": object(),
        "target": SimilarProfileCandidate(
            profile_ref=ProfileRef(
                repo_name="target-repo",
                commit_hash="b" * 40,
                profile=_mk_profile("target"),
            ),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    }
    batch_args = Namespace(
        llm_provider="deepseek",
        llm_name=None,
        scan_output_dir=tmp_path / "scan-out",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
    )
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())

    def failing_scan(**kwargs):
        _ = kwargs
        raise RuntimeError("synthetic scan failure")

    monkeypatch.setattr(batch_scanner, "_run_target_scan", failing_scan)

    result = batch_scanner._run_target_scan_task(
        task=task,
        batch_args=batch_args,
        target_repos_root=tmp_path,
        repo_lock_manager=batch_scanner.RepoPathLockManager(),
    )

    assert result["status"] == "failed"
    assert result["failure_reason"] == "synthetic scan failure"


def test_run_target_scan_task_times_out_slow_worker(monkeypatch, tmp_path):
    task = {
        "task_id": "CVE-2026-0001:target-repo:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "cve_id": "CVE-2026-0001",
        "vulnerability_profile": object(),
        "target": SimilarProfileCandidate(
            profile_ref=ProfileRef(
                repo_name="target-repo",
                commit_hash="b" * 40,
                profile=_mk_profile("target"),
            ),
            metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        ),
    }
    batch_args = Namespace(
        llm_provider="deepseek",
        llm_name=None,
        scan_output_dir=tmp_path / "scan-out",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        target_scan_timeout=1,
    )
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())

    def slow_scan(**kwargs):
        _ = kwargs
        time.sleep(20)
        return "ok"

    monkeypatch.setattr(batch_scanner, "_run_target_scan", slow_scan)

    started_at = time.monotonic()
    result = batch_scanner._run_target_scan_task(
        task=task,
        batch_args=batch_args,
        target_repos_root=tmp_path,
        repo_lock_manager=batch_scanner.RepoPathLockManager(),
    )

    assert time.monotonic() - started_at < 8
    assert result["status"] == "incomplete"
    assert "timed out" in result["failure_reason"]


def test_run_target_scan_task_preserves_skip_any_as_partial(monkeypatch, tmp_path):
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            repo_name="target-repo",
            commit_hash="b" * 40,
            profile=_mk_profile("target"),
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    batch_args = Namespace(
        llm_provider="deepseek",
        llm_name=None,
        scan_output_dir=tmp_path / "scan-out",
        skip_any_existing_scan_result=True,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "_run_target_scan",
        lambda **_kwargs: "skipped",
    )

    result = batch_scanner_execution._run_target_scan_task_inner(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        target=target,
    )

    assert result["status"] == "skipped"
    assert result["coverage_status"] == "unknown"
    assert result["headline_eligible"] is False
    assert result["scan_output_commit_sha256"] is None


def test_run_target_scan_task_waits_for_child_queue_result(monkeypatch):
    observed = {}
    expected_result = {"status": "ok"}

    class FakeQueue:
        def __init__(self, maxsize):
            observed["queue_maxsize"] = maxsize

        def get(self, *, timeout):
            observed["queue_timeout"] = timeout
            return {"ok": True, "result": expected_result}

        def close(self):
            observed["queue_closed"] = True

        def join_thread(self):
            observed["queue_thread_joined"] = True

    class FakeProcess:
        exitcode = 0

        def __init__(self, *, target, kwargs):
            observed["process_target"] = target
            observed["process_kwargs"] = kwargs

        def start(self):
            observed["started"] = True

        def join(self, *, timeout):
            observed["join_timeout"] = timeout

        def is_alive(self):
            return False

    monkeypatch.setattr(
        batch_scanner_execution.multiprocessing,
        "Queue",
        FakeQueue,
    )
    monkeypatch.setattr(
        batch_scanner_execution.multiprocessing,
        "Process",
        FakeProcess,
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            repo_name="target-repo",
            commit_hash="b" * 40,
            profile=_mk_profile("target"),
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    result = batch_scanner_execution._run_target_scan_task(
        batch_args=Namespace(target_scan_timeout=3),
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        target=target,
    )

    assert result is expected_result
    assert observed["queue_maxsize"] == 1
    assert 0 < observed["queue_timeout"] <= 0.1
    assert observed["join_timeout"] == 1.0
    assert observed["queue_closed"] is True
    assert observed["queue_thread_joined"] is True


def _emit_large_scan_task_result(result_queue, kwargs):
    del kwargs
    result_queue.put(
        {
            "ok": True,
            "result": {
                "status": "ok",
                "large_provenance": "x" * (2 * 1024 * 1024),
            },
        }
    )


def test_run_target_scan_task_drains_large_child_result_before_join(
    monkeypatch,
):
    monkeypatch.setattr(
        batch_scanner_execution,
        "_target_scan_process_entry",
        _emit_large_scan_task_result,
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            repo_name="target-repo",
            commit_hash="b" * 40,
            profile=_mk_profile("target"),
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    result = batch_scanner_execution._run_target_scan_task(
        batch_args=Namespace(target_scan_timeout=5),
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        target=target,
    )

    assert result["status"] == "ok"
    assert len(result["large_provenance"]) == 2 * 1024 * 1024


def test_main_uses_jobs_when_scan_worker_flags_are_unset(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text("[]", encoding="utf-8")
    target_repos_root = tmp_path / "target-repos"
    target_repos_root.mkdir()
    scan_output_dir = tmp_path / "scan-out"
    captured = {}
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "source-repos"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(tmp_path / "profiles"),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(scan_output_dir),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
        jobs=4,
        max_workers=1,
        scan_workers=None,
    )

    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(batch_scanner, "_ensure_source_inputs_available", lambda **kwargs: True)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_select_similar_targets", lambda **kwargs: ([target_candidate], False))

    def fake_run_thread_pool_tasks(*, tasks, worker_fn, max_workers):
        del tasks, worker_fn
        captured["max_workers"] = max_workers
        return [
            Namespace(
                status="success",
                payload={
                    "repo_name": "target-repo",
                    "commit_hash": "b" * 40,
                    "overall_similarity": 0.8,
                    "status": "ok",
                    "coverage_status": "complete",
                    "scan_output_commit_sha256": "f" * 64,
                    "headline_eligible": True,
                },
                error_message="",
            )
        ]

    monkeypatch.setattr(batch_scanner, "run_thread_pool_tasks", fake_run_thread_pool_tasks)

    exit_code = batch_scanner.main()

    assert exit_code == 0
    assert captured["max_workers"] == 4


def test_main_summary_counts_are_aggregated_after_scan_task_dedup(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text(
        json.dumps([{"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"}]),
        encoding="utf-8",
    )
    target_repos_root = tmp_path / "targets"
    target_repos_root.mkdir()
    profile_base_path = tmp_path / "profiles"
    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "sources"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(profile_base_path),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
        max_workers=3,
        scan_workers=None,
    )
    duplicated_target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setitem(batch_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(batch_scanner, "_load_vuln_entries", lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})])
    monkeypatch.setattr(batch_scanner, "_ensure_source_inputs_available", lambda **kwargs: True)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_discover_latest_repo_refs", lambda **kwargs: {"target-repo": duplicated_target.profile_ref})
    monkeypatch.setattr(
        batch_scanner,
        "_select_similar_targets",
        lambda **kwargs: ([duplicated_target, duplicated_target], False),
    )
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "ok")
    monkeypatch.setattr(
        batch_scanner_execution,
        "_load_saved_scan_quality",
        _complete_saved_scan_quality,
    )


    exit_code = batch_scanner.main()
    assert exit_code == 0

    summary_files = sorted((tmp_path / "scan-out").glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))

    assert summary["total_scans"] == 1
    assert summary["successful_scans"] == 1
    assert summary["failed_scans"] == 0
    assert summary["entries"][0]["scan_results"][0]["status"] == "ok"


def test_main_scan_all_profiled_targets_bypasses_similarity_ranking(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text(
        json.dumps([{"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"}]),
        encoding="utf-8",
    )
    target_repos_root = tmp_path / "targets"
    target_repos_root.mkdir()
    profile_base_path = tmp_path / "profiles"
    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "sources"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(profile_base_path),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        scan_all_profiled_targets=True,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
        max_workers=2,
        scan_workers=2,
        jobs=2,
        run_id="run-1",
        shared_public_memory_dir=str(tmp_path / "scan-out" / "_runs" / "run-1" / "shared-public-memory"),
    )
    target_one = ProfileRef("target-one", "b" * 40, _mk_profile("target-one"))
    target_two = ProfileRef("target-two", "c" * 40, _mk_profile("target-two"))

    monkeypatch.setitem(batch_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    build_calls = []
    monkeypatch.setattr(
        batch_scanner,
        "build_text_retriever",
        lambda model_name, device: build_calls.append((model_name, device)) or object(),
    )
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(batch_scanner, "_ensure_source_inputs_available", lambda **kwargs: True)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(
        batch_scanner,
        "_discover_existing_profiled_repo_refs",
        lambda **kwargs: {
            "source-repo": ProfileRef("source-repo", "a" * 40, _mk_profile("same")),
            "target-one": target_one,
            "target-two": target_two,
        },
    )

    def _unexpected_rank(**kwargs):
        raise AssertionError("similarity ranking should not run in all-profile mode")

    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", _unexpected_rank)
    monkeypatch.setattr(
        batch_scanner,
        "run_thread_pool_tasks",
        lambda **kwargs: [
            Namespace(
                status="success",
                payload={
                    "repo_name": task["target"].profile_ref.repo_name,
                    "commit_hash": task["target"].profile_ref.commit_hash,
                    "overall_similarity": (
                        task["target"].metrics.overall_sim
                        if task["target"].metrics is not None
                        else None
                    ),
                    "similarity_computed": task["target"].metrics is not None,
                    "status": "ok",
                    "coverage_status": "complete",
                    "scan_output_commit_sha256": hashlib.sha256(
                        task["task_id"].encode("utf-8")
                    ).hexdigest(),

                    "headline_eligible": True,
                },
                error_message="",
            )
            for task in kwargs["tasks"]
        ],
    )

    assert batch_scanner.main() == 0
    assert build_calls == []

    summary_files = sorted((tmp_path / "scan-out").glob("batch-summary-*.json"))
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))

    assert summary["entries"][0]["selection_mode"] == "all_profiled"
    selected_targets = summary["entries"][0]["selected_targets"]
    assert [target["repo_name"] for target in selected_targets] == ["target-one", "target-two"]
    assert all(target["similarity_computed"] is False for target in selected_targets)
    assert all(target["metrics"] is None for target in selected_targets)
    assert all(result["overall_similarity"] is None for result in summary["entries"][0]["scan_results"])
    assert all(result["similarity_computed"] is False for result in summary["entries"][0]["scan_results"])
    assert summary["total_scans"] == 2


def test_discover_existing_profiled_repo_refs_tolerates_profile_removed_during_latest_selection(monkeypatch, tmp_path):
    repos_root = tmp_path / "repos"
    repo_profiles_dir = tmp_path / "profiles"
    (repos_root / "target-one").mkdir(parents=True)

    profile_path = repo_profiles_dir / "target-one" / ("a" * 40) / "software_profile.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(json.dumps({"marker": "x"}), encoding="utf-8")

    ref = ProfileRef(
        repo_name="target-one",
        commit_hash="a" * 40,
        profile=_mk_profile("target-one"),
        profile_path=profile_path,
    )

    monkeypatch.setattr(batch_scanner, "load_all_software_profiles", lambda _path: [ref])

    class _MissingThenGone:
        def __init__(self):
            self.exists_calls = 0

        def exists(self):
            self.exists_calls += 1
            return True

        def stat(self):
            raise FileNotFoundError("profile disappeared")

    object.__setattr__(ref, "profile_path", _MissingThenGone())

    refs = batch_scanner._discover_existing_profiled_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
    )

    assert set(refs.keys()) == {"target-one"}
    assert refs["target-one"].commit_hash == "a" * 40


def test_discover_existing_profiled_repo_refs_reloads_repo_when_initial_snapshot_misses_profile(
    monkeypatch,
    tmp_path,
):
    repos_root = tmp_path / "repos"
    repo_profiles_dir = tmp_path / "profiles"
    (repos_root / "target-one").mkdir(parents=True)
    (repo_profiles_dir / "target-one" / ("a" * 40)).mkdir(parents=True)

    monkeypatch.setattr(batch_scanner, "load_all_software_profiles", lambda _path: [])
    monkeypatch.setattr(batch_scanner, "resolve_profile_commit", lambda base_dir, repo_name: "a" * 40)
    monkeypatch.setattr(batch_scanner, "load_software_profile", lambda repo_name, commit_hash, base_dir=None: _mk_profile(repo_name))

    refs = batch_scanner._discover_existing_profiled_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
    )

    assert set(refs.keys()) == {"target-one"}
    assert refs["target-one"].commit_hash == "a" * 40


def test_discover_existing_profiled_repo_refs_reloads_selected_profile_after_latest_pick(
    monkeypatch,
    tmp_path,
):
    repos_root = tmp_path / "repos"
    repo_profiles_dir = tmp_path / "profiles"
    (repos_root / "target-one").mkdir(parents=True)

    profile_path = repo_profiles_dir / "target-one" / ("a" * 40) / "software_profile.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text("{}", encoding="utf-8")

    stale_ref = ProfileRef(
        repo_name="target-one",
        commit_hash="a" * 40,
        profile=_mk_profile("stale-profile"),
        profile_path=profile_path,
    )

    monkeypatch.setattr(batch_scanner, "load_all_software_profiles", lambda _path: [stale_ref])
    monkeypatch.setattr(batch_scanner, "load_software_profile", lambda repo_name, commit_hash, base_dir=None: _mk_profile("fresh-profile"))

    refs = batch_scanner._discover_existing_profiled_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
    )

    assert set(refs.keys()) == {"target-one"}
    assert refs["target-one"].profile.name == "fresh-profile"


def test_discover_existing_profiled_repo_refs_refreshes_repo_when_newer_profile_appears_after_snapshot(
    monkeypatch,
    tmp_path,
):
    repos_root = tmp_path / "repos"
    repo_profiles_dir = tmp_path / "profiles"
    (repos_root / "target-one").mkdir(parents=True)

    old_path = repo_profiles_dir / "target-one" / ("a" * 40) / "software_profile.json"
    new_path = repo_profiles_dir / "target-one" / ("b" * 40) / "software_profile.json"
    old_path.parent.mkdir(parents=True)
    new_path.parent.mkdir(parents=True)
    old_path.write_text("{}", encoding="utf-8")
    new_path.write_text("{}", encoding="utf-8")

    stale_ref = ProfileRef(
        repo_name="target-one",
        commit_hash="a" * 40,
        profile=_mk_profile("stale-profile"),
        profile_path=old_path,
    )

    monkeypatch.setattr(batch_scanner, "load_all_software_profiles", lambda _path: [stale_ref])
    monkeypatch.setattr(batch_scanner, "resolve_profile_commit", lambda base_dir, repo_name: "b" * 40)
    monkeypatch.setattr(
        batch_scanner,
        "load_software_profile",
        lambda repo_name, commit_hash, base_dir=None: _mk_profile(f"reloaded-{commit_hash[:1]}"),
    )

    refs = batch_scanner._discover_existing_profiled_repo_refs(
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
    )

    assert set(refs.keys()) == {"target-one"}
    assert refs["target-one"].commit_hash == "b" * 40
    assert refs["target-one"].profile.name == "reloaded-b"


def test_main_summary_preserves_per_target_timing_and_coverage_metadata(monkeypatch, tmp_path):
    vuln_json = tmp_path / "vuln.json"
    vuln_json.write_text(
        json.dumps([{"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"}]),
        encoding="utf-8",
    )
    target_repos_root = tmp_path / "targets"
    target_repos_root.mkdir()
    profile_base_path = tmp_path / "profiles"
    args = Namespace(
        vuln_json=str(vuln_json),
        source_repos_root=str(tmp_path / "sources"),
        target_repos_root=str(target_repos_root),
        profile_base_path=str(profile_base_path),
        source_soft_profiles_dir="soft",
        target_soft_profiles_dir="soft-nvidia",
        vuln_profiles_dir="vuln",
        scan_output_dir=str(tmp_path / "scan-out"),
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=5,
        include_same_repo=False,
        similarity_model_name="stub-model",
        similarity_device="cpu",
        llm_provider="deepseek",
        llm_name=None,
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        force_regenerate_profiles=False,
        skip_existing_scans=True,
        limit=None,
        verbose=False,
        max_workers=1,
        scan_workers=1,
        jobs=1,
        run_id="run-1",
        shared_public_memory_dir=str(tmp_path / "scan-out" / "_runs" / "run-1" / "shared-public-memory"),
    )
    target_candidate = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "b" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    monkeypatch.setitem(batch_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda model_name, device: object())
    monkeypatch.setattr(
        batch_scanner,
        "_load_vuln_entries",
        lambda vuln_json, limit=None: [(0, {"repo_name": "source-repo", "commit": "a" * 40, "cve_id": "CVE-2026-0001"})],
    )
    monkeypatch.setattr(batch_scanner, "_ensure_source_inputs_available", lambda **kwargs: True)
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    monkeypatch.setattr(
        batch_scanner,
        "_discover_latest_repo_refs",
        lambda **kwargs: {"target-repo": target_candidate.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_select_similar_targets", lambda **kwargs: ([target_candidate], False))
    monkeypatch.setattr(
        batch_scanner,
        "run_thread_pool_tasks",
        lambda **kwargs: [
            Namespace(
                status="success",
                payload={
                    "repo_name": "target-repo",
                    "commit_hash": "b" * 40,
                    "overall_similarity": 0.8,
                    "status": "ok",
                    "coverage_status": "complete",
                    "scan_output_commit_sha256": "f" * 64,
                    "headline_eligible": True,
                    "critical_scope_present": True,
                    "critical_complete": True,
                    "critical_scope_total_files": 3,
                    "critical_scope_completed_files": 3,
                    "scan_progress": {"completed": 3, "pending": 0},
                    "started_at": "2026-03-26T10:00:00",
                    "finished_at": "2026-03-26T10:00:05",
                    "duration_seconds": 5.0,
                },
                error_message="",
            )
        ],
    )

    assert batch_scanner.main() == 0

    summary_files = sorted((tmp_path / "scan-out").glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    scan_result = summary["entries"][0]["scan_results"][0]

    assert scan_result["critical_scope_present"] is True
    assert scan_result["critical_complete"] is True
    assert scan_result["critical_scope_total_files"] == 3
    assert scan_result["critical_scope_completed_files"] == 3
    assert scan_result["scan_progress"] == {"completed": 3, "pending": 0}
    assert scan_result["started_at"] == "2026-03-26T10:00:00"
    assert scan_result["finished_at"] == "2026-03-26T10:00:05"
    assert scan_result["duration_seconds"] == 5.0


def _ranked_selection_candidates(scores):
    return [
        SimilarProfileCandidate(
            profile_ref=ProfileRef(
                f"repo-{index}",
                str(index) * 40,
                _mk_profile(f"repo-{index}"),
            ),
            metrics=ProfileSimilarityMetrics(score, score, score, score, score, score),
        )
        for index, score in enumerate(scores)
    ]


@pytest.mark.parametrize("passed_count", [0, 2])
def test_select_similar_targets_sparse_hits_use_top_five(passed_count):
    scores = [0.9] * passed_count + [0.6] * (7 - passed_count)
    ranked = _ranked_selection_candidates(scores)

    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=5,
        min_threshold_hits=3,
    )

    assert fallback_used is True
    assert [item.profile_ref.repo_name for item in selected] == [
        f"repo-{index}" for index in range(5)
    ]


def test_select_similar_targets_exactly_three_hits_keep_threshold_set():
    ranked = _ranked_selection_candidates([0.9, 0.8, 0.7, 0.6, 0.5, 0.4])

    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=5,
        min_threshold_hits=3,
    )

    assert fallback_used is False
    assert [item.profile_ref.repo_name for item in selected] == [
        "repo-0", "repo-1", "repo-2"
    ]


def test_select_similar_targets_more_than_five_hits_keep_all_threshold_hits():
    ranked = _ranked_selection_candidates([0.9] * 7)

    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=None,
        fallback_top_n=5,
        min_threshold_hits=3,
    )

    assert fallback_used is False
    assert len(selected) == 7


def test_select_similar_targets_max_targets_is_hard_cap():
    ranked = _ranked_selection_candidates([0.9] * 7)

    selected, fallback_used = batch_scanner._select_similar_targets(
        ranked_candidates=ranked,
        similarity_threshold=0.7,
        max_targets=4,
        fallback_top_n=5,
        min_threshold_hits=3,
    )

    assert fallback_used is False
    assert [item.profile_ref.repo_name for item in selected] == [
        "repo-0", "repo-1", "repo-2", "repo-3"
    ]


def test_parse_args_defaults_split_threshold_and_fallback_knobs(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["batch-scanner"])

    args = batch_scanner.parse_args()

    assert args.min_threshold_hits == 3
    assert args.fallback_top_n == 5
    assert args.evaluation_mode is False
    assert args.ablate_repo_semantics is False
    assert args.ablate_candidate_priority is False
    assert args.ablate_memory is False
    assert args.ablate_verifier is False


def test_parse_args_accepts_evaluation_alias_and_all_ablation_switches(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--benchmark-mode",
            "--ablate-repo-semantics",
            "--ablate-repo-priority",
            "--ablate-memory",
            "--ablate-verifier",
            "--min-threshold-hits",
            "4",
            "--fallback-top-n",
            "6",
        ],
    )

    args = batch_scanner.parse_args()

    assert args.evaluation_mode is True
    assert args.ablate_repo_semantics is True
    assert args.ablate_candidate_priority is True
    assert args.ablate_memory is True
    assert args.ablate_verifier is True
    assert args.min_threshold_hits == 4
    assert args.fallback_top_n == 6

def test_standalone_run_provenance_overrides_stale_embedded_complete_state(tmp_path):
    output_dir = tmp_path / "scan-out"
    output_dir.mkdir()
    embedded = {
        "execution": {"status": "complete"},
        "coverage": {"coverage_status": "complete"},
        "scan_fingerprint": {"hash": "stale-complete"},
    }
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps({
            "coverage_status": "complete",
            "run_provenance": embedded,
            "scan_fingerprint": {"hash": "stale-complete"},
        }),
        encoding="utf-8",
    )
    (output_dir / "run_provenance.json").write_text(
        json.dumps({
            "execution": {
                "status": "failed", "termination": "exception",
                "failure_reason": "new attempt failed",
            },
            "coverage": None,
        }),
        encoding="utf-8",
    )
    (output_dir / "scan_memory.json").write_text(
        json.dumps({
            "file_status": {"a.py": "completed", "b.py": "pending"},
            "module_priorities": {"m": 1},
            "file_to_module": {"a.py": "m", "b.py": "m"},
            "findings": [],
        }),
        encoding="utf-8",
    )
    saved = batch_scanner_execution._load_saved_scan_quality(output_dir)
    assert saved["run_provenance_source"] == "legacy_uncommitted"
    assert saved["run_status"] == "failed"
    assert saved["terminal_commit_valid"] is False
    assert saved["coverage_status"] == "partial"
    assert saved["coverage_source"] == "scan_memory"
    assert saved["scan_fingerprint_hash"] == ""


def test_timeout_recovers_scan_memory_as_partial_and_finalizes_standalone_provenance(tmp_path):
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out", llm_provider="lab", llm_name="model",
        max_iterations_cap=3, evaluation_mode=True,
    )
    output_dir = batch_scanner.agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001", target_repo="target-repo",
        target_commit="a" * 40, output_base=str(batch_args.scan_output_dir),
    )
    output_dir.mkdir(parents=True)
    (output_dir / "scan_memory.json").write_text(
        json.dumps({
            "file_status": {"a.py": "completed", "b.py": "pending"},
            "module_priorities": {"m": 1},
            "file_to_module": {"a.py": "m", "b.py": "m"},
            "findings": [],
        }),
        encoding="utf-8",
    )
    result = batch_scanner_execution._build_timed_out_scan_task_result(
        started_at=datetime.now() - timedelta(seconds=2),
        batch_args=batch_args, cve_id="CVE-2026-0001", target=target,
        timeout_seconds=1,
    )
    assert result["status"] == "incomplete"
    assert result["coverage_status"] == "partial"
    assert result["termination"] == "timeout"
    assert result["run_provenance"]["execution"]["status"] == "failed"
    persisted = json.loads((output_dir / "run_failure.json").read_text(encoding="utf-8"))
    assert persisted["execution"]["termination"] == "timeout"
    assert persisted["coverage"]["coverage_status"] == "partial"
    assert not (output_dir / "run_provenance.json").exists()
    assert not (output_dir / "scan_output_commit.json").exists()

def test_run_target_scan_keeps_authoritative_failed_status_with_partial_coverage(monkeypatch, tmp_path):
    def fake_run_single_target_scan(**kwargs):
        output_dir = batch_scanner.agent_scanner.resolve_output_dir(
            cve_id=kwargs["cve_id"], target_repo=kwargs["target"].repo_name,
            target_commit=kwargs["target"].commit_hash,
            output_base=str(kwargs["output_base"]),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "agentic_vuln_findings.json").write_text(
            json.dumps({"coverage_status": "partial"}), encoding="utf-8"
        )
        batch_scanner.agent_scanner._write_run_failure(  # pylint: disable=protected-access
            output_dir,
            {
                "execution": {"status": "failed", "termination": "runtime_failure"},
                "coverage": {"coverage_status": "partial"},
            },
        )
        return False
    monkeypatch.setattr(
        batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan
    )
    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out", target_repos_root=tmp_path / "repos",
        max_iterations_cap=3, disable_critical_stop=False, critical_stop_mode="min",
        verbose=False, skip_existing_scans=False, profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    status = batch_scanner._run_target_scan(
        batch_args=batch_args, cve_id="CVE-2026-0001",
        vulnerability_profile=object(), llm_client=object(), target=target,
    )
    assert status == "failed"
    output_dir = batch_scanner.agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001", target_repo="target-repo",
        target_commit="a" * 40, output_base=str(batch_args.scan_output_dir),
    )
    saved = batch_scanner_execution._load_saved_scan_quality(output_dir)
    assert saved["run_status"] == "failed"
    assert saved["coverage_status"] == "partial"

def _terminal_contract_batch_args(tmp_path, **overrides):
    values = {
        "vuln_json": str(tmp_path / "vuln.json"),
        "source_repos_root": str(tmp_path / "sources"),
        "target_repos_root": str(tmp_path / "targets"),
        "profile_base_path": str(tmp_path / "profiles"),
        "source_soft_profiles_dir": "soft",
        "target_soft_profiles_dir": "soft-target",
        "vuln_profiles_dir": "vuln",
        "scan_output_dir": str(tmp_path / "scan-out"),
        "similarity_threshold": 0.7, "max_targets": 5, "fallback_top_n": 5,
        "include_same_repo": False, "similarity_model_name": "model",
        "similarity_device": "cpu", "llm_provider": "lab", "llm_name": None,
        "max_iterations_cap": 3, "disable_critical_stop": False,
        "critical_stop_mode": "max", "force_regenerate_profiles": False,
        "skip_existing_scans": True, "limit": None, "verbose": False,
        "evaluation_mode": False, "ablate_repo_semantics": False,
        "ablate_reference_semantics": False, "ablate_candidate_priority": False,
        "ablate_memory": False, "ablate_verifier": False,
    }
    values.update(overrides)
    return Namespace(**values)


def test_unanchored_resealed_terminal_is_not_headline_eligible(tmp_path):
    output_dir = tmp_path / "scan-out"
    original_hash, _fingerprint = _write_terminal_scan_output(output_dir)
    assert _reseal_terminal_output_with_finding(output_dir) != original_hash

    anchored = batch_scanner_execution._load_saved_scan_quality(
        output_dir,
        expected_commit_sha256=original_hash,
    )
    unanchored = batch_scanner_execution._load_saved_scan_quality(
        output_dir,
        allow_unanchored_terminal=True,
    )

    assert anchored["terminal_commit_valid"] is False
    assert unanchored["terminal_commit_valid"] is False
    assert unanchored["headline_eligible"] is False
    assert "external" in unanchored["scan_output_commit_error"]


def test_post_run_uses_scanner_returned_binding_not_directory_self_anchor(
    monkeypatch, tmp_path
):
    batch_args = _terminal_contract_batch_args(
        tmp_path,
        skip_existing_scans=False,
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            "target-repo", "a" * 40, _mk_profile("target-repo")
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    def fake_run_single_target_scan(**kwargs):
        receipt = _write_terminal_scan_for_kwargs(kwargs)
        output_dir = batch_scanner.agent_scanner.resolve_output_dir(
            cve_id=kwargs["cve_id"],
            target_repo=kwargs["target"].repo_name,
            target_commit=kwargs["target"].commit_hash,
            output_base=str(kwargs["output_base"]),
        )
        _reseal_terminal_output_with_finding(output_dir)
        return receipt

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        fake_run_single_target_scan,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "scan_output_commit_sha256",
        lambda _output_dir: pytest.fail("batch must not self-anchor"),
        raising=False,
    )

    assert batch_scanner._run_target_scan(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    ) == "failed"


def test_main_zero_scan_batch_is_failed_with_consistent_reason(monkeypatch, tmp_path):
    (tmp_path / "vuln.json").write_text("[]", encoding="utf-8")
    (tmp_path / "sources").mkdir()
    (tmp_path / "targets").mkdir()
    args = _terminal_contract_batch_args(tmp_path)
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    monkeypatch.setattr(batch_scanner, "build_text_retriever", lambda *args, **kwargs: object())
    monkeypatch.setattr(batch_scanner, "_discover_latest_repo_refs", lambda **kwargs: {})
    monkeypatch.setattr(batch_scanner, "_load_vuln_entries", lambda *args, **kwargs: [])
    assert batch_scanner.main() == 1
    summary_path = next((tmp_path / "scan-out").glob("batch-summary-*.json"))
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_scans"] == 0
    assert summary["status"] == "failed"
    assert summary["partial"] is False
    assert summary["failure_reason"] == "no vulnerability entries; no target scans were scheduled"


def test_main_rejects_evaluation_batch_before_any_setup(
    monkeypatch, tmp_path
):
    args = _terminal_contract_batch_args(
        tmp_path,
        evaluation_mode=True,
        skip_existing_scans=False,
    )
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(
        batch_scanner,
        "_resolve_batch_scan_paths",
        lambda *_args, **_kwargs: pytest.fail(
            "evaluation must be rejected before path/task/model setup"
        ),
    )

    assert batch_scanner.main() == 1

def test_main_resets_embedding_provenance_for_each_vulnerability(monkeypatch, tmp_path):
    (tmp_path / "vuln.json").write_text("[]", encoding="utf-8")
    (tmp_path / "sources").mkdir()
    (tmp_path / "targets").mkdir()
    args = _terminal_contract_batch_args(tmp_path)
    entries = [
        (0, {"repo_name": "source-a", "commit": "a" * 40, "cve_id": "CVE-2026-0001"}),
        (1, {"repo_name": "source-b", "commit": "b" * 40, "cve_id": "CVE-2026-0002"}),
    ]
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target", "c" * 40, _mk_profile("target")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(batch_scanner, "_load_vuln_entries", lambda *args, **kwargs: entries)
    monkeypatch.setattr(batch_scanner, "_ensure_source_inputs_available", lambda **kwargs: True)
    monkeypatch.setattr(batch_scanner, "create_profile_llm_client", lambda provider, model: object())
    def fake_build_retriever(*args, **kwargs):
        kwargs["provenance"].update({"setup_marker": "base"})
        return object()
    monkeypatch.setattr(batch_scanner, "build_text_retriever", fake_build_retriever)
    monkeypatch.setattr(
        batch_scanner, "_discover_latest_repo_refs",
        lambda **kwargs: {"target": target.profile_ref},
    )
    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: _mk_profile("source"))
    monkeypatch.setattr(batch_scanner, "_ensure_vulnerability_profile", lambda **kwargs: object())
    snapshots = []
    def fake_rank(**kwargs):
        provenance = kwargs["embedding_provenance"]
        snapshots.append(dict(provenance))
        provenance["per_vulnerability_marker"] = len(snapshots)
        return [target]
    monkeypatch.setattr(batch_scanner, "_rank_similar_candidates", fake_rank)
    def fake_pool(*, tasks, worker_fn, max_workers):
        _ = worker_fn, max_workers
        task_target = tasks[0]["target"]
        return [Namespace(
            status="success", error_message="",
            payload={
                "repo_name": task_target.profile_ref.repo_name,
                "commit_hash": task_target.profile_ref.commit_hash,
                "overall_similarity": 0.8, "status": "ok",
                "coverage_status": "complete",
                "scan_output_commit_sha256": hashlib.sha256(
                    tasks[0]["task_id"].encode("utf-8")
                ).hexdigest(),
                "headline_eligible": True,
            },
        )]
    monkeypatch.setattr(batch_scanner, "run_thread_pool_tasks", fake_pool)
    assert batch_scanner.main() == 0
    assert snapshots == [{"setup_marker": "base"}, {"setup_marker": "base"}]


def _write_frozen_batch_schedule_fixture(root: Path):
    benchmark_constant = "batch-schedule-fixture-v1"
    rows = []
    target_profiles = {}
    for index in range(20):
        target_id = f"target-{index:02d}"
        target_commit = f"{index + 1:040x}"
        shared_path = f"pkg/{index:02d}/shared.py"
        left_path = f"pkg/{index:02d}/left.py"
        right_path = f"pkg/{index:02d}/right.py"
        profile = {
            "basic_info": {
                "name": f"RuntimeRepo_{index:02d}",
                "version": target_commit,
            },
            "modules": [
                {"name": "left", "files": [shared_path, left_path]},
                {"name": "right", "files": [right_path, shared_path]},
            ]
        }
        target_profiles[(target_id, target_commit)] = profile
        profile_relative = (
            Path("profiles") / target_id / target_commit / "software_profile.json"
        )
        profile_path = root / profile_relative
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(
            json.dumps(profile, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        profile_sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()
        universe = sorted(
            {shared_path, left_path, right_path},
            key=lambda value: value.encode("utf-8"),
        )
        multi_module_paths = [shared_path]

        for replicate in (1, 2, 3):
            seed_sha256 = batch_scanner.agent_scanner.stable_data_hash(
                {
                    "benchmark_constant": benchmark_constant,
                    "target_commit": target_commit,
                    "replicate": str(replicate),
                }
            )
            ordered_files = sorted(
                universe,
                key=lambda path: (
                    hashlib.sha256((seed_sha256 + path).encode("utf-8")).hexdigest(),
                    path.encode("utf-8"),
                ),
            )
            schedule_payload = {
                "schema_version": 1,
                "algorithm": "sha256-seed-path-v1",
                "benchmark_constant": benchmark_constant,
                "target_commit": target_commit,
                "replicate": str(replicate),
                "seed_sha256": seed_sha256,
                "files": ordered_files,
                "universe_sha256": batch_scanner.agent_scanner.stable_data_hash(
                    universe
                ),
                "order_sha256": batch_scanner.agent_scanner.stable_data_hash(
                    ordered_files
                ),
            }
            schedule_relative = (
                Path("schedules")
                / target_id
                / target_commit
                / f"replicate-{replicate}.json"
            )
            schedule_path = root / schedule_relative
            schedule_path.parent.mkdir(parents=True, exist_ok=True)
            schedule_path.write_text(
                json.dumps(schedule_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            rows.append(
                {
                    "target_id": target_id,
                    "target_commit": target_commit,
                    "replicate": replicate,
                    "path": schedule_relative.as_posix(),
                    "file_sha256": hashlib.sha256(
                        schedule_path.read_bytes()
                    ).hexdigest(),
                    "file_count": len(ordered_files),
                    "target_software_profile_path": profile_relative.as_posix(),
                    "target_software_profile_sha256": profile_sha256,
                    "overlap_path_count": 1,
                    "overlap_extra_membership_count": 1,
                    "multi_module_paths": multi_module_paths,
                    "multi_module_paths_sha256": (
                        batch_scanner.agent_scanner.stable_data_hash(
                            multi_module_paths
                        )
                    ),
                    "universe_sha256": schedule_payload["universe_sha256"],
                    "order_sha256": schedule_payload["order_sha256"],
                }
            )

    manifest = {
        "schema_version": 1,
        "freeze_status": "frozen",
        "algorithm": "sha256-seed-path-v1",
        "benchmark_constant": benchmark_constant,
        "schedules": rows,
    }
    manifest_path = root / "config" / "unprioritized-file-orders.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path, manifest, target_profiles


def _rewrite_frozen_batch_manifest(path: Path, payload):
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_frozen_batch_schedule_fixture(manifest_path: Path, trusted_root: Path):
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    return batch_scanner.load_batch_unprioritized_schedule_manifest(
        manifest_path,
        manifest_sha256,
        trusted_root,
    )


def test_batch_frozen_manifest_maps_all_20_targets_and_replicates(tmp_path):
    manifest_path, _, target_profiles = _write_frozen_batch_schedule_fixture(tmp_path)

    loaded = _load_frozen_batch_schedule_fixture(
        manifest_path,
        tmp_path,
    )

    assert len(loaded["schedule_index"]) == 60
    assert len({key[0] for key in loaded["schedule_index"]}) == 20
    for (target_id, target_commit), profile in target_profiles.items():
        for replicate in (1, 2, 3):
            schedule = batch_scanner.resolve_batch_unprioritized_file_schedule(
                loaded,
                target_id=target_id,
                target_commit=target_commit,
                replicate=replicate,
                software_profile=profile,
            )
            assert len(schedule["files"]) == 3
            assert len(set(schedule["files"])) == 3
            assert schedule["provenance"]["manifest_target_id"] == target_id
            assert schedule["provenance"]["manifest_replicate"] == replicate
            assert schedule["provenance"]["overlap_path_count"] == 1


def test_batch_manifest_hashes_and_parses_each_artifact_from_one_byte_snapshot(
    tmp_path, monkeypatch
):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    expected_manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    artifact_paths = {manifest_path.resolve()}
    artifact_paths.update((tmp_path / row["path"]).resolve() for row in manifest["schedules"])
    artifact_paths.update(
        (tmp_path / row["target_software_profile_path"]).resolve()
        for row in manifest["schedules"]
    )
    snapshots = {path: path.read_bytes() for path in artifact_paths}
    read_counts = {path: 0 for path in artifact_paths}
    original_read_bytes = Path.read_bytes

    def adversarial_read_bytes(path):
        resolved = path.resolve()
        if resolved not in snapshots:
            return original_read_bytes(path)
        read_counts[resolved] += 1
        if read_counts[resolved] > 1:
            return b'{}'
        return snapshots[resolved]

    monkeypatch.setattr(Path, "read_bytes", adversarial_read_bytes)
    loaded = batch_scanner.load_batch_unprioritized_schedule_manifest(
        manifest_path,
        expected_manifest_sha256,
        tmp_path,
    )

    assert len(loaded["schedule_index"]) == 60
    assert set(read_counts.values()) == {1}


def test_batch_manifest_rejects_split_identity_for_one_target_id(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][0]["target_id"] = manifest["schedules"][3]["target_id"]
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="target identity changes across replicates"):
        _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)


def test_batch_manifest_rejects_reused_schedule_artifact_path(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][1]["path"] = manifest["schedules"][0]["path"]
    manifest["schedules"][1]["file_sha256"] = manifest["schedules"][0][
        "file_sha256"
    ]
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="reuses a schedule artifact path"):
        _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)


def test_exp_glm_manifest_has_20_unique_canonical_non_openclaw_targets():
    revision_root = next(
        parent
        for parent in Path(__file__).resolve().parents
        if (
            parent
            / "exp-glm-0823"
            / "manifests"
            / "repositories.json"
        ).is_file()
    )
    manifest_path = (
        revision_root
        / "exp-glm-0823"
        / "manifests"
        / "repositories.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    targets = manifest["repositories"]

    assert len(targets) == 20
    assert manifest["openclaw_policy"] == "excluded_permanently"
    assert len({target["repository_id"] for target in targets}) == 20
    assert len({target["frozen_commit"] for target in targets}) == 20
    assert all(
        re.fullmatch(r"[0-9a-f]{40}", target["frozen_commit"])
        for target in targets
    )
    assert all(
        target["repository_id"].lower() not in {"openclaw", "transformers"}
        for target in targets
    )


def test_batch_repo_name_resolution_rejects_identity_and_profile_mismatch(
    tmp_path,
):
    manifest_path, _, target_profiles = _write_frozen_batch_schedule_fixture(tmp_path)
    loaded = _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)
    (target_id, target_commit), profile = next(iter(target_profiles.items()))

    with pytest.raises(ValueError, match="repository identity mismatch"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_repo_name="Case_Sensitive-Repo-Name",
            target_commit=target_commit,
            replicate=1,
        )

    with pytest.raises(ValueError, match="universe does not match"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_id=target_id,
            target_commit=target_commit,
            replicate=1,
            software_profile={
                "modules": [{"name": "different", "files": ["different.py"]}]
            },
        )


def test_batch_runtime_profile_bytes_path_and_public_provenance_are_bound(tmp_path):
    manifest_path, manifest, target_profiles = _write_frozen_batch_schedule_fixture(
        tmp_path
    )
    loaded = _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)
    (target_id, target_commit), profile = next(iter(target_profiles.items()))
    repo_name = profile["basic_info"]["name"]
    frozen_profile_path = tmp_path / manifest["schedules"][0][
        "target_software_profile_path"
    ]
    runtime_root = tmp_path / "runtime-profiles"
    runtime_profile_path = (
        runtime_root / repo_name / target_commit / "software_profile.json"
    )
    runtime_profile_path.parent.mkdir(parents=True)
    runtime_profile_path.write_bytes(frozen_profile_path.read_bytes())

    schedule = batch_scanner.resolve_batch_unprioritized_file_schedule(
        loaded,
        target_repo_name=repo_name,
        target_commit=target_commit,
        replicate=1,
        software_profile=profile,
        software_profile_path=runtime_profile_path,
        software_profile_root=runtime_root,
    )

    assert schedule["provenance"]["manifest_target_id"] == target_id
    assert schedule["provenance"]["runtime_software_profile_path"] == (
        f"{repo_name}/{target_commit}/software_profile.json"
    )
    serialized_provenance = json.dumps(schedule["provenance"], sort_keys=True)
    assert str(tmp_path) not in serialized_provenance
    for key, value in schedule["provenance"].items():
        if key.endswith("_path"):
            assert not Path(value).is_absolute()

    drifted_profile = json.loads(json.dumps(profile))
    drifted_profile["basic_info"]["description"] = "caller-only drift"
    with pytest.raises(ValueError, match="ProfileRef profile object does not exactly match"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_repo_name=repo_name,
            target_commit=target_commit,
            replicate=1,
            software_profile=drifted_profile,
            software_profile_path=runtime_profile_path,
            software_profile_root=runtime_root,
        )

    runtime_profile_path.write_text(
        runtime_profile_path.read_text(encoding="utf-8") + " ",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_repo_name=repo_name,
            target_commit=target_commit,
            replicate=1,
            software_profile=profile,
            software_profile_path=runtime_profile_path,
            software_profile_root=runtime_root,
        )


def test_batch_runtime_profile_hash_and_parse_share_one_byte_snapshot(
    tmp_path, monkeypatch
):
    manifest_path, manifest, target_profiles = _write_frozen_batch_schedule_fixture(
        tmp_path
    )
    loaded = _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)
    (target_id, target_commit), profile = next(iter(target_profiles.items()))
    repo_name = profile["basic_info"]["name"]
    frozen_profile_path = tmp_path / manifest["schedules"][0][
        "target_software_profile_path"
    ]
    runtime_root = tmp_path / "runtime-profiles"
    runtime_profile_path = (
        runtime_root / repo_name / target_commit / "software_profile.json"
    )
    runtime_profile_path.parent.mkdir(parents=True)
    runtime_bytes = frozen_profile_path.read_bytes()
    runtime_profile_path.write_bytes(runtime_bytes)
    original_read_bytes = Path.read_bytes
    read_count = 0

    def adversarial_read_bytes(path):
        nonlocal read_count
        if path.resolve() != runtime_profile_path.resolve():
            return original_read_bytes(path)
        read_count += 1
        return runtime_bytes if read_count == 1 else b'{}'

    monkeypatch.setattr(Path, "read_bytes", adversarial_read_bytes)
    schedule = batch_scanner.resolve_batch_unprioritized_file_schedule(
        loaded,
        target_repo_name=repo_name,
        target_commit=target_commit,
        replicate=1,
        software_profile=profile,
        software_profile_path=runtime_profile_path,
        software_profile_root=runtime_root,
    )

    assert schedule["provenance"]["manifest_target_id"] == target_id
    assert read_count == 1


def test_batch_manifest_rejects_symlink_ancestor_in_trusted_root(tmp_path):
    real_parent = tmp_path / "real-parent"
    trusted_root = real_parent / "root"
    manifest_path, _, _ = _write_frozen_batch_schedule_fixture(trusted_root)
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    aliased_root = alias_parent / "root"

    with pytest.raises(ValueError, match="symlink components"):
        batch_scanner.load_batch_unprioritized_schedule_manifest(
            aliased_root / manifest_path.relative_to(trusted_root),
            manifest_sha256,
            aliased_root,
        )

def test_batch_frozen_manifest_resolver_rejects_missing_target_replicate_and_commit(
    tmp_path,
):
    manifest_path, _, target_profiles = _write_frozen_batch_schedule_fixture(tmp_path)
    loaded = _load_frozen_batch_schedule_fixture(
        manifest_path,
        tmp_path,
    )
    target_id, target_commit = next(iter(target_profiles))

    with pytest.raises(ValueError, match="target is missing"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_id="missing-target",
            target_commit=target_commit,
            replicate=1,
        )
    with pytest.raises(ValueError, match="replicate is missing"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_id=target_id,
            target_commit=target_commit,
            replicate=4,
        )
    with pytest.raises(ValueError, match="target commit mismatch"):
        batch_scanner.resolve_batch_unprioritized_file_schedule(
            loaded,
            target_id=target_id,
            target_commit="f" * 40,
            replicate=1,
        )


@pytest.mark.parametrize(
    ("field", "expected_error"),
    [
        ("file_sha256", "file_sha256 mismatch"),
        (
            "target_software_profile_sha256",
            "target_software_profile_sha256 mismatch",
        ),
    ],
)
def test_batch_frozen_manifest_rejects_artifact_hash_mismatch(
    tmp_path,
    field,
    expected_error,
):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][0][field] = "0" * 64
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match=expected_error):
        _load_frozen_batch_schedule_fixture(
            manifest_path,
            tmp_path,
        )


def test_batch_frozen_manifest_rejects_raw_manifest_hash_mismatch(tmp_path):
    manifest_path, _, _ = _write_frozen_batch_schedule_fixture(tmp_path)

    with pytest.raises(ValueError, match="manifest SHA-256 mismatch"):
        batch_scanner.load_batch_unprioritized_schedule_manifest(
            manifest_path,
            "0" * 64,
            tmp_path,
        )


def test_batch_frozen_manifest_rejects_duplicate_json_keys_in_manifest(tmp_path):
    manifest_path, _, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    content = manifest_path.read_text(encoding="utf-8")
    content = content.replace(
        '"algorithm": "sha256-seed-path-v1",',
        '"algorithm": "sha256-seed-path-v1",\n  '
        '"algorithm": "sha256-seed-path-v1",',
        1,
    )
    manifest_path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key.*algorithm"):
        _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)


def test_batch_frozen_manifest_rejects_duplicate_json_keys_in_schedule(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    row = manifest["schedules"][0]
    schedule_path = tmp_path / row["path"]
    content = schedule_path.read_text(encoding="utf-8")
    content = content.replace(
        '"algorithm": "sha256-seed-path-v1",',
        '"algorithm": "sha256-seed-path-v1",\n  '
        '"algorithm": "sha256-seed-path-v1",',
        1,
    )
    schedule_path.write_text(content, encoding="utf-8")
    row["file_sha256"] = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="duplicate JSON key.*algorithm"):
        _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)


def test_batch_frozen_manifest_rejects_duplicate_json_keys_in_profile(tmp_path):
    manifest_path, manifest, target_profiles = _write_frozen_batch_schedule_fixture(
        tmp_path
    )
    (_, _), profile = next(iter(target_profiles.items()))
    repo_name = profile["basic_info"]["name"]
    first_row = manifest["schedules"][0]
    profile_path = tmp_path / first_row["target_software_profile_path"]
    content = profile_path.read_text(encoding="utf-8")
    content = content.replace(
        f'"name": "{repo_name}",',
        f'"name": "{repo_name}",\n    "name": "{repo_name}",',
        1,
    )
    profile_path.write_text(content, encoding="utf-8")
    profile_sha256 = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    for row in manifest["schedules"]:
        if row["target_software_profile_path"] == first_row[
            "target_software_profile_path"
        ]:
            row["target_software_profile_sha256"] = profile_sha256
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="duplicate JSON key.*name"):
        _load_frozen_batch_schedule_fixture(manifest_path, tmp_path)


def test_batch_frozen_manifest_rejects_schedule_commit_mismatch(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][0]["target_commit"] = "f" * 40
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="target_commit must exactly match"):
        _load_frozen_batch_schedule_fixture(
            manifest_path,
            tmp_path,
        )


def test_batch_frozen_manifest_rejects_ambiguous_duplicate_key(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][1] = dict(manifest["schedules"][0])
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="ambiguous duplicate"):
        _load_frozen_batch_schedule_fixture(
            manifest_path,
            tmp_path,
        )


def test_batch_frozen_manifest_rejects_duplicate_schedule_file(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    row = manifest["schedules"][0]
    schedule_path = tmp_path / row["path"]
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    schedule["files"].append(schedule["files"][0])
    schedule_path.write_text(
        json.dumps(schedule, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    row["file_sha256"] = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    row["file_count"] = len(schedule["files"])
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="duplicate files"):
        _load_frozen_batch_schedule_fixture(
            manifest_path,
            tmp_path,
        )


def test_batch_frozen_manifest_rejects_overlap_provenance_mismatch(tmp_path):
    manifest_path, manifest, _ = _write_frozen_batch_schedule_fixture(tmp_path)
    manifest["schedules"][0]["overlap_path_count"] = 0
    _rewrite_frozen_batch_manifest(manifest_path, manifest)

    with pytest.raises(ValueError, match="overlap_path_count mismatch"):
        _load_frozen_batch_schedule_fixture(
            manifest_path,
            tmp_path,
        )


def test_batch_candidate_ablation_cli_requires_manifest_root_and_replicate(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--ablate-candidate-priority",
            "--unprioritized-file-order-manifest",
            "/trusted/manifest.json",
            "--unprioritized-file-order-manifest-sha256",
            "a" * 64,
            "--unprioritized-file-order-root",
            "/trusted",
            "--unprioritized-file-order-replicate",
            "2",
        ],
    )
    args = batch_scanner.parse_args()

    assert batch_scanner._validate_args(args) is True
    assert args.unprioritized_file_order_replicate == 2
    assert args.unprioritized_file_order_manifest_sha256 == "a" * 64

    args.skip_any_existing_scan_result = True
    assert batch_scanner._validate_args(args) is False
    args.skip_any_existing_scan_result = False

    args.unprioritized_file_order_replicate = None
    assert batch_scanner._validate_args(args) is False


def test_batch_evaluation_mode_rejects_skip_any_existing_result(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--evaluation-mode",
            "--skip-existing-scans",
            "--skip-any-existing-scan-result",
        ],
    )
    args = batch_scanner.parse_args()

    assert batch_scanner._validate_args(args) is False


def test_batch_invalid_manifest_fails_before_path_or_scan_setup(monkeypatch, tmp_path):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "batch-scanner",
            "--ablate-candidate-priority",
            "--unprioritized-file-order-manifest",
            str(tmp_path / "missing.json"),
            "--unprioritized-file-order-manifest-sha256",
            "0" * 64,
            "--unprioritized-file-order-root",
            str(tmp_path),
            "--unprioritized-file-order-replicate",
            "1",
        ],
    )
    args = batch_scanner.parse_args()
    monkeypatch.setattr(batch_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(batch_scanner, "setup_logging", lambda _verbose: None)
    path_setup_called = False

    def fail_if_called(_args):
        nonlocal path_setup_called
        path_setup_called = True
        raise AssertionError("path setup must not run after frozen manifest failure")

    monkeypatch.setattr(batch_scanner, "_resolve_batch_scan_paths", fail_if_called)

    assert batch_scanner.main() == 1
    assert path_setup_called is False


def test_batch_task_and_run_single_target_receive_exact_frozen_schedule(
    monkeypatch,
    tmp_path,
):
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef(
            "target-repo",
            "a" * 40,
            _mk_profile("target-repo"),
        ),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    schedule = {
        "files": ["b.py", "a.py"],
        "provenance": {
            "manifest_target_id": "target-repo",
            "manifest_target_commit": "a" * 40,
            "manifest_replicate": 2,
        },
    }
    tasks = batch_scanner._build_scan_tasks(
        cve_id="CVE-2026-0001",
        similar_targets=[target],
        vulnerability_profile=object(),
        unprioritized_file_schedules={("target-repo", "a" * 40): schedule},
    )
    assert tasks[0]["unprioritized_file_schedule"] is schedule

    captured_execution = {}

    def fake_execution_task(**kwargs):
        captured_execution.update(kwargs)
        return {
            "status": "ok",
            "started_at": "start",
            "finished_at": "finish",
            "duration_seconds": 0.0,
        }

    monkeypatch.setattr(
        batch_scanner.batch_scanner_execution_module,
        "_run_target_scan_task",
        fake_execution_task,
    )
    batch_scanner._run_target_scan_task(
        tasks[0],
        batch_args=Namespace(),
        target_repos_root=tmp_path,
        repo_lock_manager=object(),
    )
    assert captured_execution["unprioritized_file_schedule"] is schedule

    captured_scan = {}

    def fake_run_single_target_scan(**kwargs):
        return _write_terminal_scan_for_kwargs(
            kwargs, captured=captured_scan
        )

    monkeypatch.setattr(
        batch_scanner_execution.agent_scanner,
        "run_single_target_scan",
        fake_run_single_target_scan,
    )
    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        target_repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="max",
        verbose=False,
        skip_existing_scans=False,
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft",
        ablate_candidate_priority=True,
    )
    status = batch_scanner_execution._DEFAULT_RUN_TARGET_SCAN(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
        unprioritized_file_schedule=schedule,
    )

    assert status == "ok"
    assert captured_scan["unprioritized_file_schedule"] is schedule


def test_batch_skip_fingerprints_include_exact_frozen_schedule(monkeypatch, tmp_path):
    captured = []

    def fake_build_scan_fingerprint(**kwargs):
        captured.append(kwargs)
        return {"hash": "expected"}

    @contextmanager
    def fake_repo_lock(*_args, **_kwargs):
        yield

    target_commit = "a" * 40
    target_profile = SoftwareProfile(
        name="target-repo",
        version=target_commit,
        modules=[ModuleInfo(name="module", files=["b.py", "a.py"])],
    )
    target_profile.repo_info = {
        "repo_analysis": {"languages": ["python"]},
    }
    profile_path = (
        tmp_path
        / "profiles"
        / "soft"
        / "target-repo"
        / target_commit
        / "software_profile.json"
    )
    profile_path.parent.mkdir(parents=True)
    profile_bytes = json.dumps(
        target_profile.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    profile_path.write_bytes(profile_bytes)
    schedule_files = ["b.py", "a.py"]
    schedule = {
        "files": schedule_files,
        "provenance": {
            "manifest_replicate": 2,
            "target_software_profile_sha256": hashlib.sha256(
                profile_bytes
            ).hexdigest(),
            "universe_sha256": batch_scanner.agent_scanner.stable_data_hash(
                sorted(schedule_files)
            ),
                "order_sha256": batch_scanner.agent_scanner.stable_data_hash(
                    schedule_files
                ),
                "page_algorithm": (
                    batch_scanner.agent_scanner.FROZEN_SCHEDULE_PAGE_ALGORITHM
                ),
                "page_size": batch_scanner.agent_scanner.FROZEN_SCHEDULE_PAGE_SIZE,
            },
    }
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", target_commit, target_profile),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    scan_target = batch_scanner.agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=target_commit,
        similarity=target,
    )
    repo_path = tmp_path / "repos" / "target-repo"
    repo_path.mkdir(parents=True)
    batch_args = Namespace(
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        target_repos_root=tmp_path / "repos",
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft",
        ablate_candidate_priority=True,
    )
    monkeypatch.setattr(
        batch_scanner_execution.agent_scanner,
        "build_scan_fingerprint",
        fake_build_scan_fingerprint,
    )
    monkeypatch.setattr(batch_scanner_execution, "hold_repo_lock", fake_repo_lock)
    monkeypatch.setattr(
        batch_scanner_execution,
        "get_git_commit",
        lambda _path: target_commit,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "get_git_restore_target",
        lambda _path: target_commit,
    )
    monkeypatch.setattr(
        batch_scanner_execution,
        "has_uncommitted_changes",
        lambda _path: False,
    )
    monkeypatch.setattr(
        batch_scanner_execution.agent_scanner,
        "_resolve_scan_languages",
        lambda *_args, **_kwargs: ["python"],
    )
    monkeypatch.setattr(
        batch_scanner_execution.agent_scanner,
        "_resolve_codeql_database_names",
        lambda *_args, **_kwargs: {},
    )

    live = batch_scanner_execution._build_expected_scan_fingerprint_for_skip(
        batch_args=batch_args,
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
        scan_target=scan_target,
        target_repo_path=repo_path,
        unprioritized_file_schedule=schedule,
    )
    profile_based = (
        batch_scanner_execution._build_profile_based_scan_fingerprint_for_skip(
            batch_args=batch_args,
            cve_id="CVE-2026-0001",
            vulnerability_profile=object(),
            llm_client=object(),
            target=target,
            scan_target=scan_target,
            unprioritized_file_schedule=schedule,
        )
    )

    assert live == {"hash": "expected"}
    assert profile_based == {"hash": "expected"}
    assert [call["unprioritized_file_schedule"] for call in captured] == [
        schedule,
        schedule,
    ]

    mutated_payload = target_profile.to_dict()
    mutated_payload["basic_info"]["description"] = "mutated after preflight"
    profile_path.write_text(
        json.dumps(mutated_payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="target software profile SHA-256 mismatch"):
        batch_scanner_execution._build_profile_based_scan_fingerprint_for_skip(
            batch_args=batch_args,
            cve_id="CVE-2026-0001",
            vulnerability_profile=object(),
            llm_client=object(),
            target=target,
            scan_target=scan_target,
            unprioritized_file_schedule=schedule,
        )


def test_scan_memory_full_universe_cap_before_progress_is_partial(tmp_path):
    output_dir = tmp_path / "scan-out"
    output_dir.mkdir()
    (output_dir / "scan_memory.json").write_text(
        json.dumps(
            {
                "file_status": {"a.py": "pending", "b.py": "pending"},
                "module_priorities": {"m": 1},
                "file_to_module": {"a.py": "m", "b.py": "m"},
                "findings": [],
                "scan_signature": {
                    "scan_config": {"require_full_universe_completion": True}
                },
            }
        ),
        encoding="utf-8",
    )

    quality = batch_scanner_execution._load_scan_memory_quality(output_dir)

    assert quality is not None
    assert quality["coverage_status"] == "partial"
    assert quality["full_universe_required"] is True
    assert quality["full_universe_complete"] is False
    assert quality["full_universe_total_files"] == 2
    assert quality["full_universe_completed_files"] == 0
