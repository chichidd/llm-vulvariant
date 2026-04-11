import json
import time
import sys
import threading
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path

import pytest

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME
from scanner.similarity.retriever import ProfileRef, ProfileSimilarityMetrics, SimilarProfileCandidate

import cli.batch_scanner_cache as batch_scanner_cache
import cli.batch_scanner_execution as batch_scanner_execution
import cli.batch_scanner as batch_scanner


def _mk_profile(name: str):
    return SoftwareProfile(name=name, modules=[ModuleInfo(name="m")])


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
    assert fallback_used is False


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
        captured.update(kwargs)
        return True

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
        json.dumps({"coverage_status": "complete", "scan_fingerprint": {"hash": "expected"}}),
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
        captured.update(kwargs)
        return True

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
    monkeypatch.setattr(
        batch_scanner_execution,
        "_build_profile_based_scan_fingerprint_for_skip",
        lambda **_kwargs: {"hash": "saved"},
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

    assert status == "skipped"


def test_run_target_scan_does_not_reuse_saved_findings_when_live_validation_fails_on_existing_repo(
    monkeypatch,
    tmp_path,
):
    repo_dir = tmp_path / "repos" / "target-repo"
    repo_dir.mkdir(parents=True)
    captured = {}

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **kwargs: captured.update(kwargs) or True,
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
        captured.update(kwargs)
        return True

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

    monkeypatch.setattr(
        batch_scanner.agent_scanner,
        "run_single_target_scan",
        lambda **kwargs: captured.update(kwargs) or True,
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

    def _fake_build_scan_fingerprint(**kwargs):
        captured_fingerprint.update(kwargs)
        return {"hash": kwargs["scan_languages"][0]}

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
    target_commit = "t" * 40
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", target_commit, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    output_dir = tmp_path / "scan-out" / "CVE-2026-0001" / "target-repo-tttttttttttt"
    output_dir.mkdir(parents=True)
    (output_dir / "agentic_vuln_findings.json").write_text(
        json.dumps({"coverage_status": "complete", "scan_fingerprint": {"hash": "target"}}),
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
    assert marker_path.read_text(encoding="utf-8") == "current"
    assert captured_fingerprint["critical_stop_max_priority"] == 1
    assert captured_fingerprint["module_similarity_config"] == {
        "model_name": "mini-model",
        "device": "cuda",
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
        captured.update(kwargs)
        return True

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
        captured.update(kwargs)
        return True

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
        captured.update(kwargs)
        return True

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


def test_load_saved_scan_quality_reads_coverage_metadata(tmp_path):
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
    assert saved["scan_fingerprint_hash"] == "expected"


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
    assert summary["fallback_top_n"] == 2
    assert summary["include_same_repo"] is True
    assert summary["limit"] == 5
    assert summary["force_regenerate_profiles"] is True
    assert summary["jobs"] == 4
    assert summary["llm_name"] == "deepseek-chat"


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

    assert exit_code == 0
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
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "agentic_vuln_findings.json").write_text(
            json.dumps(
                {
                    "coverage_status": "complete",
                    "critical_scope_present": True,
                    "critical_complete": True,
                    "critical_scope_total_files": 2,
                    "critical_scope_completed_files": 2,
                    "scan_progress": {"completed": 2, "pending": 0},
                }
            ),
            encoding="utf-8",
        )
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
    assert result["scan_progress"] == {"completed": 2, "pending": 0}
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
