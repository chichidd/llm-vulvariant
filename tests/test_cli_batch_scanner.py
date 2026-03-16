import json
import sys
from argparse import Namespace

import pytest

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.retriever import ProfileRef, ProfileSimilarityMetrics, SimilarProfileCandidate

import cli.batch_scanner as batch_scanner


def _mk_profile(name: str):
    return SoftwareProfile(name=name, modules=[ModuleInfo(name="m")])


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


def test_validate_args_rejects_negative_limit():
    args = Namespace(
        similarity_threshold=0.7,
        max_targets=5,
        fallback_top_n=3,
        max_iterations_cap=10,
        limit=-1,
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
        profile_base_path=str(tmp_path / "profiles"),
        target_soft_profiles_dir="soft-nvidia",
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


def test_run_target_scan_reports_skipped_for_existing_findings(monkeypatch, tmp_path):
    def fake_run_single_target_scan(**kwargs):
        raise AssertionError("existing result should have been skipped")

    monkeypatch.setattr(batch_scanner.agent_scanner, "run_single_target_scan", fake_run_single_target_scan)

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

    assert status == "skipped"


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


def test_ensure_vulnerability_profile_uses_source_repos_root_for_vuln_loading(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    source_repos_root = tmp_path / "repos"
    (source_repos_root / repo_name).mkdir(parents=True)

    monkeypatch.setattr(batch_scanner, "_ensure_software_profile", lambda **kwargs: object())
    monkeypatch.setattr(batch_scanner, "load_vulnerability_profile", lambda *args, **kwargs: None)

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
        lambda *, repo_path, output_dir, llm_client, repo_profile, vuln_entry: captured.update(
            {
                "output_dir": output_dir,
                "vuln_entry_cve": vuln_entry.cve_id,
                "repo_path": str(repo_path),
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
    assert summary["llm_name"] == "deepseek-chat"


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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "ok")

    exit_code = batch_scanner.main()

    assert exit_code == 0
    assert captured["source_repos_root"] == source_repos_root
    assert captured["target_repos_root"] == target_repos_root
    assert captured["source_repo_profiles_dir"] == tmp_path / "profiles" / "soft"
    assert captured["target_repo_profiles_dir"] == tmp_path / "profiles" / "soft-nvidia"
    assert captured["vuln_source_repos_root"] == source_repos_root
    assert captured["vuln_source_repo_profiles_dir"] == tmp_path / "profiles" / "soft"
    assert captured["resolved_vuln_profiles_dir"] == tmp_path / "profiles" / "vuln"


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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "skipped")

    exit_code = batch_scanner.main()

    assert exit_code == 0
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["failed_scans"] == 0
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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: next(scan_results))

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["failed_scans"] == 1
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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "skipped")

    exit_code = batch_scanner.main()

    assert exit_code == 1
    summary_files = sorted(scan_output_dir.glob("batch-summary-*.json"))
    assert len(summary_files) == 1
    summary = json.loads(summary_files[0].read_text(encoding="utf-8"))
    assert summary["total_scans"] == 1
    assert summary["successful_scans"] == 0
    assert summary["skipped_scans"] == 1
    assert summary["failed_profile_generation"] == 1
    assert summary["failed_scans"] == 0
    assert (
        summary["total_scans"]
        == summary["successful_scans"] + summary["skipped_scans"] + summary["failed_scans"]
    )
    assert summary["entries"][1]["status"] == "failed_profile_generation"


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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "ok")

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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "ok")

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
    monkeypatch.setattr(batch_scanner, "create_llm_client", lambda config: object())
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
    monkeypatch.setattr(batch_scanner, "_run_target_scan", lambda **kwargs: "ok")

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
        "create_llm_client",
        lambda config: (_ for _ in ()).throw(AssertionError("should fail before creating llm clients")),
    )

    exit_code = batch_scanner.main()

    assert exit_code == 1
