from argparse import Namespace

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.retriever import ProfileRef, ProfileSimilarityMetrics, SimilarProfileCandidate

import cli.batch_scanner as batch_scanner


def _mk_profile(name: str):
    return SoftwareProfile(name=name, modules=[ModuleInfo(name="m")])


def test_normalize_cve_id_fallback():
    assert batch_scanner._normalize_cve_id({"cve_id": ""}, 3) == "vuln-3"
    assert batch_scanner._normalize_cve_id({"cve_id": "CVE-2025-0001"}, 3) == "CVE-2025-0001"


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


def test_resolve_profile_dirs_from_args_with_relative_dirnames(tmp_path):
    args = Namespace(
        profile_base_path=str(tmp_path / "profiles"),
        soft_profiles_dir="soft",
        vuln_profiles_dir="vuln",
    )

    soft_dir, vuln_dir = batch_scanner._resolve_profile_dirs_from_args(args)

    assert soft_dir == tmp_path / "profiles" / "soft"
    assert vuln_dir == tmp_path / "profiles" / "vuln"


def test_resolve_profile_dirs_from_args_with_absolute_paths(tmp_path):
    soft_abs = tmp_path / "custom-soft"
    vuln_abs = tmp_path / "custom-vuln"
    args = Namespace(
        profile_base_path=str(tmp_path / "profiles"),
        soft_profiles_dir=str(soft_abs),
        vuln_profiles_dir=str(vuln_abs),
    )

    soft_dir, vuln_dir = batch_scanner._resolve_profile_dirs_from_args(args)

    assert soft_dir == soft_abs
    assert vuln_dir == vuln_abs


def test_run_target_scan_passes_profile_base_path_and_dirname(monkeypatch, tmp_path):
    captured = {}

    def fake_run_single_target_scan(*, args, vulnerability_profile, llm_client, target):
        captured["profile_base_path"] = getattr(args, "profile_base_path", None)
        captured["software_profile_dirname"] = getattr(args, "software_profile_dirname", None)
        return True

    monkeypatch.setattr(batch_scanner.agent_scanner, "_run_single_target_scan", fake_run_single_target_scan)

    batch_args = Namespace(
        scan_output_dir=tmp_path / "scan-out",
        repos_root=tmp_path / "repos",
        max_iterations_cap=3,
        disable_critical_stop=False,
        critical_stop_mode="min",
        verbose=False,
        skip_existing_scans=False,
        profile_base_path=str(tmp_path / "profiles"),
        soft_profiles_dir="soft-nvidia",
    )
    target = SimilarProfileCandidate(
        profile_ref=ProfileRef("target-repo", "a" * 40, _mk_profile("target-repo")),
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )

    ok = batch_scanner._run_target_scan(
        batch_args=batch_args,
        repo_profiles_dir=tmp_path / "profiles" / "soft-nvidia",
        cve_id="CVE-2026-0001",
        vulnerability_profile=object(),
        llm_client=object(),
        target=target,
    )

    assert ok is True
    assert captured["profile_base_path"] == str(tmp_path / "profiles")
    assert captured["software_profile_dirname"] == "soft-nvidia"


def test_ensure_vulnerability_profile_uses_repos_root_for_vuln_loading(monkeypatch, tmp_path):
    repo_name = "demo"
    commit_hash = "abc123"
    cve_id = "CVE-2026-0001"
    repos_root = tmp_path / "repos"
    (repos_root / repo_name).mkdir(parents=True)

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

    class StubProfiler:
        def __init__(self, llm_client, repo_profile, vuln_entry, output_dir):
            captured["output_dir"] = output_dir
            captured["vuln_entry_cve"] = vuln_entry.cve_id

        def generate_vulnerability_profile(self, repo_path, save_results=True):
            captured["repo_path"] = repo_path
            captured["save_results"] = save_results

    monkeypatch.setattr(batch_scanner, "read_vuln_data", fake_read_vuln_data)
    monkeypatch.setattr(batch_scanner, "VulnerabilityProfiler", StubProfiler)

    profile = batch_scanner._ensure_vulnerability_profile(
        vuln_index=4,
        repo_name=repo_name,
        commit_hash=commit_hash,
        cve_id=cve_id,
        repos_root=repos_root,
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
    assert captured["repo_base_path"] == repos_root
    assert captured["vuln_json_path"] == str(tmp_path / "vuln.json")
    assert captured["repo_path"] == str(repos_root / repo_name)
    assert captured["save_results"] is True
    assert captured["vuln_entry_cve"] == cve_id
