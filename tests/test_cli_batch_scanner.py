from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.retriever import ProfileRef, ProfileSimilarityMetrics

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
