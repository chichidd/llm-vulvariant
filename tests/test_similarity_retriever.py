from pathlib import Path

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.retriever import (
    ProfileRef,
    ProfileSimilarityMetrics,
    _jaccard_similarity,
    _module_dependency_import_tokens,
    _text_similarity,
    compute_profile_similarity,
    load_all_software_profiles,
    rank_similar_profiles,
    resolve_profile_commit,
    select_profile_ref,
)


def _mk_profile(name: str, desc: str, modules, apps=None, users=None, dep_count=None, libs=None):
    return SoftwareProfile(
        name=name,
        description=desc,
        target_application=apps or [],
        target_user=users or [],
        modules=modules,
        dependency_usage_count=dep_count or {},
        third_party_libraries=libs or [],
    )


def test_module_dependency_import_tokens_include_internal_external_and_project_level():
    profile = _mk_profile(
        name="src",
        desc="d",
        modules=[
            ModuleInfo(
                name="API",
                internal_dependencies=["Core"],
                calls_modules=["Storage"],
                called_by_modules=["Gateway"],
                external_dependencies=["requests"],
            )
        ],
        dep_count={"numpy": 2},
        libs=["pydantic"],
    )

    tokens = _module_dependency_import_tokens(profile)

    assert "dep::api->core" in tokens
    assert "dep::api->storage" in tokens
    assert "dep::api->gateway" in tokens
    assert "import::api::requests" in tokens
    assert "project_import::numpy" in tokens
    assert "project_import::pydantic" in tokens


def test_compute_profile_similarity_lexical_and_dependency_import_dimension():
    source = _mk_profile(
        name="s",
        desc="ml inference api service",
        apps=["inference"],
        users=["ml engineer"],
        modules=[
            ModuleInfo(
                name="API",
                internal_dependencies=["Core"],
                external_dependencies=["requests", "numpy"],
            )
        ],
        dep_count={"numpy": 3},
    )
    target = _mk_profile(
        name="t",
        desc="api service for inference",
        apps=["inference"],
        users=["platform engineer"],
        modules=[
            ModuleInfo(
                name="api",
                internal_dependencies=["core"],
                external_dependencies=["numpy", "fastapi"],
            )
        ],
        dep_count={"numpy": 1},
    )

    metrics = compute_profile_similarity(source, target, text_retriever=None)

    assert 0.0 <= metrics.description_sim <= 1.0
    assert 0.0 <= metrics.target_application_sim <= 1.0
    assert 0.0 <= metrics.target_user_sim <= 1.0
    assert 0.0 <= metrics.module_jaccard_sim <= 1.0
    assert 0.0 <= metrics.module_dependency_import_sim <= 1.0
    assert metrics.module_dependency_import_sim > 0.0
    assert 0.0 <= metrics.overall_sim <= 1.0


def test_compute_profile_similarity_when_weights_non_positive_uses_average():
    source = _mk_profile("a", "same text", [ModuleInfo(name="m")])
    target = _mk_profile("b", "same text", [ModuleInfo(name="m")])

    metrics = compute_profile_similarity(
        source,
        target,
        weights={
            "description": 0,
            "target_application": -1,
            "target_user": 0,
            "module_jaccard": 0,
            "module_dependency_import": 0,
        },
    )

    expected_avg = (
        metrics.description_sim
        + metrics.target_application_sim
        + metrics.target_user_sim
        + metrics.module_jaccard_sim
        + metrics.module_dependency_import_sim
    ) / 5
    assert metrics.overall_sim == expected_avg


def test_text_similarity_uses_retriever_and_falls_back_to_jaccard_on_error():
    class DummyRetriever:
        def similarity(self, left, right):
            return 0.88

    assert _text_similarity("a", "b", text_retriever=DummyRetriever()) == 0.88

    class BrokenRetriever:
        def similarity(self, left, right):
            raise RuntimeError("boom")

    # lexical jaccard: {alpha,beta} vs {alpha,gamma} = 1/3
    assert _text_similarity("alpha beta", "alpha gamma", text_retriever=BrokenRetriever()) == 1 / 3


def test_rank_similar_profiles_excludes_same_repo_and_uses_tie_break(monkeypatch):
    source = ProfileRef("repo-a", "aaaaaaaaaaaa1111", _mk_profile("a", "x", [ModuleInfo(name="m")]))
    candidate_1 = ProfileRef("repo-b", "bbbb", _mk_profile("b", "x", [ModuleInfo(name="m")]))
    candidate_2 = ProfileRef("repo-c", "cccc", _mk_profile("c", "x", [ModuleInfo(name="m")]))
    same_repo = ProfileRef("repo-a", "dddd", _mk_profile("d", "x", [ModuleInfo(name="m")]))

    score_map = {
        "b": ProfileSimilarityMetrics(0.6, 0.6, 0.6, 0.4, 0.8, 0.6),
        "c": ProfileSimilarityMetrics(0.6, 0.6, 0.6, 0.9, 0.7, 0.6),
        "a": ProfileSimilarityMetrics(1, 1, 1, 1, 1, 1),
    }

    def fake_compute(source_profile, target_profile, text_retriever=None, weights=None):
        return score_map[target_profile.name]

    monkeypatch.setattr("scanner.similarity.retriever.compute_profile_similarity", fake_compute)

    ranked = rank_similar_profiles(
        source_ref=source,
        candidate_refs=[candidate_1, candidate_2, same_repo],
        top_k=2,
        exclude_same_repo=True,
    )

    # overall equal; dep/import higher should win before module_jaccard
    assert [c.profile_ref.repo_name for c in ranked] == ["repo-b", "repo-c"]


def test_rank_similar_profiles_applies_min_overall_similarity(monkeypatch):
    source = ProfileRef("repo-a", "aaaaaaaaaaaa1111", _mk_profile("a", "x", [ModuleInfo(name="m")]))
    candidate_1 = ProfileRef("repo-b", "bbbb", _mk_profile("b", "x", [ModuleInfo(name="m")]))
    candidate_2 = ProfileRef("repo-c", "cccc", _mk_profile("c", "x", [ModuleInfo(name="m")]))

    score_map = {
        "b": ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
        "c": ProfileSimilarityMetrics(0.6, 0.6, 0.6, 0.6, 0.6, 0.6),
    }

    def fake_compute(source_profile, target_profile, text_retriever=None, weights=None):
        return score_map[target_profile.name]

    monkeypatch.setattr("scanner.similarity.retriever.compute_profile_similarity", fake_compute)

    ranked = rank_similar_profiles(
        source_ref=source,
        candidate_refs=[candidate_1, candidate_2],
        top_k=10,
        min_overall_similarity=0.7,
    )

    assert len(ranked) == 1
    assert ranked[0].profile_ref.repo_name == "repo-b"


def test_load_all_profiles_and_commit_resolution(tmp_path):
    repo_profiles_dir = tmp_path / "repo-profiles"
    good_dir = repo_profiles_dir / "repo1" / "abc123456789"
    good_dir.mkdir(parents=True)
    (good_dir / "software_profile.json").write_text(
        "{\"basic_info\": {\"name\": \"repo1\", \"version\": \"abc123456789\"}}",
        encoding="utf-8",
    )

    bad_dir = repo_profiles_dir / "repo1" / "broken"
    bad_dir.mkdir(parents=True)
    (bad_dir / "software_profile.json").write_text("{not-json", encoding="utf-8")

    repo2 = repo_profiles_dir / "repo2"
    (repo2 / "000000000001").mkdir(parents=True)
    (repo2 / "000000000002").mkdir(parents=True)

    refs = load_all_software_profiles(repo_profiles_dir)
    assert len(refs) == 1
    assert refs[0].repo_name == "repo1"
    assert refs[0].label.startswith("repo1-")

    assert resolve_profile_commit(repo_profiles_dir, "repo2") == "000000000002"
    assert resolve_profile_commit(repo_profiles_dir, "repo2", "00000000000") == "000000000001"
    assert resolve_profile_commit(repo_profiles_dir, "repo2", "does-not-exist") is None


def test_select_profile_ref_with_commit_hint():
    refs = [
        ProfileRef("repo", "1111aaaa", _mk_profile("a", "", [])),
        ProfileRef("repo", "2222bbbb", _mk_profile("b", "", [])),
    ]

    selected_latest = select_profile_ref(refs, "repo", None)
    selected_prefix = select_profile_ref(refs, "repo", "1111")
    missing = select_profile_ref(refs, "repo", "ffff")

    assert selected_latest is not None and selected_latest.commit_hash == "2222bbbb"
    assert selected_prefix is not None and selected_prefix.commit_hash == "1111aaaa"
    assert missing is None


def test_jaccard_similarity_handles_empty_sets():
    assert _jaccard_similarity(set(), {"a"}) == 0.0
    assert _jaccard_similarity({"a"}, set()) == 0.0
    assert _jaccard_similarity({"a"}, {"a", "b"}) == 0.5
