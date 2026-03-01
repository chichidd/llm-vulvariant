from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import cli.agent_scanner as agent_scanner
from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.retriever import (
    ProfileRef,
    ProfileSimilarityMetrics,
    SimilarProfileCandidate,
)


def _mk_profile(name: str, version: str = ""):
    return SoftwareProfile(name=name, version=version, modules=[ModuleInfo(name="m")])


def test_validate_args_rejects_target_commit_without_repo():
    args = Namespace(target_repo=None, target_commit="abc", top_k=3)
    assert agent_scanner._validate_args(args) is False


def test_validate_args_rejects_non_positive_top_k():
    args = Namespace(target_repo="repo", target_commit=None, top_k=0)
    assert agent_scanner._validate_args(args) is False


def test_validate_args_rejects_out_of_range_similarity_threshold():
    args = Namespace(target_repo="repo", target_commit=None, top_k=1, similarity_threshold=1.2)
    assert agent_scanner._validate_args(args) is False


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

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "headcommit123456")
    monkeypatch.setattr(agent_scanner, "resolve_profile_commit", lambda *_: "headcommit123456ffff")

    targets = agent_scanner._resolve_manual_targets(args, vuln, tmp_path)

    assert len(targets) == 1
    assert targets[0].commit_hash.startswith("headcommit")


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


def test_save_scan_outputs_writes_similarity_file(tmp_path):
    finder = SimpleNamespace(conversation_history=[{"role": "assistant", "content": "ok"}])
    results = {"vulnerabilities": []}

    profile_ref = ProfileRef("repo", "abcd", _mk_profile("repo"))
    similarity = SimilarProfileCandidate(
        profile_ref=profile_ref,
        metrics=ProfileSimilarityMetrics(1, 1, 1, 1, 1, 1),
    )
    target = agent_scanner.ScanTarget(repo_name="repo", commit_hash="abcd", similarity=similarity)

    agent_scanner._save_scan_outputs(tmp_path, finder, results, target)

    assert (tmp_path / "agentic_vuln_findings.json").exists()
    assert (tmp_path / "conversation_history.json").exists()
    assert (tmp_path / "target_similarity.json").exists()


def test_run_single_target_scan_success_restores_original_commit(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)

    checkout_calls = []

    def fake_checkout(repo_path, commit):
        checkout_calls.append(commit)
        return True

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "checkout_commit", fake_checkout)
    monkeypatch.setattr(agent_scanner, "load_software_profile", lambda *args, **kwargs: _mk_profile("target-repo", "targethash"))
    monkeypatch.setattr(agent_scanner, "detect_repo_language", lambda repo_path: "python")

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]

        def run(self):
            return {"vulnerabilities": [{"id": 1}]}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    args = Namespace(
        cve="CVE-2025-0001",
        output=str(tmp_path / "scan-out"),
        language=None,
        max_iterations=1,
        verbose=False,
    )
    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner._run_single_target_scan(
        args=args,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
    )

    assert ok is True
    assert checkout_calls[0] == "targethash1234"
    assert checkout_calls[-1] == "origcommit9999"


def test_run_single_target_scan_fails_when_profile_missing(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "orig")
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "load_software_profile", lambda *args, **kwargs: None)

    args = Namespace(
        cve="CVE-2025-0001",
        output=str(tmp_path / "scan-out"),
        language="python",
        max_iterations=1,
        verbose=False,
    )
    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner._run_single_target_scan(
        args=args,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
    )

    assert ok is False


def test_run_single_target_scan_passes_critical_stop_flag(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda repo_path: "origcommit9999")
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", "targethash"),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_language", lambda repo_path: "python")

    captured = {}

    class DummyFinder:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.conversation_history = [{"role": "assistant", "content": "done"}]

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    args = Namespace(
        cve="CVE-2025-0001",
        output=str(tmp_path / "scan-out"),
        language=None,
        max_iterations=2,
        stop_when_critical_complete=True,
        critical_stop_mode="min",
        verbose=False,
    )
    target = agent_scanner.ScanTarget(repo_name="target-repo", commit_hash="targethash1234")

    ok = agent_scanner._run_single_target_scan(
        args=args,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=target,
    )

    assert ok is True
    assert captured["stop_when_critical_complete"] is True
    assert captured["critical_stop_mode"] == "min"
