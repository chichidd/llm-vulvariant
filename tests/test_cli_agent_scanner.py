from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import pytest


import cli.agent_scanner as agent_scanner
from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME
from scanner.similarity.retriever import (
    ProfileRef,
    ProfileSimilarityMetrics,
    SimilarProfileCandidate,
)

TARGET_COMMIT = "a" * 40
ORIGINAL_COMMIT = "b" * 40


def _mk_profile(name: str, version: str = "", repo_analysis=None, metadata=None):
    repo_info = {"repo_analysis": repo_analysis} if isinstance(repo_analysis, dict) else {}
    return SoftwareProfile(
        name=name,
        version=version,
        repo_info=repo_info,
        modules=[ModuleInfo(name="m")],
        metadata=metadata or {},
    )


def _mk_complete_finder_memory(findings=0):
    return SimpleNamespace(
        get_progress=lambda: {
            "total_files": 1,
            "completed": 1,
            "pending": 0,
            "findings": findings,
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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("llm_max_attempts", 0),
        ("llm_timeout_seconds", 0.0),
        ("llm_timeout_seconds", float("inf")),
    ],
)
def test_validate_args_rejects_invalid_llm_retry_controls(field, value):
    args = _valid_evaluation_args(**{field: value})

    assert agent_scanner._validate_args(args) is False


def _endpoint_snapshot_binding():
    snapshot = {
        "snapshot_id": "deployment-2026-08-01-a",
        "base_url": "https://llm.shtech.org/v1",
        "api_family": "openai_compatible",
    }
    snapshot_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        snapshot,
        snapshot_json,
        hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest(),
    )


def _model_revision_attestation_binding(
    *,
    provider="lab",
    model_name="GLM-5.2",
    model_revision="revision-a",
    endpoint_snapshot_sha256=None,
    binding_path="rq2/inputs/model-revision-attestations/GLM-5.2.json",
    file_sha256="9" * 64,
):
    if endpoint_snapshot_sha256 is None:
        endpoint_snapshot_sha256 = _endpoint_snapshot_binding()[2]
    payload = {
        "schema_version": 1,
        "kind": "operator_attested_deployment_revision",
        "provider": provider,
        "model_name": model_name,
        "model_revision": model_revision,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
    }
    return {
        "payload": payload,
        "binding": {
            "path": binding_path,
            "file_sha256": file_sha256,
            "payload_sha256": agent_scanner.stable_data_hash(payload),
        },
    }


def _decoding_config_binding(**overrides):
    config = {
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 1024,
        "enable_thinking": None,
        "reasoning_effort": None,
        "service_tier": None,
    }
    config.update(overrides)
    config_json = json.dumps(
        config,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return (
        config,
        config_json,
        hashlib.sha256(config_json.encode("utf-8")).hexdigest(),
    )


def _evaluation_llm_config(
    *,
    provider="lab",
    model="GLM-5.2",
    model_revision="revision-a",
    base_url="https://llm.shtech.org/v1",
    decoding_overrides=None,
    fallback_on_retry_exhausted=False,
    enforce_exact_decoding=True,
    max_retries=3,
):
    config, _config_json, _config_sha256 = _decoding_config_binding(
        **(decoding_overrides or {})
    )
    return SimpleNamespace(
        **config,
        provider=provider,
        model=model,
        model_revision=model_revision,
        base_url=base_url,
        fallback_on_retry_exhausted=fallback_on_retry_exhausted,
        enforce_exact_decoding=enforce_exact_decoding,
        max_retries=max_retries,
        _explicit_config_fields=set(agent_scanner.DECODING_CONFIG_KEYS),
    )


def _evaluation_llm_client(**config_overrides):
    return SimpleNamespace(
        config=_evaluation_llm_config(**config_overrides),
        sdk_max_retries=0,
    )


def _valid_evaluation_args(**overrides):
    _snapshot, snapshot_json, snapshot_sha256 = _endpoint_snapshot_binding()
    _decoding, decoding_json, decoding_sha256 = (
        _decoding_config_binding()
    )
    values = {
        "vuln_repo": "source",
        "cve": "CVE-2026-0001",
        "target_repo": "target",
        "target_commit": "a" * 40,
        "top_k": 1,
        "evaluation_mode": True,
        "llm_provider": "lab",
        "llm_name": "GLM-5.2",
        "llm_max_attempts": 3,
        "model_revision": "model-revision-2026-08-01",
        "model_revision_attestation": (
            "/run/input-snapshots/model-revision-attestation.json"
        ),
        "model_revision_attestation_sha256": "9" * 64,
        "model_revision_attestation_binding_path": (
            "rq2/inputs/model-revision-attestations/GLM-5.2.json"
        ),
        "endpoint_snapshot_json": snapshot_json,
        "endpoint_snapshot_sha256": snapshot_sha256,
        "decoding_config_json": decoding_json,
        "decoding_config_sha256": decoding_sha256,
        "target_path_projection": "/run/input-snapshots/projection.json",
        "target_path_projection_sha256": "b" * 64,
        "target_path_projection_binding_path": (
            "rq2/inputs/target-path-projections/target/"
            + "a" * 40
            + "/projection.json"
        ),
        "model_input_invariant_stage_sha256": "c" * 64,
        "model_input_policy_stage_sha256": "d" * 64,
        "target_software_profile_sha256": "e" * 64,
        "reference_card": "/run/input-snapshots/reference.json",
        "reference_card_sha256": "f" * 64,
        "reference_card_binding_path": "rq2/inputs/reference-cards/card.json",
        "ablate_candidate_priority": False,
    }
    values.update(overrides)
    return Namespace(**values)


def _main_frozen_control_args(tmp_path, **overrides):
    values = {
        "verbose": False,
        "vuln_repo": "source",
        "cve": "CVE-2026-0001",
        "target_repo": "target",
        "target_commit": "a" * 40,
        "output": str(tmp_path / "scan-out"),
        "run_id": "preflight-run-a",
        "max_iterations": 3,
        "llm_provider": "lab",
        "llm_name": "model-x",
        "model_revision": None,
        "model_revision_attestation": None,
        "model_revision_attestation_sha256": None,
        "model_revision_attestation_binding_path": None,
        "endpoint_snapshot_json": None,
        "endpoint_snapshot_sha256": None,
        "decoding_config_json": None,
        "decoding_config_sha256": None,
        "reference_card": None,
        "reference_card_sha256": None,
        "reference_card_binding_path": None,
        "target_path_projection": None,
        "target_path_projection_sha256": None,
        "target_path_projection_binding_path": None,
        "target_software_profile_sha256": None,
        "unprioritized_file_order": None,
        "unprioritized_file_order_sha256": None,
        "unprioritized_file_order_binding_path": None,
        "model_input_invariant_stage_sha256": None,
        "model_input_policy_stage_sha256": None,
        "evaluation_mode": False,
        "ablate_repo_semantics": False,
        "ablate_reference_semantics": False,
        "ablate_candidate_priority": False,
        "ablate_memory": False,
        "ablate_verifier": False,
    }
    values.update(overrides)
    return Namespace(**values)


def _assert_durable_preflight_failure(
    output_base,
    *,
    cve_id="CVE-2026-0001",
    repo_name="target",
    commit_hash="a" * 40,
    termination="evaluation_precheck_failure",
    stage="evaluation_precheck",
):
    paths = list(Path(output_base).rglob("run_failure.json"))
    assert paths == [
        Path(output_base)
        / cve_id
        / f"{repo_name}-{commit_hash[:12]}"
        / "run_failure.json"
    ]
    payload = json.loads(paths[0].read_text(encoding="utf-8"))
    assert payload["kind"] == "scanner_run"
    assert payload["repo"] == {
        "name": repo_name,
        "requested_commit": commit_hash,
        "actual_commit": None,
    }
    assert payload["execution"]["stage"] == stage
    assert payload["execution"]["status"] == "failed"
    assert payload["execution"]["partial"] is False
    assert payload["execution"]["termination"] == termination
    assert payload["scan_fingerprint"] is None
    assert payload["coverage"] is None
    assert payload["usage"] is None
    assert payload["input_hashes"]["target_software_profile"] is None
    assert (
        payload["input_hashes"]["target_software_profile_artifact"]
        is None
    )
    assert not list(Path(output_base).rglob("agentic_vuln_findings.json"))
    assert not list(Path(output_base).rglob("conversation_history.json"))
    assert not list(Path(output_base).rglob("results.json"))
    assert not list(Path(output_base).rglob("conversation.json"))
    assert not list(Path(output_base).rglob("scan_memory.json"))
    return payload


def test_validate_args_requires_exact_model_revision_in_evaluation_mode():
    assert agent_scanner._validate_args(_valid_evaluation_args()) is True
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(model_revision=None)
        )
        is False
    )
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(model_revision="")
        )
        is False
    )
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(model_revision=" revision-with-space ")
        )
        is False
    )


def test_validate_args_requires_exact_model_name_and_complete_attestation():
    assert agent_scanner._validate_args(_valid_evaluation_args()) is True
    for invalid_name in (None, "", " model-x "):
        assert (
            agent_scanner._validate_args(
                _valid_evaluation_args(llm_name=invalid_name)
            )
            is False
        )
    for field in (
        "model_revision_attestation",
        "model_revision_attestation_sha256",
        "model_revision_attestation_binding_path",
    ):
        assert (
            agent_scanner._validate_args(
                _valid_evaluation_args(**{field: None})
            )
            is False
        )
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(
                model_revision_attestation_sha256=("A" * 64)
            )
        )
        is False
    )
    for invalid_path in (
        "/absolute/attestation.json",
        "../attestation.json",
        "./attestation.json",
        "rq2\\attestation.json",
    ):
        assert (
            agent_scanner._validate_args(
                _valid_evaluation_args(
                    model_revision_attestation_binding_path=invalid_path
                )
            )
            is False
        )


def test_validate_args_requires_canonical_endpoint_snapshot_in_evaluation_mode():
    assert agent_scanner._validate_args(_valid_evaluation_args()) is True
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(endpoint_snapshot_json=None)
        )
        is False
    )
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(endpoint_snapshot_sha256=None)
        )
        is False
    )

    _snapshot, snapshot_json, snapshot_sha256 = _endpoint_snapshot_binding()
    noncanonical = json.dumps(json.loads(snapshot_json), indent=2)
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(
                endpoint_snapshot_json=noncanonical,
                endpoint_snapshot_sha256=hashlib.sha256(
                    noncanonical.encode("utf-8")
                ).hexdigest(),
            )
        )
        is False
    )
    assert (
        agent_scanner._validate_args(
            _valid_evaluation_args(
                endpoint_snapshot_sha256=snapshot_sha256.upper(),
            )
        )
        is False
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_url", "http://api.example.invalid/v1"),
        ("base_url", "https://user:secret@api.example.invalid/v1"),
        ("base_url", "https://api.example.invalid/v1?token=secret"),
        ("base_url", "https://api.example.invalid/v1#fragment"),
        ("base_url", "https://api.example.invalid/v1/"),
        ("base_url", "https://api.example.invalid:443/v1"),
        ("api_family", "unknown_family"),
        ("snapshot_id", "latest"),
    ],
)
def test_endpoint_snapshot_rejects_mutable_or_noncanonical_identity_without_echoing_secrets(
    field,
    value,
):
    snapshot, _snapshot_json, _snapshot_sha256 = _endpoint_snapshot_binding()
    snapshot[field] = value
    snapshot_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    snapshot_sha256 = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()

    with pytest.raises(ValueError) as exc_info:
        agent_scanner.validate_endpoint_snapshot_contract(
            snapshot_json,
            snapshot_sha256,
        )

    assert "secret" not in str(exc_info.value)


def test_endpoint_snapshot_localhost_http_exception_is_test_only():
    snapshot, _snapshot_json, _snapshot_sha256 = _endpoint_snapshot_binding()
    snapshot["base_url"] = "http://localhost:8080/v1"
    snapshot_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    snapshot_sha256 = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()

    with pytest.raises(ValueError, match="base_url"):
        agent_scanner.validate_endpoint_snapshot_contract(
            snapshot_json,
            snapshot_sha256,
        )
    validated, validated_sha256 = (
        agent_scanner.validate_endpoint_snapshot_contract(
            snapshot_json,
            snapshot_sha256,
            allow_localhost_http=True,
        )
    )
    assert validated == snapshot
    assert validated_sha256 == snapshot_sha256


def test_validate_args_requires_canonical_logical_binding_paths_in_evaluation_mode():
    assert agent_scanner._validate_args(_valid_evaluation_args()) is True

    for field in (
        "target_path_projection_binding_path",
        "reference_card_binding_path",
    ):
        args = _valid_evaluation_args(**{field: None})
        assert agent_scanner._validate_args(args) is False

    for invalid in (
        "/absolute/projection.json",
        "../projection.json",
        "./projection.json",
        "rq2\\projection.json",
        "rq2//projection.json",
    ):
        args = _valid_evaluation_args(
            target_path_projection_binding_path=invalid
        )
        assert agent_scanner._validate_args(args) is False


def test_validate_args_requires_schedule_binding_for_unprioritized_policy_stage():
    args = _valid_evaluation_args(
        ablate_candidate_priority=True,
        unprioritized_file_order="/run/input-snapshots/order.json",
        unprioritized_file_order_sha256="1" * 64,
        unprioritized_file_order_binding_path="rq2/inputs/orders/order.json",
    )
    assert agent_scanner._validate_args(args) is True
    args.unprioritized_file_order_binding_path = None
    assert agent_scanner._validate_args(args) is False


def test_validate_args_requires_frozen_file_order_for_candidate_priority_ablation():
    args = Namespace(
        vuln_repo="source",
        cve="CVE-2026-0001",
        target_repo="repo",
        target_commit=None,
        top_k=1,
        ablate_candidate_priority=True,
    )

    assert agent_scanner._validate_args(args) is False


def test_validate_args_requires_raw_target_profile_sha_for_candidate_ablation():
    args = Namespace(
        vuln_repo="source",
        cve="CVE-2026-0001",
        target_repo="repo",
        target_commit="a" * 40,
        top_k=1,
        ablate_candidate_priority=True,
        unprioritized_file_order="schedule.json",
        unprioritized_file_order_sha256="b" * 64,
        target_software_profile_sha256="c" * 64,
    )

    assert agent_scanner._validate_args(args) is True
    args.target_software_profile_sha256 = None
    assert agent_scanner._validate_args(args) is False
    args.target_software_profile_sha256 = "C" * 64
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


def test_resolve_output_dir_uses_revision_results_default_when_output_base_is_omitted(
    monkeypatch, tmp_path
):
    revision_root = tmp_path / "ccs-revision"
    repo_root = revision_root / "code" / "llm-vulvariant"
    repo_root.mkdir(parents=True)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", repo_root)
    monkeypatch.setitem(agent_scanner._path_config, "project_root", revision_root)
    monkeypatch.setitem(
        agent_scanner._path_config,
        "results_base_path",
        revision_root / "results",
    )

    resolved = agent_scanner.resolve_output_dir(
        cve_id="CVE-2026-0001",
        target_repo="demo",
        target_commit="a" * 40,
        output_base=None,
    )

    assert resolved == (
        revision_root
        / "results"
        / "scan-results"
        / "CVE-2026-0001"
        / "demo-aaaaaaaaaaaa"
    )


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
    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )
    profile_repo_path = Path("/tmp/target-profile").resolve()
    software_profile = _mk_profile(
        "target-repo",
        version=TARGET_COMMIT,
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
        "python": f"target-repo-{expected_path_hash}-{TARGET_COMMIT[:8]}-python",
        "javascript": f"target-repo-{expected_path_hash}-{TARGET_COMMIT[:8]}-javascript",
    }


def test_save_scan_outputs_writes_similarity_file(tmp_path):
    finder = SimpleNamespace(
        conversation_history=[{"role": "assistant", "content": "ok"}],
        memory=_mk_complete_finder_memory(),
        critical_stop_max_priority=2,
        require_full_universe_completion=True,
        _is_full_universe_complete=lambda: True,
    )
    results = {"vulnerabilities": []}
    fingerprint_payload = {
        "schema_version": 1,
        "kind": "scan_result",
        "scan_config": {"run_id": "run-1"},
    }
    scan_fingerprint = {
        **fingerprint_payload,
        "hash": agent_scanner.stable_data_hash(fingerprint_payload),
    }
    run_provenance = {
        "reference_id": "CVE-2026-0001",
        "run_id": "run-1",
        "repo": {
            "name": "repo",
            "requested_commit": "a" * 40,
            "actual_commit": "a" * 40,
        },
        "execution": {
            "status": "complete",
            "termination": "finished",
            "partial": False,
            "failure_reason": None,
        },
        "coverage": agent_scanner._build_scan_quality_metadata(finder),
        "scan_fingerprint": dict(scan_fingerprint),
    }

    profile_ref = ProfileRef(
        "repo",
        "a" * 40,
        _mk_profile("repo", version="a" * 40),
    )
    similarity = SimilarProfileCandidate(
        profile_ref=profile_ref,
        metrics=ProfileSimilarityMetrics(1, 1, 1, 1, 1, 1),
    )
    target = agent_scanner.ScanTarget(
        repo_name="repo",
        commit_hash="a" * 40,
        similarity=similarity,
    )

    marker = agent_scanner._save_scan_outputs(
        tmp_path,
        finder,
        results,
        target,
        scan_fingerprint=scan_fingerprint,
        run_provenance=run_provenance,
    )

    assert (tmp_path / "agentic_vuln_findings.json").exists()
    assert (tmp_path / "conversation_history.json").exists()
    assert (tmp_path / "target_similarity.json").exists()
    assert (tmp_path / "scan_output_commit.json").exists()
    payload = json.loads((tmp_path / "agentic_vuln_findings.json").read_text(encoding="utf-8"))
    assert payload["coverage_status"] == "complete"
    provenance_payload = json.loads(
        (tmp_path / "run_provenance.json").read_text(encoding="utf-8")
    )
    assert (
        payload["scan_fingerprint"]
        == payload["run_provenance"]["scan_fingerprint"]
        == provenance_payload["scan_fingerprint"]
        == scan_fingerprint
    )
    validated = agent_scanner.validate_committed_scan_outputs(
        tmp_path,
        expected_commit_sha256=marker["sha256"],
    )
    assert validated["headline_eligible"] is True
    assert not (tmp_path / "scan_fingerprint.json").exists()
    assert not (tmp_path / "run_state.json").exists()
    assert not (tmp_path / "run_failure.json").exists()


@pytest.mark.parametrize(
    "provenance_fingerprint",
    [None, {"schema_version": 1, "hash": "replacement"}],
)
def test_save_scan_outputs_rejects_missing_or_replaced_provenance_fingerprint(
    tmp_path,
    provenance_fingerprint,
):
    fingerprint_payload = {
        "schema_version": 1,
        "kind": "scan_result",
        "scan_config": {"run_id": "run-1"},
    }
    scan_fingerprint = {
        **fingerprint_payload,
        "hash": agent_scanner.stable_data_hash(fingerprint_payload),
    }
    run_provenance = {
        "run_id": "run-1",
        "execution": {"status": "complete"},
        "scan_fingerprint": provenance_fingerprint,
    }

    with pytest.raises(
        ValueError,
        match="scan fingerprint mismatch between findings and run provenance",
    ):
        agent_scanner._save_scan_outputs(
            tmp_path,
            SimpleNamespace(conversation_history=[]),
            {"vulnerabilities": []},
            agent_scanner.ScanTarget(repo_name="repo", commit_hash="abcd"),
            scan_fingerprint=scan_fingerprint,
            run_provenance=run_provenance,
        )

    assert not (tmp_path / "agentic_vuln_findings.json").exists()
    assert not (tmp_path / "run_provenance.json").exists()
    assert not (tmp_path / "conversation_history.json").exists()
    assert not (tmp_path / "scan_output_commit.json").exists()


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


def test_build_scan_quality_metadata_keeps_zero_scope_unresolved_with_progress():
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

    assert metadata["coverage_status"] == "partial"
    assert metadata["critical_scope_present"] is False
    assert metadata["critical_complete"] is False
    assert metadata["critical_scope_total_files"] == 0
    assert metadata["critical_scope_completed_files"] == 0


def test_build_scan_quality_metadata_keeps_affected_only_empty_scope_unresolved():
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

    assert metadata["coverage_status"] == "empty"
    assert metadata["critical_scope_present"] is False
    assert metadata["critical_complete"] is False


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
        reference_context_provenance={"artifact_sha256": "ref-hash"},
        unprioritized_file_schedule={
            "files": ["a.py"],
            "provenance": {
                "order_sha256": "order-hash",
                "target_software_profile_sha256": "b" * 64,
            },
        },
        run_id="run-7",
    )

    assert "scanner/agent/utils.py" in fingerprint["source_hashes"]
    assert fingerprint["source_hashes"]["scanner/agent/utils.py"]
    assert "utils/codeql_native.py" in fingerprint["source_hashes"]
    assert fingerprint["source_hashes"]["utils/codeql_native.py"]
    assert "scanner/agent/shared_memory.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_fs.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_codeql.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_reporting.py" in fingerprint["source_hashes"]
    assert "scanner/agent/toolkit_profile.py" in fingerprint["source_hashes"]
    assert "scanner/similarity/retriever.py" in fingerprint["source_hashes"]
    assert "scanner/similarity/embedding.py" in fingerprint["source_hashes"]
    for source_path in (
        "llm/__init__.py",
        "llm/client.py",
        "llm/tool_arguments.py",
        "utils/llm_usage.py",
        "utils/claude_cli.py",
        "utils/number_utils.py",
    ):
        assert source_path in fingerprint["source_hashes"]
        assert fingerprint["source_hashes"][source_path]
    assert "config.py" in fingerprint["source_hashes"]
    assert "config_snapshot.py" in fingerprint["source_hashes"]
    assert "source_snapshot.py" in fingerprint["source_hashes"]
    assert "scanner/evaluation_contract.py" in fingerprint["source_hashes"]
    assert set(fingerprint["config_hashes"]) == {
        "paths.yaml",
        "scanner_config.yaml",
        "codeql_config.yaml",
        "llm_config.yaml",
    }
    assert all(fingerprint["config_hashes"].values())
    assert (
        fingerprint["config_hashes"]
        == agent_scanner._scanner_config_hashes()
    )
    assert fingerprint["scan_config"]["run_id"] == "run-7"
    assert fingerprint["scan_config"]["reference_context"]["artifact_sha256"] == "ref-hash"
    assert fingerprint["target_software_profile_artifact_sha256"] == "b" * 64
    assert fingerprint["scan_config"]["unprioritized_file_schedule"]["files"] == ["a.py"]


def _write_isolated_scanner_config_fixture(tmp_path):
    stage_root = Path(__file__).resolve().parents[1]
    revision_root = stage_root.parents[1]
    fixture_root = tmp_path / "config"
    fixture_root.mkdir()
    project_root_rel = Path(
        os.path.relpath(revision_root, fixture_root)
    ).as_posix()
    repo_root_rel = Path(
        os.path.relpath(stage_root, fixture_root)
    ).as_posix()
    # Default scanner paths must stay inside the revision root, but pytest's
    # temporary directory is not required to live there. These paths are only
    # parsed by the isolated subprocess and are never materialized.
    output_rel = f"results/test-config-fixtures/{tmp_path.name}"
    (fixture_root / "paths.yaml").write_text(
        "\n".join(
            (
                "paths:",
                f'  project_root: "{project_root_rel}"',
                f'  repo_root: "{repo_root_rel}"',
                f'  results_base_path: "{output_rel}/results"',
                f'  profile_base_path: "{output_rel}/profiles"',
                f'  data_base_path: "{output_rel}/data"',
                f'  vuln_data_path: "{output_rel}/data/vuln.json"',
                f'  repo_base_path: "{output_rel}/repos"',
                f'  codeql_db_path: "{output_rel}/codeql-dbs"',
                f'  embedding_model_path: "{output_rel}/models"',
                "",
            )
        ),
        encoding="utf-8",
    )
    for filename in (
        "scanner_config.yaml",
        "codeql_config.yaml",
        "llm_config.yaml",
    ):
        (fixture_root / filename).write_bytes(
            (stage_root / "config" / filename).read_bytes()
        )
    return stage_root, fixture_root


def test_scanner_config_generation_rejects_cross_file_mix(
    tmp_path,
    monkeypatch,
):
    import config_snapshot

    config_root = tmp_path / "config"
    config_root.mkdir()
    source_root = Path(config_snapshot.__file__).resolve().parents[1] / "config"
    for filename in config_snapshot.SCANNER_CONFIG_FILENAMES:
        (config_root / filename).write_bytes(
            (source_root / filename).read_bytes()
        )
    monkeypatch.setattr(config_snapshot, "SCANNER_CONFIG_ROOT", config_root)
    monkeypatch.setattr(config_snapshot, "_CONSUMED_SCANNER_CONFIGS", {})
    original_read = config_snapshot._read_regular_file_snapshot
    mutated = False

    def mutate_first_file_while_reading_second(path, *, label):
        nonlocal mutated
        snapshot = original_read(path, label=label)
        if label == "scanner_config.yaml" and not mutated:
            paths_file = config_root / "paths.yaml"
            paths_file.write_bytes(
                paths_file.read_bytes() + b"\n# hostile generation drift\n"
            )
            mutated = True
        return snapshot

    monkeypatch.setattr(
        config_snapshot,
        "_read_regular_file_snapshot",
        mutate_first_file_while_reading_second,
    )

    with pytest.raises(
        config_snapshot.ConfigSnapshotDriftError,
        match="paths.yaml changed across scanner config generation",
    ):
        config_snapshot.freeze_scanner_config_files()
    assert config_snapshot._CONSUMED_SCANNER_CONFIGS == {}


@pytest.mark.parametrize(
    "mutated_filename",
    (
        "paths.yaml",
        "scanner_config.yaml",
        "codeql_config.yaml",
        "llm_config.yaml",
    ),
)
def test_consumed_config_hashes_reject_post_import_byte_drift(
    tmp_path,
    mutated_filename,
):
    stage_root, fixture_root = _write_isolated_scanner_config_fixture(
        tmp_path
    )

    script = r'''import hashlib
import json
from pathlib import Path
import sys

import config_snapshot

config_root = Path(sys.argv[1])
mutated_filename = sys.argv[2]
config_snapshot.SCANNER_CONFIG_ROOT = config_root

import config
from llm.client import LLMConfig
from utils.codeql_native import load_codeql_config

LLMConfig(
    provider="fixture",
    model="fixture-model",
    api_key="fixture-key",
    base_url="https://example.invalid/v1",
)
load_codeql_config()
before = config_snapshot.consumed_scanner_config_hashes()
expected = {
    filename: hashlib.sha256((config_root / filename).read_bytes()).hexdigest()
    for filename in config_snapshot.SCANNER_CONFIG_FILENAMES
}
assert before == expected
assert config._config_snapshot_hashes == before

mutated_path = config_root / mutated_filename
mutated_path.write_bytes(mutated_path.read_bytes() + b"\n# hostile drift\n")
if mutated_filename == "paths.yaml":
    public_loader = config.load_paths_config
elif mutated_filename == "scanner_config.yaml":
    public_loader = config.load_scanner_config
elif mutated_filename == "codeql_config.yaml":
    public_loader = load_codeql_config
else:
    public_loader = lambda: LLMConfig(
        provider="fixture",
        model="fixture-model",
        api_key="fixture-key",
        base_url="https://example.invalid/v1",
    )
try:
    public_loader()
except Exception:
    pass
else:
    raise AssertionError("default public loader accepted post-freeze drift")
try:
    config_snapshot.consumed_scanner_config_hashes()
except config_snapshot.ConfigSnapshotDriftError as exc:
    immutable = config_snapshot.immutable_consumed_scanner_config_hashes()
    print(json.dumps({
        "before": before,
        "immutable": immutable,
        "reason": str(exc),
    }, sort_keys=True))
else:
    raise AssertionError("post-import config mutation was accepted")
'''
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(stage_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(fixture_root),
            mutated_filename,
        ],
        cwd=stage_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    lines = [line for line in completed.stdout.splitlines() if line]
    payload = json.loads(lines[-1])
    assert payload["immutable"] == payload["before"]
    assert mutated_filename in payload["reason"]


@pytest.mark.parametrize(
    ("loader_name", "filename"),
    (
        ("llm", "llm_config.yaml"),
        ("codeql", "codeql_config.yaml"),
    ),
)
@pytest.mark.parametrize(
    "mutation",
    ("missing", "same_bytes_replacement", "symlink_swap"),
)
def test_default_yaml_loader_rejects_missing_or_replaced_frozen_file(
    tmp_path,
    loader_name,
    filename,
    mutation,
):
    stage_root, fixture_root = _write_isolated_scanner_config_fixture(
        tmp_path
    )
    script = r'''import json
from pathlib import Path
import sys

import config_snapshot

config_root = Path(sys.argv[1])
loader_name = sys.argv[2]
filename = sys.argv[3]
mutation = sys.argv[4]
config_snapshot.SCANNER_CONFIG_ROOT = config_root

import config
from llm.client import load_llm_config_from_yaml
from utils.codeql_native import load_codeql_config

before = config_snapshot.immutable_consumed_scanner_config_hashes()
target = config_root / filename
backup = config_root / (filename + ".original")
raw_bytes = target.read_bytes()
target.rename(backup)
if mutation == "same_bytes_replacement":
    target.write_bytes(raw_bytes)
elif mutation == "symlink_swap":
    target.symlink_to(backup.name)

loader = (
    load_llm_config_from_yaml
    if loader_name == "llm"
    else load_codeql_config
)
try:
    loader()
except RuntimeError as exc:
    reason = str(exc)
else:
    raise AssertionError("unsafe default-config fallback was accepted")
finally:
    if target.is_symlink() or target.exists():
        target.unlink()
    backup.rename(target)

print(json.dumps({
    "before": before,
    "immutable": config_snapshot.immutable_consumed_scanner_config_hashes(),
    "reason": reason,
}, sort_keys=True))
'''
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(stage_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(fixture_root),
            loader_name,
            filename,
            mutation,
        ],
        cwd=stage_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.splitlines()[-1])
    assert payload["immutable"] == payload["before"]
    assert filename in payload["reason"]


@pytest.mark.parametrize(
    ("loader_name", "filename"),
    (
        ("llm", "llm_config.yaml"),
        ("codeql", "codeql_config.yaml"),
    ),
)
def test_default_yaml_loader_rejects_same_byte_replacement_during_parse(
    tmp_path,
    loader_name,
    filename,
):
    stage_root, fixture_root = _write_isolated_scanner_config_fixture(
        tmp_path
    )
    script = r'''import json
from pathlib import Path
import sys

import yaml
import config_snapshot

config_root = Path(sys.argv[1])
loader_name = sys.argv[2]
filename = sys.argv[3]
config_snapshot.SCANNER_CONFIG_ROOT = config_root

import config
from llm.client import load_llm_config_from_yaml
from utils.codeql_native import load_codeql_config

before = config_snapshot.immutable_consumed_scanner_config_hashes()
target = config_root / filename
backup = config_root / (filename + ".original")
raw_bytes = target.read_bytes()
original_safe_load = yaml.safe_load
replaced = False

def replace_after_parse(value):
    global replaced
    parsed = original_safe_load(value)
    if not replaced:
        target.rename(backup)
        target.write_bytes(raw_bytes)
        replaced = True
    return parsed

yaml.safe_load = replace_after_parse
loader = (
    load_llm_config_from_yaml
    if loader_name == "llm"
    else load_codeql_config
)
try:
    loader()
except RuntimeError as exc:
    reason = str(exc)
else:
    raise AssertionError("same-byte replacement during parse was accepted")
finally:
    if target.exists():
        target.unlink()
    backup.rename(target)

print(json.dumps({
    "before": before,
    "immutable": config_snapshot.immutable_consumed_scanner_config_hashes(),
    "reason": reason,
}, sort_keys=True))
'''
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(stage_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(fixture_root),
            loader_name,
            filename,
        ],
        cwd=stage_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.splitlines()[-1])
    assert payload["immutable"] == payload["before"]
    assert "identity changed" in payload["reason"]


@pytest.mark.parametrize(
    ("filename", "parse_index"),
    (("paths.yaml", 0), ("scanner_config.yaml", 1)),
)
def test_import_config_rejects_same_byte_replacement_during_parse(
    tmp_path,
    filename,
    parse_index,
):
    stage_root, fixture_root = _write_isolated_scanner_config_fixture(
        tmp_path
    )
    script = r'''import json
from pathlib import Path
import sys

import yaml
import config_snapshot

config_root = Path(sys.argv[1])
filename = sys.argv[2]
parse_index = int(sys.argv[3])
config_snapshot.SCANNER_CONFIG_ROOT = config_root
target = config_root / filename
backup = config_root / (filename + ".original")
raw_bytes = target.read_bytes()
original_load = yaml.load
calls = 0

def replace_after_selected_parse(value, *args, **kwargs):
    global calls
    parsed = original_load(value, *args, **kwargs)
    if calls == parse_index:
        target.rename(backup)
        target.write_bytes(raw_bytes)
    calls += 1
    return parsed

yaml.load = replace_after_selected_parse
try:
    import config  # noqa: F401
except config_snapshot.ConfigSnapshotDriftError as exc:
    reason = str(exc)
else:
    raise AssertionError("same-byte import-time replacement was accepted")
finally:
    if target.exists():
        target.unlink()
    backup.rename(target)

print(json.dumps({"reason": reason}, sort_keys=True))
'''
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = str(stage_root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(fixture_root),
            filename,
            str(parse_index),
        ],
        cwd=stage_root,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.splitlines()[-1])
    assert filename in payload["reason"]
    assert "identity changed" in payload["reason"]


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
        lambda model_name: {
            "resolved_model_path": f"/models/{model_name}",
            "artifact_hash": f"artifact::{model_name}",
        },
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
        "resolved_model_path": "/models/mini-model",
        "artifact_hash": "artifact::mini-model",
    }
    assert fingerprint["scan_config"][
        "module_similarity_byte_binding"
    ] == {
        "status": "unattested",
        "blocker_code": "consumed-embedding-bytes-unattested",
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
    lifecycle_events = []

    def fake_checkout(repo_path, commit):
        checkout_calls.append(commit)
        lifecycle_events.append("checkout")
        return True

    restore_calls = []

    def fake_restore(repo_path, restore_target):
        restore_calls.append(restore_target)
        return True

    def fake_get_git_commit(repo_path):
        _ = repo_path
        if checkout_calls:
            lifecycle_events.append("record_target_commit")
            return TARGET_COMMIT
        lifecycle_events.append("read_original_commit")
        return ORIGINAL_COMMIT

    monkeypatch.setattr(agent_scanner, "get_git_commit", fake_get_git_commit)
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
        lambda *args, **kwargs: (
            lifecycle_events.append("load_profile"),
            _mk_profile("target-repo", TARGET_COMMIT),
        )[1],
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory(findings=1)

        def run(self):
            return {"vulnerabilities": [{"id": 1}]}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
    assert captured_lock["purpose"] == (
        f"agent_scan:CVE-2025-0001:{TARGET_COMMIT[:12]}"
    )
    assert checkout_calls[0] == TARGET_COMMIT
    assert lifecycle_events.index("record_target_commit") < lifecycle_events.index("load_profile")
    assert restore_calls == ["master"]


def test_run_single_target_scan_uses_attempt_unique_shared_memory_producer_id(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    checkout_calls = []
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: TARGET_COMMIT if checkout_calls else ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda repo_path, restore_target: True)
    monkeypatch.setattr(
        agent_scanner,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )

    @contextmanager
    def fake_hold_repo_lock(repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        yield

    monkeypatch.setattr(agent_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", TARGET_COMMIT),
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
            self.memory = _mk_complete_finder_memory(findings=1)

        def run(self):
            return {"vulnerabilities": [{"id": 1}]}

    monkeypatch.setattr(agent_scanner, "SharedPublicMemoryManager", DummySharedPublicMemoryManager)
    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
    target_output_commit = "c" * 40

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

    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: TARGET_COMMIT if checkout_calls else None,
    )
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
        lambda *args, **kwargs: _mk_profile("target-repo", TARGET_COMMIT),
    )
    monkeypatch.setattr(agent_scanner, "detect_repo_languages", lambda repo_path: ["python"])

    class DummyFinder:
        def __init__(self, **kwargs):
            self.conversation_history = [{"role": "assistant", "content": "done"}]
            self.memory = _mk_complete_finder_memory()

        def run(self):
            return {"vulnerabilities": []}

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", DummyFinder)

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
    assert checkout_calls == [TARGET_COMMIT]
    assert restore_calls == ["main"]


def test_run_single_target_scan_refuses_checkout_without_restore_target(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)

    checkout_calls = []

    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: None)
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(
        agent_scanner,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: TARGET_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("dirty repo should fail before loading profile")),
    )

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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


def test_candidate_ablation_rejects_profile_mutation_before_finder(
    monkeypatch, tmp_path
):
    commit_hash = "a" * 40
    repo_base = tmp_path / "repos"
    (repo_base / "target-repo").mkdir(parents=True)
    profile_base = tmp_path / "profiles"
    profile_path = (
        profile_base
        / "soft"
        / "target-repo"
        / commit_hash
        / "software_profile.json"
    )
    profile_path.parent.mkdir(parents=True)
    frozen_profile = SoftwareProfile(
        name="target-repo",
        version=commit_hash,
        description="frozen semantics",
        modules=[ModuleInfo(name="module", files=["src/a.py"])],
    ).to_dict()
    frozen_bytes = json.dumps(
        frozen_profile,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected_profile_sha256 = hashlib.sha256(frozen_bytes).hexdigest()

    mutated_profile = json.loads(frozen_bytes.decode("utf-8"))
    mutated_profile["basic_info"]["description"] = "mutated after preflight"
    profile_path.write_text(
        json.dumps(mutated_profile, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    monkeypatch.setattr(agent_scanner, "get_git_commit", lambda _path: commit_hash)
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda _path: "main")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda _path: False)

    @contextmanager
    def fake_hold_repo_lock(_repo_path, *, purpose, run_id=None, poll_interval_seconds=0.2):
        _ = (purpose, run_id, poll_interval_seconds)
        yield

    monkeypatch.setattr(agent_scanner, "hold_repo_lock", fake_hold_repo_lock)
    monkeypatch.setattr(agent_scanner, "_write_run_provenance", lambda *_args, **_kwargs: None)
    finder_calls = []

    def fail_if_finder_runs(**_kwargs):
        finder_calls.append(True)
        raise AssertionError("finder must not receive a post-preflight mutated profile")

    monkeypatch.setattr(agent_scanner, "AgenticVulnFinder", fail_if_finder_runs)
    schedule_files = ["src/a.py"]
    schedule = {
        "files": schedule_files,
        "provenance": {
            "target_software_profile_sha256": expected_profile_sha256,
            "universe_sha256": agent_scanner.stable_data_hash(
                sorted(schedule_files)
            ),
            "order_sha256": agent_scanner.stable_data_hash(schedule_files),
        },
    }

    ok = agent_scanner.run_single_target_scan(
        cve_id="CVE-2026-0001",
        output_base=tmp_path / "scan-out",
        repo_base_path=repo_base,
        max_iterations=1,
        vulnerability_profile=SimpleNamespace(),
        llm_client=object(),
        target=agent_scanner.ScanTarget("target-repo", commit_hash),
        profile_base_path=str(profile_base),
        software_profile_dirname="soft",
        ablation_config={"candidate_priority": True},
        unprioritized_file_schedule=schedule,
    )

    assert ok is False
    assert finder_calls == []


def test_hash_bound_profile_uses_one_snapshot_and_rejects_duplicate_keys(
    monkeypatch, tmp_path
):
    commit_hash = "a" * 40
    profile_root = tmp_path / "soft"
    profile_path = (
        profile_root / "target-repo" / commit_hash / "software_profile.json"
    )
    profile_path.parent.mkdir(parents=True)
    payload = SoftwareProfile(
        name="target-repo",
        version=commit_hash,
        modules=[ModuleInfo(name="module", files=["src/a.py"])],
    ).to_dict()
    raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    profile_path.write_bytes(raw_bytes)
    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    original_read_bytes = Path.read_bytes
    read_count = 0

    def adversarial_read_bytes(path):
        nonlocal read_count
        if path.resolve() != profile_path.resolve():
            return original_read_bytes(path)
        read_count += 1
        return raw_bytes if read_count == 1 else b'{}'

    monkeypatch.setattr(Path, "read_bytes", adversarial_read_bytes)
    loaded = agent_scanner._load_hash_bound_software_profile(
        repo_name="target-repo",
        commit_hash=commit_hash,
        base_dir=profile_root,
        expected_sha256=expected_sha256,
    )

    assert loaded.to_dict() == payload
    assert read_count == 1

    monkeypatch.setattr(Path, "read_bytes", original_read_bytes)
    duplicate_bytes = (
        b'{"basic_info":{"name":"target-repo","version":"'
        + commit_hash.encode("ascii")
        + b'"},"basic_info":{},"modules":[]}'
    )
    profile_path.write_bytes(duplicate_bytes)
    with pytest.raises(ValueError, match="duplicate JSON key.*basic_info"):
        agent_scanner._load_hash_bound_software_profile(
            repo_name="target-repo",
            commit_hash=commit_hash,
            base_dir=profile_root,
            expected_sha256=hashlib.sha256(duplicate_bytes).hexdigest(),
        )


def test_run_single_target_scan_passes_critical_stop_flag(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    checkout_calls = []
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: TARGET_COMMIT if checkout_calls else ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile(
            "target-repo",
            TARGET_COMMIT,
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

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
    assert captured["endpoint_snapshot"] is None
    assert captured["decoding_config_requested"] is None
    assert captured["decoding_config_effective"] is None
    assert captured["languages"] == ["python", "javascript"]
    expected_path_hash = agent_scanner.stable_data_hash(str(Path("/tmp/target-profile").resolve()))[:12]
    assert captured["codeql_database_names"] == {
            "python": f"target-repo-{expected_path_hash}-{TARGET_COMMIT[:8]}-python",
            "javascript": f"target-repo-{expected_path_hash}-{TARGET_COMMIT[:8]}-javascript",
    }


def test_run_single_target_scan_passes_module_similarity_override(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    checkout_calls = []
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: TARGET_COMMIT if checkout_calls else ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "checkout_commit",
        lambda repo_path, commit: checkout_calls.append(commit) or True,
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", TARGET_COMMIT),
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
        payload = {
            "schema_version": 1,
            "scan_config": {"run_id": kwargs.get("run_id")},
        }
        return {
            **payload,
            "hash": agent_scanner.stable_data_hash(payload),
        }

    monkeypatch.setattr(agent_scanner, "build_scan_fingerprint", fake_build_scan_fingerprint)

    target = agent_scanner.ScanTarget(
        repo_name="target-repo",
        commit_hash=TARGET_COMMIT,
    )

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
        "require_embedding": False,
    }
    assert captured_fingerprint["module_similarity_config"] == {
        "threshold": 0.8,
        "model_name": "mini-model",
        "device": "cuda",
        "require_embedding": False,
    }


def test_run_single_target_scan_fails_when_coverage_is_incomplete(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", TARGET_COMMIT),
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
        target=agent_scanner.ScanTarget(
            repo_name="target-repo",
            commit_hash=TARGET_COMMIT,
        ),
        verbose=False,
    )

    assert ok is False


def test_run_single_target_scan_fails_when_restore_fails(monkeypatch, tmp_path):
    repo_base = tmp_path / "repos"
    repo_dir = repo_base / "target-repo"
    repo_dir.mkdir(parents=True)

    monkeypatch.setitem(agent_scanner._path_config, "repo_base_path", repo_base)
    monkeypatch.setitem(agent_scanner._path_config, "repo_root", tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda repo_path: ORIGINAL_COMMIT,
    )
    monkeypatch.setattr(agent_scanner, "get_git_restore_target", lambda repo_path: "master")
    monkeypatch.setattr(agent_scanner, "has_uncommitted_changes", lambda repo_path: False)
    monkeypatch.setattr(agent_scanner, "checkout_commit", lambda *args, **kwargs: True)
    monkeypatch.setattr(agent_scanner, "restore_git_position", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        agent_scanner,
        "load_software_profile",
        lambda *args, **kwargs: _mk_profile("target-repo", TARGET_COMMIT),
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
        target=agent_scanner.ScanTarget(
            repo_name="target-repo",
            commit_hash=TARGET_COMMIT,
        ),
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


def test_main_returns_nonzero_when_any_auto_target_scan_fails(
    monkeypatch, tmp_path
):
    args = _main_frozen_control_args(
        tmp_path,
        target_repo=None,
        target_commit=None,
    )
    targets = [
        agent_scanner.ScanTarget("target-ok", "a" * 40),
        agent_scanner.ScanTarget("target-failed", "b" * 40),
    ]
    executed = []
    monkeypatch.setattr(agent_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(agent_scanner, "setup_logging", lambda _verbose: None)
    monkeypatch.setattr(agent_scanner, "_validate_args", lambda _args: True)
    monkeypatch.setattr(agent_scanner, "_scanner_config_hashes", lambda: {})
    monkeypatch.setattr(
        agent_scanner,
        "require_evaluation_embedding_byte_binding",
        lambda _evaluation_mode: None,
    )
    monkeypatch.setattr(
        agent_scanner,
        "_resolve_profile_dirs",
        lambda _args: (tmp_path, tmp_path),
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_vulnerability_profile",
        lambda *_args, **_kwargs: {"cve_id": args.cve},
    )
    monkeypatch.setattr(
        agent_scanner,
        "_resolve_auto_targets",
        lambda *_args, **_kwargs: targets,
    )
    monkeypatch.setattr(
        agent_scanner,
        "create_llm_client",
        lambda _config: object(),
    )

    def fake_run_single_target_scan(**kwargs):
        executed.append(kwargs["target"].repo_name)
        return kwargs["target"].repo_name == "target-ok"

    monkeypatch.setattr(
        agent_scanner,
        "run_single_target_scan",
        fake_run_single_target_scan,
    )

    assert agent_scanner.main() == 1
    assert executed == ["target-ok", "target-failed"]


def _install_main_frozen_control_stubs(
    monkeypatch,
    args,
    tmp_path,
):
    monkeypatch.setattr(agent_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(
        agent_scanner,
        "setup_logging",
        lambda verbose: None,
    )
    monkeypatch.setattr(
        agent_scanner,
        "_validate_args",
        lambda parsed: True,
    )
    monkeypatch.setattr(
        agent_scanner,
        "_resolve_profile_dirs",
        lambda parsed: (tmp_path, tmp_path),
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_vulnerability_profile",
        lambda *values, **kwargs: (_ for _ in ()).throw(
            AssertionError(
                "vulnerability profile loading must be unreachable"
            )
        ),
    )


def test_main_embedding_gate_persists_frozen_control_sidecar(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    args = _main_frozen_control_args(
        tmp_path,
        evaluation_mode=True,
    )
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "module_similarity_embedding"
    )
    assert payload["execution"]["failure_class"] == (
        "EvaluationEvidenceUnavailableError"
    )
    assert payload["execution"]["blocker_code"] == (
        "consumed-embedding-bytes-unattested"
    )


def test_main_embedding_gate_does_not_trust_exception_blocker_attribute(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    args = _main_frozen_control_args(tmp_path, evaluation_mode=True)
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)

    def raise_modified_blocker(_evaluation_mode):
        error = agent_scanner.EvaluationEvidenceUnavailableError(
            "consumed-embedding-bytes-unattested"
        )
        error.blocker_code = "forged-replacement"
        raise error

    monkeypatch.setattr(
        agent_scanner,
        "require_evaluation_embedding_byte_binding",
        raise_modified_blocker,
    )

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "module_similarity_embedding"
    )
    assert payload["execution"]["blocker_code"] == (
        "consumed-embedding-bytes-unattested"
    )


def test_non_embedding_error_cannot_claim_embedding_blocker_code(
    monkeypatch,
    tmp_path,
):
    class ForgedEmbeddingError(ValueError):
        blocker_code = "consumed-embedding-bytes-unattested"

    output_base = tmp_path / "scan-out"
    args = _main_frozen_control_args(tmp_path, evaluation_mode=True)
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "require_evaluation_embedding_byte_binding",
        lambda _evaluation_mode: (_ for _ in ()).throw(
            ForgedEmbeddingError("forged blocker")
        ),
    )

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "module_similarity_embedding"
    )
    assert payload["execution"]["failure_class"] == (
        "ForgedEmbeddingError"
    )
    assert payload["execution"]["blocker_code"] is None


def test_main_projection_hash_failure_persists_sanitized_provenance(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    args = _main_frozen_control_args(
        tmp_path,
        target_path_projection="/run/secret-projection.json",
        target_path_projection_sha256="b" * 64,
        target_path_projection_binding_path=(
            "rq2/inputs/projections/target.json"
        ),
        target_software_profile_sha256="e" * 64,
    )
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "load_target_path_projection",
        lambda *values, **kwargs: (_ for _ in ()).throw(
            ValueError("secret projection bytes at /tmp/private")
        ),
    )

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "target_path_projection"
    )
    assert (
        payload["input_hashes"]["target_path_projection_artifact"]
        is None
    )
    assert (
        payload["declared_input_hashes"][
            "target_path_projection_artifact"
        ]
        == "b" * 64
    )
    assert (
        payload["observed_input_hashes"][
            "target_path_projection_artifact"
        ]
        is None
    )
    for key in (
        "target_software_profile_artifact",
        "model_input_invariant_stage",
        "model_input_policy_stage",
        "model_input_control",
    ):
        assert payload["input_hashes"][key] is None
        assert payload["observed_input_hashes"][key] is None
    serialized = json.dumps(payload, sort_keys=True)
    assert "secret projection" not in serialized
    assert "/tmp/private" not in serialized


def test_main_stage_hash_failure_retains_only_loaded_raw_artifacts(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    args = _main_frozen_control_args(
        tmp_path,
        reference_card="/run/reference.json",
        reference_card_sha256="7" * 64,
        reference_card_binding_path="rq2/inputs/reference.json",
        target_path_projection="/run/projection.json",
        target_path_projection_sha256="8" * 64,
        target_path_projection_binding_path=(
            "rq2/inputs/projections/target.json"
        ),
        target_software_profile_sha256="e" * 64,
        model_input_invariant_stage_sha256="c" * 64,
        model_input_policy_stage_sha256="d" * 64,
    )
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "load_reference_context_envelope",
        lambda *values, **kwargs: {
            "provenance": {"artifact_sha256": "7" * 64}
        },
    )
    monkeypatch.setattr(
        agent_scanner,
        "load_target_path_projection",
        lambda *values, **kwargs: {
            "provenance": {"artifact_sha256": "8" * 64}
        },
    )
    monkeypatch.setattr(
        agent_scanner,
        "bind_verified_model_input_control",
        lambda *values, **kwargs: (_ for _ in ()).throw(
            ValueError("secret stage mismatch at /tmp/private")
        ),
    )

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "model_input_stage_binding"
    )
    for key, expected in (
        ("reference_context_artifact", "7" * 64),
        ("target_path_projection_artifact", "8" * 64),
    ):
        assert payload["input_hashes"][key] == expected
        assert payload["observed_input_hashes"][key] == expected
    for key, expected in (
        ("model_input_invariant_stage", "c" * 64),
        ("model_input_policy_stage", "d" * 64),
    ):
        assert payload["declared_input_hashes"][key] == expected
        assert payload["input_hashes"][key] is None
        assert payload["observed_input_hashes"][key] is None
    assert payload["input_hashes"]["model_input_control"] is None
    assert payload["input_hashes"][
        "target_software_profile_artifact"
    ] is None
    serialized = json.dumps(payload, sort_keys=True)
    assert "secret stage" not in serialized
    assert "/tmp/private" not in serialized


def test_main_attestation_load_failure_does_not_reread_or_claim_hashes(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    _snapshot, snapshot_json, snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    args = _main_frozen_control_args(
        tmp_path,
        model_revision="revision-a",
        model_revision_attestation="/run/secret-attestation.json",
        model_revision_attestation_sha256="9" * 64,
        model_revision_attestation_binding_path=(
            "rq2/inputs/model-revision-attestations/model-x.json"
        ),
        endpoint_snapshot_json=snapshot_json,
        endpoint_snapshot_sha256=snapshot_sha256,
    )
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "load_model_revision_attestation",
        lambda *values, **kwargs: (_ for _ in ()).throw(
            ValueError("secret attestation at /tmp/private")
        ),
    )

    assert agent_scanner.main() == 1

    payload = _assert_durable_preflight_failure(
        output_base,
        termination="frozen_control_validation_failure",
        stage="frozen_control_loading",
    )
    assert payload["execution"]["failure_control"] == (
        "model_revision_attestation"
    )
    assert payload["input_hashes"]["endpoint_snapshot"] == snapshot_sha256
    assert (
        payload["declared_input_hashes"][
            "model_revision_attestation_file"
        ]
        == "9" * 64
    )
    for section in (
        payload["input_hashes"],
        payload["observed_input_hashes"],
    ):
        assert section["model_revision_attestation_file"] is None
        assert section["model_revision_attestation_payload"] is None
    assert payload["llm"]["model_revision_attestation"] == {}
    serialized = json.dumps(payload, sort_keys=True)
    assert "secret attestation" not in serialized
    assert "/tmp/private" not in serialized


def test_main_unsafe_failure_identity_stays_under_hashed_preflight_root(
    monkeypatch,
    tmp_path,
):
    output_base = tmp_path / "scan-out"
    raw_run_id = "../../secret/run-id"
    args = _main_frozen_control_args(
        tmp_path,
        cve="../secret-cve",
        target_repo="../secret-repo",
        target_commit="../../secret-commit",
        run_id=raw_run_id,
        target_path_projection="/run/projection.json",
        target_path_projection_sha256="b" * 64,
        target_path_projection_binding_path=(
            "rq2/inputs/projections/target.json"
        ),
        target_software_profile_sha256="e" * 64,
    )
    _install_main_frozen_control_stubs(monkeypatch, args, tmp_path)
    monkeypatch.setattr(
        agent_scanner,
        "load_target_path_projection",
        lambda *values, **kwargs: (_ for _ in ()).throw(
            ValueError("secret unsafe identity at /tmp/private")
        ),
    )

    assert agent_scanner.main() == 1

    portable_run_id = "preflight-" + hashlib.sha256(
        raw_run_id.encode("utf-8")
    ).hexdigest()[:24]
    expected_path = (
        output_base
        / "_preflight"
        / hashlib.sha256(
        portable_run_id.encode("utf-8")
        ).hexdigest()
        / "run_failure.json"
    )
    assert list(output_base.rglob("run_failure.json")) == [
        expected_path
    ]
    payload = json.loads(expected_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == portable_run_id
    assert payload["repo"] == {
        "name": "",
        "requested_commit": None,
        "actual_commit": None,
    }
    assert expected_path.resolve().is_relative_to(output_base.resolve())
    serialized = json.dumps(payload, sort_keys=True)
    assert "secret-cve" not in serialized
    assert "secret-repo" not in serialized
    assert "secret-commit" not in serialized
    assert "/tmp/private" not in serialized
    assert not list(output_base.rglob("agentic_vuln_findings.json"))
    assert not list(output_base.rglob("conversation_history.json"))
    assert not list(output_base.rglob("scan_memory.json"))


def test_run_provenance_preserves_unknown_usage_and_scoped_ablations():
    started_at = datetime(2026, 7, 31, 10, 0, 0)
    target = agent_scanner.ScanTarget(
        repo_name="target",
        commit_hash="a" * 40,
        selection_provenance={"embedding": {"backend": "transformers"}},
    )
    llm_client = SimpleNamespace(
        config=SimpleNamespace(
            provider="lab",
            model="model-x",
            reasoning_effort="high",
            enable_thinking=True,
            service_tier="priority",
        )
    )

    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    decoding_config, _decoding_json, decoding_sha256 = (
        _decoding_config_binding(
            enable_thinking=True,
            reasoning_effort="high",
            service_tier="priority",
        )
    )
    attestation = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_snapshot_sha256
    )
    provenance = agent_scanner._build_run_provenance(
        target=target,
        llm_client=llm_client,
        max_iterations=10,
        started_at=started_at,
        finished_at=started_at + timedelta(seconds=2),
        actual_repo_commit="a" * 40,
        status="partial",
        termination="max_iterations",
        results={"iterations": 10, "iteration_durations_seconds": [0.2]},
        quality={"coverage_status": "partial"},
        usage_summary={"calls_total": 0, "sessions_total": 0, "turns_total": 0},
        ablation_config={"memory": True, "verifier": True},
        evaluation_mode=True,
        model_revision="revision-a",
        model_revision_attestation_binding=attestation["binding"],
        endpoint_snapshot=endpoint_snapshot,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_requested=decoding_config,
        decoding_config_requested_sha256=decoding_sha256,
        decoding_config_effective=decoding_config,
        decoding_config_effective_sha256=decoding_sha256,
    )

    assert provenance["repo"]["actual_commit"] == "a" * 40
    assert provenance["config_hashes"] == agent_scanner._scanner_config_hashes()
    assert provenance["llm"]["reasoning_effort"] == "high"
    assert provenance["llm"]["model_revision"] == "revision-a"
    assert (
        provenance["llm"]["model_revision_attestation"]
        == attestation["binding"]
    )
    assert provenance["llm"]["endpoint_snapshot"] == endpoint_snapshot
    assert (
        provenance["llm"]["endpoint_snapshot_sha256"]
        == endpoint_snapshot_sha256
    )
    assert provenance["llm"]["decoding_config_requested"] == decoding_config
    assert (
        provenance["llm"]["decoding_config_requested_sha256"]
        == decoding_sha256
    )
    assert provenance["llm"]["decoding_config_effective"] == decoding_config
    assert (
        provenance["llm"]["decoding_config_effective_sha256"]
        == decoding_sha256
    )
    assert provenance["execution"]["duration_seconds"] == 2.0
    assert provenance["execution"]["partial"] is True
    assert provenance["usage"] is None
    assert "did not report usage" in provenance["usage_unavailable_reason"]
    assert provenance["ablations"]["memory"] is True
    assert "control-plane ledgers retained" in provenance["ablation_scope"]["memory"]
    assert "first-presented" in provenance["ablation_scope"]["candidate_priority"]
    assert "model-controlled" in provenance["ablation_scope"]["candidate_priority"]
    assert "external exploitability" in provenance["ablation_scope"]["verifier"]
    assert provenance["selection_similarity"]["embedding"]["backend"] == "transformers"


def test_auto_target_repo_semantics_ablation_uses_structure_only_without_embedding(monkeypatch, tmp_path):
    args = Namespace(
        vuln_repo="src-repo",
        top_k=1,
        include_same_repo=False,
        similarity_model_name="model",
        similarity_device="cpu",
        similarity_threshold=None,
        evaluation_mode=True,
        ablate_repo_semantics=True,
    )
    source_ref = ProfileRef(
        "src-repo", "1" * 40, _mk_profile("src-repo", version="1" * 40)
    )
    candidate_ref = ProfileRef(
        "target-repo", "2" * 40, _mk_profile("target-repo", version="2" * 40)
    )
    similarity = SimilarProfileCandidate(
        profile_ref=candidate_ref,
        metrics=ProfileSimilarityMetrics(0.8, 0.8, 0.8, 0.8, 0.8, 0.8),
    )
    captured = {}
    monkeypatch.setattr(
        agent_scanner, "load_all_software_profiles", lambda _: [source_ref, candidate_ref]
    )
    monkeypatch.setattr(
        agent_scanner, "select_profile_ref", lambda refs, repo, commit_hint: source_ref
    )
    monkeypatch.setattr(
        agent_scanner,
        "build_text_retriever",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("repo-semantics ablation must not load embeddings")
        ),
    )
    monkeypatch.setattr(
        agent_scanner,
        "embedding_model_artifact_signature",
        lambda model_name: {"artifact_hash": "artifact", "resolved_model_path": "/model"},
    )

    def fake_rank(**kwargs):
        captured.update(kwargs)
        return [similarity]

    monkeypatch.setattr(agent_scanner, "rank_similar_profiles", fake_rank)

    targets = agent_scanner._resolve_auto_targets(
        args,
        SimpleNamespace(repo_name="src-repo", affected_version="1" * 40),
        tmp_path,
    )

    assert captured["text_retriever"] is None
    assert captured["weights"] == agent_scanner.REPO_STRUCTURE_ONLY_WEIGHTS
    assert captured["require_embedding"] is False
    assert targets[0].selection_provenance["embedding"]["disabled_reason"] == (
        "repo_semantics_ablation"
    )

def _write_frozen_json(path, payload):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_model_revision_attestation_loader_binds_raw_and_canonical_hashes(
    tmp_path,
):
    endpoint_sha256 = _endpoint_snapshot_binding()[2]
    expected = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_sha256
    )
    path = tmp_path / "model-revision-attestation.json"
    file_sha256 = _write_frozen_json(path, expected["payload"])

    loaded = agent_scanner.load_model_revision_attestation(
        str(path),
        file_sha256,
        expected["binding"]["path"],
        provider="lab",
        model_name="GLM-5.2",
        model_revision="revision-a",
        endpoint_snapshot_sha256=endpoint_sha256,
    )

    assert loaded["payload"] == expected["payload"]
    assert loaded["binding"] == {
        "path": expected["binding"]["path"],
        "file_sha256": file_sha256,
        "payload_sha256": agent_scanner.stable_data_hash(
            expected["payload"]
        ),
    }


@pytest.mark.parametrize(
    ("field", "value", "expected_message"),
    [
        ("schema_version", True, "payload is malformed"),
        ("provider", "secret-provider", "provider mismatch"),
        ("model_name", "secret-model", "model_name mismatch"),
        ("model_revision", "secret-revision", "revision mismatch"),
        ("endpoint_snapshot_sha256", "8" * 64, "endpoint snapshot mismatch"),
    ],
)
def test_model_revision_attestation_rejects_hostile_identity_without_echo(
    tmp_path,
    field,
    value,
    expected_message,
):
    endpoint_sha256 = _endpoint_snapshot_binding()[2]
    expected = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_sha256
    )
    payload = dict(expected["payload"])
    payload[field] = value
    path = tmp_path / "model-revision-attestation.json"
    file_sha256 = _write_frozen_json(path, payload)

    with pytest.raises(ValueError, match=expected_message) as exc_info:
        agent_scanner.load_model_revision_attestation(
            str(path),
            file_sha256,
            expected["binding"]["path"],
            provider="lab",
            model_name="GLM-5.2",
            model_revision="revision-a",
            endpoint_snapshot_sha256=endpoint_sha256,
        )

    assert "secret-" not in str(exc_info.value)


def test_model_revision_attestation_rejects_shape_hash_and_path_ambiguity(
    tmp_path,
):
    endpoint_sha256 = _endpoint_snapshot_binding()[2]
    expected = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_sha256
    )
    path = tmp_path / "model-revision-attestation.json"
    payload_with_extra = {
        **expected["payload"],
        "unexpected": "secret-extra",
    }
    file_sha256 = _write_frozen_json(path, payload_with_extra)
    with pytest.raises(ValueError, match="payload is malformed") as exc_info:
        agent_scanner.load_model_revision_attestation(
            str(path),
            file_sha256,
            expected["binding"]["path"],
            provider="lab",
            model_name="GLM-5.2",
            model_revision="revision-a",
            endpoint_snapshot_sha256=endpoint_sha256,
        )
    assert "secret-extra" not in str(exc_info.value)

    duplicate_raw = (
        b'{"schema_version":1,"schema_version":1,'
        b'"kind":"operator_attested_deployment_revision"}'
    )
    path.write_bytes(duplicate_raw)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        agent_scanner.load_model_revision_attestation(
            str(path),
            hashlib.sha256(duplicate_raw).hexdigest(),
            expected["binding"]["path"],
            provider="lab",
            model_name="GLM-5.2",
            model_revision="revision-a",
            endpoint_snapshot_sha256=endpoint_sha256,
        )

    valid_file_sha256 = _write_frozen_json(path, expected["payload"])
    for invalid_file_sha256 in (
        valid_file_sha256.upper(),
        f" {valid_file_sha256}",
    ):
        with pytest.raises(ValueError, match="lowercase hexadecimal"):
            agent_scanner.load_model_revision_attestation(
                str(path),
                invalid_file_sha256,
                expected["binding"]["path"],
                provider="lab",
                model_name="GLM-5.2",
                model_revision="revision-a",
                endpoint_snapshot_sha256=endpoint_sha256,
            )
    for invalid_binding_path in (
        "/absolute/attestation.json",
        "../attestation.json",
        "rq2\\attestation.json",
    ):
        with pytest.raises(ValueError, match="binding path"):
            agent_scanner.load_model_revision_attestation(
                str(path),
                valid_file_sha256,
                invalid_binding_path,
                provider="lab",
                model_name="GLM-5.2",
                model_revision="revision-a",
                endpoint_snapshot_sha256=endpoint_sha256,
            )

    envelope = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_sha256
    )
    envelope["binding"]["payload_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="canonical payload SHA-256"):
        agent_scanner.validate_model_revision_attestation_payload(
            envelope,
            provider="lab",
            model_name="GLM-5.2",
            model_revision="revision-a",
            endpoint_snapshot_sha256=endpoint_sha256,
        )


def _valid_target_path_projection_payload(
    *,
    target_repository="target",
    target_commit="a" * 40,
    target_id="target-a",
    paths=None,
    target_tree_listing_sha256="9" * 64,
):
    frozen_paths = sorted(
        paths or ["src/api.py", "src/worker.py"],
        key=lambda value: value.encode("utf-8"),
    )
    return {
        "schema_version": 2,
        "algorithm": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "target_id": target_id,
        "target_repository": target_repository,
        "target_commit": target_commit,
        "source": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_SOURCE,
        "target_tree_listing_sha256": target_tree_listing_sha256,
        "path_count": len(frozen_paths),
        "paths": frozen_paths,
        "universe_sha256": agent_scanner.stable_data_hash(frozen_paths),
        "replacement": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            agent_scanner.MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "scope": list(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "policy_exclusions": list(
            agent_scanner.MODEL_VISIBLE_INPUT_POLICY_EXCLUSIONS
        ),
    }


def _initialize_projection_git_repo(tmp_path):
    repo = tmp_path / "projection-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "projection@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Projection Test"],
        cwd=repo,
        check=True,
    )
    (repo / "regular.txt").write_text("regular\n", encoding="utf-8")
    executable = repo / "script.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    (repo / "regular-link").symlink_to("regular.txt")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "projection fixture"],
        cwd=repo,
        check=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repo / "untracked.py").write_text("untracked\n", encoding="utf-8")
    return repo, commit


def _validated_projection_for_git_repo(
    repo,
    commit,
    *,
    paths=None,
    tree_listing_sha256=None,
):
    actual_tree_sha256, actual_paths = (
        agent_scanner._git_regular_blob_tree_snapshot(repo, commit)
    )
    selected_paths = actual_paths if paths is None else paths
    payload = _valid_target_path_projection_payload(
        target_commit=commit,
        paths=selected_paths,
        target_tree_listing_sha256=(
            actual_tree_sha256
            if tree_listing_sha256 is None
            else tree_listing_sha256
        ),
    )
    return agent_scanner.validate_target_path_projection_payload(
        payload,
        "b" * 64,
        target_repository="target",
        target_commit=commit,
        target_software_profile_sha256="e" * 64,
        artifact_locator="rq2/inputs/projection.json",
        physical_artifact_path="results/staged/projection.json",
    )


def test_target_projection_closes_over_exact_committed_regular_blob_tree(tmp_path):
    repo, commit = _initialize_projection_git_repo(tmp_path)
    tree_sha256, committed_paths = (
        agent_scanner._git_regular_blob_tree_snapshot(repo, commit)
    )

    assert committed_paths == ["regular.txt", "script.sh"]
    assert "regular-link" not in committed_paths
    assert "untracked.py" not in committed_paths
    projection = _validated_projection_for_git_repo(repo, commit)
    assert projection["provenance"]["target_tree_listing_sha256"] == tree_sha256
    agent_scanner._validate_target_projection_against_git_tree(
        projection,
        repo,
        target_repository="target",
        target_commit=commit,
    )


@pytest.mark.parametrize(
    "mutation",
    ["omitted_blob", "untracked_file", "symlink", "wrong_tree_hash"],
)
def test_target_projection_rejects_tree_universe_and_listing_mismatches(
    tmp_path,
    mutation,
):
    repo, commit = _initialize_projection_git_repo(tmp_path)
    tree_sha256, committed_paths = (
        agent_scanner._git_regular_blob_tree_snapshot(repo, commit)
    )
    selected_paths = list(committed_paths)
    selected_tree_sha256 = tree_sha256
    if mutation == "omitted_blob":
        selected_paths = selected_paths[1:]
    elif mutation == "untracked_file":
        selected_paths.append("untracked.py")
    elif mutation == "symlink":
        selected_paths.append("regular-link")
    else:
        selected_tree_sha256 = "0" * 64
    selected_paths = sorted(
        selected_paths,
        key=lambda value: value.encode("utf-8"),
    )
    projection = _validated_projection_for_git_repo(
        repo,
        commit,
        paths=selected_paths,
        tree_listing_sha256=selected_tree_sha256,
    )

    with pytest.raises(
        ValueError,
        match="regular-blob universe|target_tree_listing_sha256",
    ):
        agent_scanner._validate_target_projection_against_git_tree(
            projection,
            repo,
            target_repository="target",
            target_commit=commit,
        )


def test_target_projection_rejects_non_string_target_id_and_paths():
    payload = _valid_target_path_projection_payload()
    payload["target_id"] = 7
    with pytest.raises(ValueError, match="target_id must be a non-empty string"):
        agent_scanner.validate_target_path_projection_payload(
            payload,
            "b" * 64,
            target_repository="target",
            target_commit="a" * 40,
            target_software_profile_sha256="e" * 64,
        )

    payload = _valid_target_path_projection_payload()
    payload["paths"] = [7]
    payload["path_count"] = 1
    payload["universe_sha256"] = agent_scanner.stable_data_hash([7])
    with pytest.raises(ValueError, match="projection path must be a JSON string"):
        agent_scanner.validate_target_path_projection_payload(
            payload,
            "b" * 64,
            target_repository="target",
            target_commit="a" * 40,
            target_software_profile_sha256="e" * 64,
        )


def test_frozen_artifact_digests_reject_uppercase_values(tmp_path):
    path = tmp_path / "artifact.json"
    digest = _write_frozen_json(path, {})
    with pytest.raises(ValueError, match="expected SHA-256"):
        agent_scanner._load_frozen_json_artifact(
            str(path),
            digest.upper(),
            label="frozen test artifact",
        )

    payload = _valid_target_path_projection_payload()
    with pytest.raises(ValueError, match="artifact SHA-256"):
        agent_scanner.validate_target_path_projection_payload(
            payload,
            ("b" * 64).upper(),
            target_repository="target",
            target_commit="a" * 40,
            target_software_profile_sha256="e" * 64,
        )
    with pytest.raises(ValueError, match="separately hash-bound"):
        agent_scanner.validate_target_path_projection_payload(
            payload,
            "b" * 64,
            target_repository="target",
            target_commit="a" * 40,
            target_software_profile_sha256=("e" * 64).upper(),
        )


def test_load_reference_context_envelope_is_strict_hash_bound_and_portable(
    tmp_path, monkeypatch
):
    model_card = {
        "schema_version": 1,
        "card_id": "card-public-7",
        "weaknesses": ["CWE-22", "CWE-78"],
    }
    host_plan = {
        "schema_version": 1,
        "module_priorities": {"api": 1, "worker": 2},
        "file_to_module": {"src/api.py": "api", "src/worker.py": "worker"},
    }
    payload = {
        "schema_version": 1,
        "model_card": model_card,
        "host_priority_plan": host_plan,
        "model_card_sha256": agent_scanner.stable_data_hash(model_card),
        "host_priority_plan_sha256": agent_scanner.stable_data_hash(host_plan),
    }
    path = tmp_path / "reference-card.json"
    digest = _write_frozen_json(path, payload)
    loaded = agent_scanner.load_reference_context_envelope(str(path), digest)
    assert loaded["model_card"] == model_card
    assert loaded["host_priority_plan"] == host_plan
    assert loaded["provenance"]["artifact_sha256"] == digest
    assert loaded["provenance"]["physical_artifact_path"] == str(path)
    assert "artifact_path" not in loaded["provenance"]

    binding_path = "rq2/inputs/reference-cards/card-public-7.json"
    staged_loaded = agent_scanner.load_reference_context_envelope(
        str(path), digest, binding_path
    )
    assert staged_loaded["provenance"]["artifact_path"] == binding_path
    assert staged_loaded["provenance"]["physical_artifact_path"] == str(path)

    monkeypatch.setitem(agent_scanner._path_config, "project_root", tmp_path)
    relative_loaded = agent_scanner.load_reference_context_envelope(path.name, digest)
    assert relative_loaded["provenance"]["artifact_path"] == path.name
    assert relative_loaded["provenance"]["physical_artifact_path"] == path.name
    payload["unexpected"] = "must-fail"
    digest = _write_frozen_json(path, payload)
    with pytest.raises(ValueError, match="exact frozen key set"):
        agent_scanner.load_reference_context_envelope(str(path), digest)

def test_load_unprioritized_file_schedule_verifies_seed_order_target_universe_and_portability(
    tmp_path, monkeypatch
):
    target_commit = "a" * 40
    seed_payload = {
        "benchmark_constant": "ccs26b-rq2-v1",
        "target_commit": target_commit,
        "replicate": "2",
    }
    seed_sha256 = agent_scanner.stable_data_hash(seed_payload)
    files = ["src/api.py", "src/worker.py"]
    ordered_files = sorted(
        files,
        key=lambda path: (
            hashlib.sha256((seed_sha256 + path).encode("utf-8")).hexdigest(),
            path.encode("utf-8"),
        ),
    )
    payload = {
        "schema_version": 1,
        "algorithm": "sha256-seed-path-v1",
        **seed_payload,
        "seed_sha256": seed_sha256,
        "files": ordered_files,
        "universe_sha256": agent_scanner.stable_data_hash(sorted(ordered_files)),
        "order_sha256": agent_scanner.stable_data_hash(ordered_files),
    }
    path = tmp_path / "file-order.json"
    digest = _write_frozen_json(path, payload)
    loaded = agent_scanner.load_unprioritized_file_schedule(
        str(path), digest, target_commit=target_commit
    )
    profile = SoftwareProfile(
        name="target",
        modules=[
            ModuleInfo(name="api", files=["src/api.py"]),
            ModuleInfo(name="worker", files=["src/worker.py"]),
        ],
    )
    host_plan = {
        "schema_version": 1,
        "module_priorities": {"api": 1, "worker": 2},
        "file_to_module": {"src/api.py": "api", "src/worker.py": "worker"},
    }
    agent_scanner.validate_frozen_scan_controls(profile, host_plan, loaded)
    assert loaded["files"] == ordered_files
    assert loaded["provenance"]["seed_sha256"] == seed_sha256
    assert loaded["provenance"]["artifact_sha256"] == digest
    assert loaded["provenance"]["physical_artifact_path"] == str(path)
    assert "artifact_path" not in loaded["provenance"]

    binding_path = "rq2/inputs/orders/target-replicate-2.json"
    staged_loaded = agent_scanner.load_unprioritized_file_schedule(
        str(path),
        digest,
        target_commit=target_commit,
        binding_path=binding_path,
    )
    assert staged_loaded["provenance"]["artifact_path"] == binding_path
    assert staged_loaded["provenance"]["physical_artifact_path"] == str(path)

    monkeypatch.setitem(agent_scanner._path_config, "project_root", tmp_path)
    relative_loaded = agent_scanner.load_unprioritized_file_schedule(
        path.name,
        digest,
        target_commit=target_commit,
    )
    assert relative_loaded["provenance"]["artifact_path"] == path.name
    assert relative_loaded["provenance"]["physical_artifact_path"] == path.name
    payload["files"] = list(reversed(ordered_files))
    digest = _write_frozen_json(path, payload)
    with pytest.raises(ValueError, match="seed-hash permutation"):
        agent_scanner.load_unprioritized_file_schedule(
            str(path), digest, target_commit=target_commit
        )


@pytest.mark.parametrize(
    ("policy_mode", "logical_policy_path"),
    [
        ("host_priority_plan", "rq2/inputs/reference-cards/card.json"),
        (
            "frozen_unprioritized_schedule",
            "rq2/inputs/unprioritized-orders/order.json",
        ),
    ],
)
def test_staged_bytes_reconstruct_exact_logical_model_input_control(
    tmp_path, policy_mode, logical_policy_path
):
    target_commit = "a" * 40
    profile_sha256 = "e" * 64
    projection_path = tmp_path / "input-snapshots" / "projection.json"
    projection_path.parent.mkdir()
    projection_digest = _write_frozen_json(
        projection_path,
        _valid_target_path_projection_payload(target_commit=target_commit),
    )
    logical_projection_path = (
        "rq2/inputs/target-path-projections/target/"
        + target_commit
        + "/projection.json"
    )
    projection = agent_scanner.load_target_path_projection(
        str(projection_path),
        projection_digest,
        target_repository="target",
        target_commit=target_commit,
        target_software_profile_sha256=profile_sha256,
        binding_path=logical_projection_path,
    )
    policy_provenance = {
        "artifact_sha256": "7" * 64,
        "physical_artifact_path": str(
            tmp_path / "input-snapshots" / "policy.json"
        ),
        "artifact_path": logical_policy_path,
    }
    policy_without_hash = {
        "mode": policy_mode,
        "artifact": {
            "kind": "file",
            "status": "frozen",
            "path": logical_policy_path,
            "sha256": "7" * 64,
        },
    }
    policy_stage_sha256 = agent_scanner.stable_data_hash(policy_without_hash)
    if policy_mode == "host_priority_plan":
        reference_context = {"provenance": policy_provenance}
        schedule = None
    else:
        reference_context = None
        schedule = {"files": ["src/api.py"], "provenance": policy_provenance}

    projection_binding = {
        "kind": "file",
        "status": "frozen",
        "path": logical_projection_path,
        "sha256": projection_digest,
    }
    invariant_without_hash = {
        "schema_version": 2,
        "algorithm": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "scope": list(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "replacement": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            agent_scanner.MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "projection_input": projection_binding,
    }
    invariant_stage_sha256 = agent_scanner.stable_data_hash(
        invariant_without_hash
    )
    bound = agent_scanner.bind_verified_model_input_control(
        projection,
        reference_context=reference_context,
        unprioritized_schedule=schedule,
        expected_invariant_stage_sha256=invariant_stage_sha256,
        expected_policy_stage_sha256=policy_stage_sha256,
    )
    expected_control = {
        "schema_version": 2,
        "invariant_preprocessing": {
            **invariant_without_hash,
            "stage_sha256": invariant_stage_sha256,
        },
        "policy_specific_eligibility": {
            **policy_without_hash,
            "stage_sha256": policy_stage_sha256,
        },
    }

    provenance = bound["provenance"]
    assert provenance["artifact_path"] == logical_projection_path
    assert provenance["physical_artifact_path"] == str(projection_path)
    assert provenance["model_input_control"] == expected_control
    assert provenance["model_input_control_sha256"] == (
        agent_scanner.stable_data_hash(expected_control)
    )
    assert provenance["model_input_stage_hashes"] == {
        "invariant_preprocessing": invariant_stage_sha256,
        "policy_specific_eligibility": policy_stage_sha256,
    }
    agent_scanner._validate_verified_model_input_control(bound)

    with pytest.raises(ValueError, match="invariant stage SHA-256 mismatch"):
        agent_scanner.bind_verified_model_input_control(
            projection,
            reference_context=reference_context,
            unprioritized_schedule=schedule,
            expected_invariant_stage_sha256="0" * 64,
            expected_policy_stage_sha256=policy_stage_sha256,
        )


def _bound_prioritized_evaluation_projection():
    target_commit = "a" * 40
    logical_projection_path = "rq2/inputs/projection.json"
    projection = agent_scanner.validate_target_path_projection_payload(
        _valid_target_path_projection_payload(target_commit=target_commit),
        "b" * 64,
        target_repository="target",
        target_commit=target_commit,
        target_software_profile_sha256="e" * 64,
        artifact_locator=logical_projection_path,
        physical_artifact_path="results/staged/projection.json",
    )
    reference_provenance = {
        "artifact_sha256": "7" * 64,
        "physical_artifact_path": "results/staged/reference.json",
        "artifact_path": "rq2/inputs/reference.json",
    }
    invariant_without_hash = {
        "schema_version": 2,
        "algorithm": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "scope": list(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "replacement": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            agent_scanner.MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "projection_input": {
            "kind": "file",
            "status": "frozen",
            "path": logical_projection_path,
            "sha256": "b" * 64,
        },
    }
    policy_without_hash = {
        "mode": "host_priority_plan",
        "artifact": {
            "kind": "file",
            "status": "frozen",
            "path": reference_provenance["artifact_path"],
            "sha256": reference_provenance["artifact_sha256"],
        },
    }
    bound = agent_scanner.bind_verified_model_input_control(
        projection,
        reference_context={"provenance": reference_provenance},
        unprioritized_schedule=None,
        expected_invariant_stage_sha256=agent_scanner.stable_data_hash(
            invariant_without_hash
        ),
        expected_policy_stage_sha256=agent_scanner.stable_data_hash(
            policy_without_hash
        ),
    )
    return bound, reference_provenance


def test_evaluation_direct_call_rejects_policy_artifact_mismatch_before_output(
    tmp_path,
):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    mismatched_reference = {
        **reference_provenance,
        "artifact_path": "rq2/inputs/different-reference.json",
    }
    output_base = tmp_path / "scan-out"
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )

    with pytest.raises(
        ValueError,
        match="model-input policy binding mismatch",
    ):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2026-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                model_revision="revision-a",
                base_url=endpoint_snapshot["base_url"],
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256
                )
            ),
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=_decoding_config_binding()[0],
            decoding_config_requested_sha256=_decoding_config_binding()[2],
            target_path_projection=bound,
            reference_context_provenance=mismatched_reference,
        )

    _assert_durable_preflight_failure(output_base)


@pytest.mark.parametrize(
    ("declared_revision", "client_revision", "message"),
    [
        (None, None, "requires an explicit model_revision"),
        (
            "revision-a",
            "revision-b",
            "does not match the LLM client configuration",
        ),
        (
            "revision-a",
            None,
            "does not match the LLM client configuration",
        ),
    ],
)
def test_evaluation_direct_call_rejects_missing_or_mismatched_model_revision(
    tmp_path,
    declared_revision,
    client_revision,
    message,
):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    output_base = tmp_path / "scan-out"
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )

    with pytest.raises(ValueError, match=message):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2026-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                model_revision=client_revision,
                base_url=endpoint_snapshot["base_url"],
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision=declared_revision,
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    model_revision=declared_revision,
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256,
                )
                if declared_revision is not None
                else None
            ),
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=_decoding_config_binding()[0],
            decoding_config_requested_sha256=_decoding_config_binding()[2],
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
        )

    _assert_durable_preflight_failure(output_base)


@pytest.mark.parametrize(
    ("attestation", "message"),
    [
        (
            None,
            "requires a verified operator model revision attestation",
        ),
        (
            _model_revision_attestation_binding(
                provider="different-provider"
            ),
            "attestation provider mismatch",
        ),
    ],
)
def test_evaluation_direct_call_rejects_missing_or_invalid_attestation(
    tmp_path,
    attestation,
    message,
):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    output_base = tmp_path / "scan-out"
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )

    with pytest.raises(ValueError, match=message):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2026-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                model_revision="revision-a",
                base_url=endpoint_snapshot["base_url"],
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=attestation,
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=_decoding_config_binding()[0],
            decoding_config_requested_sha256=_decoding_config_binding()[2],
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
        )

    payload = _assert_durable_preflight_failure(output_base)
    assert payload["llm"]["model_revision_attestation"] == {}
    assert (
        payload["input_hashes"]["model_revision_attestation_file"]
        is None
    )
    assert (
        payload["input_hashes"]["model_revision_attestation_payload"]
        is None
    )


@pytest.mark.parametrize(
    ("include_snapshot", "client_base_url", "message"),
    [
        (
            False,
            "https://api.example.invalid/v1",
            "requires an explicit immutable endpoint snapshot",
        ),
        (
            True,
            "https://different.example.invalid/v1",
            "does not match the LLM client configuration",
        ),
    ],
)
def test_evaluation_direct_call_rejects_missing_or_mismatched_endpoint_snapshot(
    tmp_path,
    include_snapshot,
    client_base_url,
    message,
):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    output_base = tmp_path / "scan-out"

    with pytest.raises(ValueError, match=message):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2026-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                model_revision="revision-a",
                base_url=client_base_url,
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256
                )
                if include_snapshot
                else None
            ),
            endpoint_snapshot=(
                endpoint_snapshot if include_snapshot else None
            ),
            endpoint_snapshot_sha256=(
                endpoint_snapshot_sha256 if include_snapshot else None
            ),
            decoding_config_requested=_decoding_config_binding()[0],
            decoding_config_requested_sha256=_decoding_config_binding()[2],
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
        )

    _assert_durable_preflight_failure(output_base)


def test_target_path_projection_v2_requires_structured_projection(tmp_path):
    payload = _valid_target_path_projection_payload()
    del payload["structured_projection"]
    path = tmp_path / "projection.json"
    digest = _write_frozen_json(path, payload)

    with pytest.raises(ValueError, match="schema_version=2 and the exact key set"):
        agent_scanner.load_target_path_projection(
            str(path),
            digest,
            target_repository="target",
            target_commit="a" * 40,
            target_software_profile_sha256="e" * 64,
            binding_path="rq2/inputs/projection.json",
        )


def test_scan_fingerprint_persists_full_projection_control_and_physical_path(
    tmp_path
):
    target_commit = "a" * 40
    profile_sha256 = "e" * 64
    projection_path = tmp_path / "input-snapshots" / "projection.json"
    projection_path.parent.mkdir()
    projection_digest = _write_frozen_json(
        projection_path,
        _valid_target_path_projection_payload(target_commit=target_commit),
    )
    logical_projection_path = "rq2/inputs/projection.json"
    projection = agent_scanner.load_target_path_projection(
        str(projection_path),
        projection_digest,
        target_repository="target",
        target_commit=target_commit,
        target_software_profile_sha256=profile_sha256,
        binding_path=logical_projection_path,
    )
    reference_provenance = {
        "artifact_sha256": "7" * 64,
        "physical_artifact_path": str(tmp_path / "input-snapshots" / "card.json"),
        "artifact_path": "rq2/inputs/card.json",
    }
    invariant_without_hash = {
        "schema_version": 2,
        "algorithm": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "scope": list(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "replacement": agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(agent_scanner.MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            agent_scanner.MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "projection_input": {
            "kind": "file",
            "status": "frozen",
            "path": logical_projection_path,
            "sha256": projection_digest,
        },
    }
    policy_without_hash = {
        "mode": "host_priority_plan",
        "artifact": {
            "kind": "file",
            "status": "frozen",
            "path": "rq2/inputs/card.json",
            "sha256": "7" * 64,
        },
    }
    bound = agent_scanner.bind_verified_model_input_control(
        projection,
        reference_context={"provenance": reference_provenance},
        unprioritized_schedule=None,
        expected_invariant_stage_sha256=agent_scanner.stable_data_hash(
            invariant_without_hash
        ),
        expected_policy_stage_sha256=agent_scanner.stable_data_hash(
            policy_without_hash
        ),
    )
    runtime_projection = {
        "raw_reference_sha256": "1" * 64,
        "projected_reference_sha256": "2" * 64,
        "raw_static_input_sha256": "3" * 64,
        "projected_static_input_sha256": "4" * 64,
        "invariant_projected_static_input_sha256": "5" * 64,
        "policy_visible_static_input_sha256": "6" * 64,
        "policy_preserved_fields": [
            "target_software.modules[].files",
        ],
    }
    base_projection, split_runtime_projection = (
        agent_scanner._split_model_visible_input_projection_provenance(
            bound,
            {
                **bound["provenance"],
                **runtime_projection,
            },
        )
    )
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    attestation = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_snapshot_sha256
    )
    fingerprint = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2026-0001",
            to_dict=lambda: {"cve_id": "CVE-2026-0001"},
        ),
        software_profile=_mk_profile("target", version=target_commit),
        llm_client=SimpleNamespace(config=SimpleNamespace()),
        max_iterations=1,
        stop_when_critical_complete=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={},
        target_path_projection=base_projection,
        model_visible_input_runtime_projection=split_runtime_projection,
        model_revision="revision-a",
        model_revision_attestation_binding=attestation["binding"],
        endpoint_snapshot=endpoint_snapshot,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_requested=_decoding_config_binding()[0],
        decoding_config_requested_sha256=_decoding_config_binding()[2],
        decoding_config_effective=_decoding_config_binding()[0],
        decoding_config_effective_sha256=_decoding_config_binding()[2],
    )

    persisted = fingerprint["scan_config"]["model_visible_input_projection"]
    assert persisted == bound["provenance"]
    assert persisted["physical_artifact_path"] == str(projection_path)
    assert persisted["artifact_path"] == logical_projection_path
    assert fingerprint["target_path_projection_artifact_sha256"] == (
        projection_digest
    )
    assert fingerprint["scan_config"]["model_input_stage_hashes"] == (
        bound["provenance"]["model_input_stage_hashes"]
    )
    assert fingerprint["scan_config"][
        "model_visible_input_runtime_projection"
    ] == runtime_projection
    assert fingerprint["llm"]["model_revision"] == "revision-a"
    for section in (
        fingerprint["llm"],
        fingerprint["scan_config"],
    ):
        assert (
            section["model_revision_attestation"]
            == attestation["binding"]
        )
    assert fingerprint["llm"]["endpoint_snapshot"] == endpoint_snapshot
    assert (
        fingerprint["llm"]["endpoint_snapshot_sha256"]
        == endpoint_snapshot_sha256
    )
    assert fingerprint["scan_config"]["endpoint_snapshot"] == endpoint_snapshot
    assert (
        fingerprint["scan_config"]["endpoint_snapshot_sha256"]
        == endpoint_snapshot_sha256
    )
    decoding_config = _decoding_config_binding()[0]
    decoding_sha256 = _decoding_config_binding()[2]
    for section in (
        fingerprint["llm"],
        fingerprint["scan_config"],
    ):
        assert section["decoding_config_requested"] == decoding_config
        assert (
            section["decoding_config_requested_sha256"]
            == decoding_sha256
        )
        assert section["decoding_config_effective"] == decoding_config
        assert (
            section["decoding_config_effective_sha256"]
            == decoding_sha256
        )
    for source_path in (
        "scanner/agent/loaders.py",
        "profiler/fingerprint.py",
        "profiler/software/models.py",
        "profiler/vulnerability/models.py",
    ):
        assert source_path in fingerprint["source_hashes"]


@pytest.mark.parametrize("loader_kind", ["reference", "schedule"])
def test_direct_frozen_artifact_loaders_reject_duplicate_json_keys(
    tmp_path, loader_kind
):
    path = tmp_path / f"duplicate-{loader_kind}.json"
    raw = b'{"schema_version":1,"schema_version":1}'
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    with pytest.raises(ValueError, match="duplicate JSON key.*schema_version"):
        if loader_kind == "reference":
            agent_scanner.load_reference_context_envelope(str(path), digest)
        else:
            agent_scanner.load_unprioritized_file_schedule(
                str(path),
                digest,
                target_commit="a" * 40,
            )

def test_unprioritized_schedule_dedupes_profile_overlap_without_module_mapping():
    files = ["src/shared.py", "src/api.py", "src/worker.py"]
    profile = SoftwareProfile(
        name="target",
        modules=[
            ModuleInfo(name="api", files=["src/shared.py", "src/api.py"]),
            ModuleInfo(name="worker", files=["src/shared.py", "src/worker.py"]),
        ],
    )
    schedule = {
        "files": files,
        "provenance": {
            "universe_sha256": agent_scanner.stable_data_hash(sorted(files)),
            "order_sha256": agent_scanner.stable_data_hash(files),
            "page_algorithm": agent_scanner.FROZEN_SCHEDULE_PAGE_ALGORITHM,
            "page_size": agent_scanner.FROZEN_SCHEDULE_PAGE_SIZE,
        },
    }
    deliberately_non_profile_mapping = {
        "schema_version": 1,
        "module_priorities": {"api": 1, "worker": 2},
        "file_to_module": {
            "src/shared.py": "api",
            "src/api.py": "api",
            "src/worker.py": "worker",
        },
    }

    agent_scanner.validate_frozen_scan_controls(
        profile, deliberately_non_profile_mapping, schedule
    )
    with pytest.raises(ValueError, match="file mapping"):
        agent_scanner.validate_frozen_scan_controls(
            profile, deliberately_non_profile_mapping
        )


def test_unprioritized_schedule_rejects_bad_universe_and_order_hashes():
    profile = SoftwareProfile(
        name="target",
        modules=[ModuleInfo(name="api", files=["src/a.py", "src/b.py"])],
    )
    files = ["src/b.py", "src/a.py"]
    valid_provenance = {
        "universe_sha256": agent_scanner.stable_data_hash(sorted(files)),
        "order_sha256": agent_scanner.stable_data_hash(files),
    }

    for hash_field in ("universe_sha256", "order_sha256"):
        provenance = dict(valid_provenance)
        provenance[hash_field] = "bad"
        with pytest.raises(ValueError, match=hash_field):
            agent_scanner.validate_frozen_scan_controls(
                profile, None, {"files": files, "provenance": provenance}
            )


def test_reference_card_rejects_cve_identity_and_cli_exposes_run_controls(monkeypatch, tmp_path):
    model_card = {
        "schema_version": 1,
        "card_id": "CVE-2026-0001",
        "weaknesses": ["CWE-78"],
    }
    host_plan = {
        "schema_version": 1,
        "module_priorities": {"api": 1},
        "file_to_module": {"src/api.py": "api"},
    }
    payload = {
        "schema_version": 1,
        "model_card": model_card,
        "host_priority_plan": host_plan,
        "model_card_sha256": agent_scanner.stable_data_hash(model_card),
        "host_priority_plan_sha256": agent_scanner.stable_data_hash(host_plan),
    }
    path = tmp_path / "reference-card.json"
    digest = _write_frozen_json(path, payload)
    with pytest.raises(ValueError, match="non-CVE opaque identifier"):
        agent_scanner.load_reference_context_envelope(str(path), digest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-scanner", "--vuln-repo", "source", "--cve", "CVE-2026-0001",
            "--target-repo", "target", "--target-commit", "a" * 40,
            "--ablate-reference-semantics", "--reference-card", "reference.json",
            "--reference-card-sha256", "b" * 64,
            "--reference-card-binding-path", "rq2/inputs/reference.json",
            "--target-path-projection-binding-path", "rq2/inputs/projection.json",
            "--ablate-candidate-priority",
            "--unprioritized-file-order", "order.json",
            "--unprioritized-file-order-sha256", "c" * 64,
            "--unprioritized-file-order-binding-path", "rq2/inputs/order.json",
            "--shared-public-memory-dir", "results/shared", "--run-id", "run-7",
        ],
    )
    args = agent_scanner.parse_args()
    assert args.ablate_reference_semantics is True
    assert args.reference_card == "reference.json"
    assert args.reference_card_binding_path == "rq2/inputs/reference.json"
    assert (
        args.target_path_projection_binding_path
        == "rq2/inputs/projection.json"
    )
    assert args.unprioritized_file_order == "order.json"
    assert (
        args.unprioritized_file_order_binding_path
        == "rq2/inputs/order.json"
    )
    assert args.shared_public_memory_dir == "results/shared"
    assert args.run_id == "run-7"

def test_target_selection_failure_provenance_binds_model_and_endpoint_identity(
    tmp_path,
):
    endpoint_snapshot, endpoint_snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    args = Namespace(
        output=str(tmp_path / "selection-failure"),
        similarity_model_name="embedding-model",
        similarity_device="cpu",
        llm_provider="lab",
        llm_name="model-x",
        model_revision="revision-a",
        endpoint_snapshot_json=endpoint_snapshot_json,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_json=_decoding_config_binding()[1],
        decoding_config_sha256=_decoding_config_binding()[2],
        evaluation_mode=True,
        ablate_repo_semantics=False,
        ablate_reference_semantics=False,
        ablate_candidate_priority=False,
        ablate_memory=False,
        ablate_verifier=False,
    )
    error = agent_scanner.EmbeddingUnavailableError(
        "embedding backend unavailable",
        {
            "required": True,
            "fallback_used": False,
        },
    )
    attestation = _model_revision_attestation_binding(
        endpoint_snapshot_sha256=endpoint_snapshot_sha256
    )

    output_path = agent_scanner._write_target_selection_failure_provenance(
        args=args,
        vulnerability_profile={"profile": "reference"},
        started_at=datetime(2026, 8, 1, 10, 0, 0),
        run_id="selection-run-a",
        error=error,
        model_revision_attestation_binding=attestation["binding"],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["llm"] == {
        "provider": "lab",
        "model": "model-x",
        "model_revision": "revision-a",
        "model_revision_attestation": attestation["binding"],
        "endpoint_snapshot": endpoint_snapshot,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "decoding_config_requested": _decoding_config_binding()[0],
        "decoding_config_requested_sha256": _decoding_config_binding()[2],
        "decoding_config_effective": _decoding_config_binding()[0],
        "decoding_config_effective_sha256": _decoding_config_binding()[2],
    }
    assert (
        payload["input_hashes"]["model_revision_attestation_file"]
        == attestation["binding"]["file_sha256"]
    )
    assert (
        payload["input_hashes"]["model_revision_attestation_payload"]
        == attestation["binding"]["payload_sha256"]
    )


def test_main_selection_failure_uses_caller_run_id_and_root_provenance(monkeypatch, tmp_path):
    args = Namespace(
        verbose=False, reference_card=None, unprioritized_file_order=None,
        ablate_reference_semantics=False, vuln_repo="source", cve="CVE-2026-0001",
        target_repo=None, run_id="run-manual", output=str(tmp_path / "out"),
        similarity_model_name="model", similarity_device="cpu",
    )
    vulnerability_profile = {"cve_id": "CVE-2026-0001"}
    captured = {}
    monkeypatch.setattr(agent_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(agent_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(agent_scanner, "_validate_args", lambda parsed: True)
    monkeypatch.setattr(agent_scanner, "_resolve_profile_dirs", lambda parsed: (tmp_path, tmp_path))
    monkeypatch.setattr(
        agent_scanner, "load_vulnerability_profile",
        lambda *args, **kwargs: vulnerability_profile,
    )
    monkeypatch.setattr(
        agent_scanner, "_resolve_auto_targets",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            agent_scanner.EmbeddingUnavailableError(
                "embedding failed", {"required": True, "fallback_used": False}
            )
        ),
    )
    def fake_write_failure(**kwargs):
        captured.update(kwargs)
        return tmp_path / "out" / "run_provenance.json"
    monkeypatch.setattr(
        agent_scanner, "_write_target_selection_failure_provenance", fake_write_failure
    )
    assert agent_scanner.main() == 1
    assert captured["run_id"] == "run-manual"
    assert captured["vulnerability_profile"] is vulnerability_profile
    assert isinstance(captured["error"], agent_scanner.EmbeddingUnavailableError)

def test_main_reference_ablation_never_loads_full_vulnerability_profile(monkeypatch, tmp_path):
    host_plan = {
        "schema_version": 1,
        "module_priorities": {"api": 1},
        "file_to_module": {"src/api.py": "api"},
    }
    model_card = {"schema_version": 1, "card_id": "card-7", "weaknesses": ["CWE-78"]}
    endpoint_snapshot, endpoint_snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    attestation = _model_revision_attestation_binding(
        model_name="model",
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
    )
    args = Namespace(
        verbose=False, reference_card="reference.json", reference_card_sha256="a" * 64,
        unprioritized_file_order=None, ablate_reference_semantics=True,
        vuln_repo="source", cve="CVE-2026-0001", target_repo="target",
        target_commit="b" * 40, llm_provider="lab", llm_name="model",
        llm_max_attempts=3, llm_timeout_seconds=120.0,
        model_revision="revision-a",
        model_revision_attestation="attestation.json",
        model_revision_attestation_sha256="9" * 64,
        model_revision_attestation_binding_path=(
            attestation["binding"]["path"]
        ),
        endpoint_snapshot_json=endpoint_snapshot_json,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_json=_decoding_config_binding()[1],
        decoding_config_sha256=_decoding_config_binding()[2],
        output=str(tmp_path / "out"), repo_base_path=tmp_path / "repos",
        max_iterations=2, stop_when_critical_complete=False, critical_stop_mode="max",
        critical_stop_max_priority=2, profile_base_path=str(tmp_path / "profiles"),
        software_profile_dirname="soft", shared_public_memory_dir=None, run_id="run-7",
        evaluation_mode=True, similarity_model_name="embedding", similarity_device="cpu",
        ablate_repo_semantics=False, ablate_candidate_priority=False,
        ablate_memory=False, ablate_verifier=False,
    )
    captured = {}
    monkeypatch.setattr(agent_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(agent_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(agent_scanner, "_validate_args", lambda parsed: True)
    monkeypatch.setattr(agent_scanner, "_resolve_profile_dirs", lambda parsed: (tmp_path, tmp_path))
    monkeypatch.setattr(
        agent_scanner,
        "require_evaluation_embedding_byte_binding",
        lambda _evaluation_mode: None,
    )
    def fake_load_attestation(*values, **kwargs):
        captured["attestation_load"] = {
            "values": values,
            "kwargs": kwargs,
        }
        return attestation
    monkeypatch.setattr(
        agent_scanner,
        "load_model_revision_attestation",
        fake_load_attestation,
    )
    monkeypatch.setattr(
        agent_scanner, "load_reference_context_envelope",
        lambda *values: {
            "model_card": model_card, "host_priority_plan": host_plan,
            "provenance": {"artifact_sha256": "a" * 64},
        },
    )
    monkeypatch.setattr(
        agent_scanner, "load_vulnerability_profile",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("full vulnerability profile loader must be unreachable")
        ),
    )
    def fake_manual_targets(parsed, vulnerability_profile, repo_profiles_dir):
        captured["selection_profile"] = vulnerability_profile
        return [agent_scanner.ScanTarget("target", "b" * 40)]
    monkeypatch.setattr(agent_scanner, "_resolve_manual_targets", fake_manual_targets)
    def fake_create_llm_client(config):
        captured["llm_config"] = config
        return object()
    monkeypatch.setattr(
        agent_scanner,
        "create_llm_client",
        fake_create_llm_client,
    )
    def fake_run(**kwargs):
        captured["run_kwargs"] = kwargs
        return True
    monkeypatch.setattr(agent_scanner, "run_single_target_scan", fake_run)
    assert agent_scanner.main() == 0
    assert captured["selection_profile"] == model_card
    assert captured["run_kwargs"]["vulnerability_profile"] == model_card
    assert captured["run_kwargs"]["host_priority_plan"] == host_plan
    assert captured["run_kwargs"]["run_id"] == "run-7"
    assert captured["run_kwargs"]["model_revision"] == "revision-a"
    assert (
        captured["run_kwargs"]["model_revision_attestation"]
        == attestation
    )
    assert captured["attestation_load"]["kwargs"] == {
        "provider": "lab",
        "model_name": "model",
        "model_revision": "revision-a",
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
    }
    assert captured["run_kwargs"]["endpoint_snapshot"] == endpoint_snapshot
    assert (
        captured["llm_config"].model_revision
        == "revision-a"
    )
    assert (
        captured["run_kwargs"]["decoding_config_requested"]
        == _decoding_config_binding()[0]
    )
    assert (
        captured["run_kwargs"]["decoding_config_requested_sha256"]
        == _decoding_config_binding()[2]
    )
    for field, value in _decoding_config_binding()[0].items():
        assert getattr(captured["llm_config"], field) == value
    assert (
        captured["llm_config"].fallback_on_retry_exhausted
        is False
    )
    assert captured["llm_config"].enforce_exact_decoding is True
    assert captured["llm_config"].max_retries == 3
    assert captured["llm_config"].timeout == 120.0

def test_main_full_reference_arm_uses_same_frozen_host_plan(monkeypatch, tmp_path):
    host_plan = {
        "schema_version": 1, "module_priorities": {"api": 1},
        "file_to_module": {"src/api.py": "api"},
    }
    full_profile = {"cve_id": "CVE-2026-0001", "dangerous_apis": ["os.system"]}
    args = Namespace(
        verbose=False, reference_card="reference.json", reference_card_sha256="a" * 64,
        unprioritized_file_order=None, ablate_reference_semantics=False,
        vuln_repo="source", cve="CVE-2026-0001", target_repo="target",
        target_commit="b" * 40, llm_provider="lab", llm_name="model",
        model_revision="revision-a",
        output=str(tmp_path / "out"), repo_base_path=tmp_path / "repos",
        max_iterations=2, stop_when_critical_complete=False, critical_stop_mode="max",
        critical_stop_max_priority=2, profile_base_path=str(tmp_path / "profiles"),
        software_profile_dirname="soft", shared_public_memory_dir=None, run_id="run-7",
        evaluation_mode=True, similarity_model_name="embedding", similarity_device="cpu",
        ablate_repo_semantics=False, ablate_candidate_priority=False,
        ablate_memory=False, ablate_verifier=False,
    )
    captured = {}
    monkeypatch.setattr(agent_scanner, "parse_args", lambda: args)
    monkeypatch.setattr(agent_scanner, "setup_logging", lambda verbose: None)
    monkeypatch.setattr(agent_scanner, "_validate_args", lambda parsed: True)
    monkeypatch.setattr(agent_scanner, "_resolve_profile_dirs", lambda parsed: (tmp_path, tmp_path))
    monkeypatch.setattr(
        agent_scanner,
        "require_evaluation_embedding_byte_binding",
        lambda _evaluation_mode: None,
    )
    monkeypatch.setattr(
        agent_scanner, "load_reference_context_envelope",
        lambda *values: {
            "model_card": {"schema_version": 1, "card_id": "card-7", "weaknesses": ["CWE-78"]},
            "host_priority_plan": host_plan, "provenance": {"artifact_sha256": "a" * 64},
        },
    )
    monkeypatch.setattr(agent_scanner, "load_vulnerability_profile", lambda *args, **kwargs: full_profile)
    monkeypatch.setattr(
        agent_scanner, "_resolve_manual_targets",
        lambda parsed, vulnerability_profile, profiles: [
            agent_scanner.ScanTarget("target", "b" * 40)
        ],
    )
    monkeypatch.setattr(agent_scanner, "create_llm_client", lambda config: object())
    def fake_run(**kwargs):
        captured.update(kwargs)
        return True
    monkeypatch.setattr(agent_scanner, "run_single_target_scan", fake_run)
    assert agent_scanner.main() == 0
    assert captured["vulnerability_profile"] is full_profile
    assert captured["host_priority_plan"] == host_plan
    assert captured["reference_context_provenance"]["artifact_sha256"] == "a" * 64
    assert captured["model_revision"] == "revision-a"


def test_build_scan_quality_full_universe_cap_before_progress_is_partial():
    finder = SimpleNamespace(
        require_full_universe_completion=True,
        critical_stop_max_priority=2,
        _is_full_universe_complete=lambda: False,
        memory=SimpleNamespace(
            get_progress=lambda: {
                "completed": 0,
                "pending": 2,
                "total_files": 2,
                "findings": 0,
                "priority_1": {"completed": 0, "total": 1},
                "priority_2": {"completed": 0, "total": 1},
            },
            is_critical_complete=lambda max_priority=2: False,
        ),
    )

    metadata = agent_scanner._build_scan_quality_metadata(finder)

    assert metadata["coverage_status"] == "partial"
    assert metadata["full_universe_required"] is True
    assert metadata["full_universe_complete"] is False
    assert metadata["full_universe_total_files"] == 2
    assert metadata["full_universe_completed_files"] == 0


def test_decoding_config_contract_accepts_exact_null_intent():
    config, config_json, config_sha256 = _decoding_config_binding()

    parsed, parsed_sha256 = agent_scanner.validate_decoding_config_contract(
        config_json,
        config_sha256,
    )

    assert parsed == config
    assert parsed_sha256 == config_sha256
    assert parsed["enable_thinking"] is None
    assert parsed["reasoning_effort"] is None
    assert parsed["service_tier"] is None


def test_decoding_config_contract_rejects_malformed_types_ranges_and_shape():
    valid = _decoding_config_binding()[0]
    invalid_configs = [
        {**valid, "temperature": float("nan")},
        {**valid, "temperature": float("inf")},
        {**valid, "temperature": True},
        {**valid, "temperature": -0.01},
        {**valid, "temperature": 2.01},
        {**valid, "top_p": False},
        {**valid, "top_p": 0},
        {**valid, "top_p": 1.01},
        {**valid, "max_tokens": True},
        {**valid, "max_tokens": 0},
        {**valid, "max_tokens": 1_000_001},
        {**valid, "enable_thinking": "false"},
        {**valid, "reasoning_effort": []},
        {**valid, "reasoning_effort": {}},
        {**valid, "reasoning_effort": "extreme"},
        {**valid, "service_tier": []},
        {**valid, "service_tier": {}},
        {**valid, "service_tier": "premium"},
        {key: value for key, value in valid.items() if key != "top_p"},
        {**valid, "unexpected": None},
    ]
    for config in invalid_configs:
        config_json = json.dumps(
            config,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        config_sha256 = hashlib.sha256(
            config_json.encode("utf-8")
        ).hexdigest()
        with pytest.raises(ValueError):
            agent_scanner.validate_decoding_config_contract(
                config_json,
                config_sha256,
            )


def test_decoding_config_contract_rejects_noncanonical_or_nonexact_hash():
    config, config_json, config_sha256 = _decoding_config_binding()
    noncanonical = json.dumps(config, indent=2, sort_keys=True)

    with pytest.raises(ValueError, match="canonical compact encoding"):
        agent_scanner.validate_decoding_config_contract(
            noncanonical,
            hashlib.sha256(noncanonical.encode("utf-8")).hexdigest(),
        )
    for invalid_sha256 in (
        config_sha256.upper(),
        f" {config_sha256}",
        f"{config_sha256} ",
    ):
        with pytest.raises(ValueError, match="lowercase hexadecimal"):
            agent_scanner.validate_decoding_config_contract(
                config_json,
                invalid_sha256,
            )


def test_validate_args_requires_complete_decoding_binding_in_evaluation_mode():
    assert agent_scanner._validate_args(_valid_evaluation_args()) is True
    assert agent_scanner._validate_args(
        _valid_evaluation_args(decoding_config_json=None)
    ) is False
    assert agent_scanner._validate_args(
        _valid_evaluation_args(decoding_config_sha256=None)
    ) is False


def test_parse_args_accepts_exact_decoding_binding(monkeypatch):
    config, config_json, config_sha256 = _decoding_config_binding()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-scanner",
            "--vuln-repo",
            "VULN_REPO",
            "--cve",
            "CVE-2099-0001",
            "--decoding-config-json",
            config_json,
            "--decoding-config-sha256",
            config_sha256,
        ],
    )

    args = agent_scanner.parse_args()

    assert json.loads(args.decoding_config_json) == config
    assert args.decoding_config_sha256 == config_sha256


def test_parse_args_accepts_model_revision_attestation_binding(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "agent-scanner",
            "--vuln-repo",
            "VULN_REPO",
            "--cve",
            "CVE-2099-0001",
            "--model-revision-attestation",
            "attestation.json",
            "--model-revision-attestation-sha256",
            "9" * 64,
            "--model-revision-attestation-binding-path",
            "rq2/inputs/model-revision-attestations/model-x.json",
        ],
    )

    args = agent_scanner.parse_args()

    assert args.model_revision_attestation == "attestation.json"
    assert args.model_revision_attestation_sha256 == "9" * 64
    assert args.model_revision_attestation_binding_path == (
        "rq2/inputs/model-revision-attestations/model-x.json"
    )


def test_evaluation_rejects_decoding_drift_before_output(tmp_path):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    output_base = tmp_path / "scan-out"
    requested, _requested_json, requested_sha256 = (
        _decoding_config_binding()
    )

    with pytest.raises(
        ValueError,
        match="requested decoding config does not match",
    ):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2099-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                decoding_overrides={"temperature": 0.5},
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256
                )
            ),
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=requested,
            decoding_config_requested_sha256=requested_sha256,
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
        )

    payload = _assert_durable_preflight_failure(
        output_base,
        cve_id="CVE-2099-0001",
    )
    assert (
        payload["input_hashes"]["decoding_config_requested"]
        == requested_sha256
    )
    assert (
        payload["input_hashes"]["decoding_config_effective"]
        != requested_sha256
    )
    assert str(tmp_path) not in json.dumps(payload, sort_keys=True)


def test_evaluation_metadata_cannot_substitute_for_embedding_byte_binding(
    monkeypatch,
    tmp_path,
):
    observed_signature = {
        "resolved_model_path": "/models/metadata-only",
        "artifact_hash": "metadata-hash",
    }
    monkeypatch.setattr(
        agent_scanner,
        "embedding_model_artifact_signature",
        lambda _model_name: observed_signature,
    )
    llm_client = _evaluation_llm_client()
    fingerprint = agent_scanner.build_scan_fingerprint(
        vulnerability_profile=SimpleNamespace(
            cve_id="CVE-2099-0001",
            to_dict=lambda: {"cve_id": "CVE-2099-0001"},
        ),
        software_profile=_mk_profile("target", version="a" * 40),
        llm_client=llm_client,
        max_iterations=1,
        stop_when_critical_complete=False,
        critical_stop_mode="max",
        critical_stop_max_priority=2,
        scan_languages=["python"],
        codeql_database_names={"python": "target-python-db"},
        module_similarity_config={
            "threshold": 0.8,
            "model_name": "metadata-model",
            "device": "cpu",
        },
    )

    assert fingerprint["scan_config"]["module_similarity"] == {
        "threshold": 0.8,
        "model_name": "metadata-model",
        "device": "cpu",
        **observed_signature,
    }
    assert fingerprint["scan_config"][
        "module_similarity_byte_binding"
    ] == {
        "status": "unattested",
        "blocker_code": "consumed-embedding-bytes-unattested",
    }

    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    requested, _requested_json, requested_sha256 = (
        _decoding_config_binding()
    )
    output_base = tmp_path / "scan-out"
    monkeypatch.setattr(
        agent_scanner,
        "get_git_commit",
        lambda *_args, **_kwargs: pytest.fail(
            "evaluation reached repository inspection without embedding bytes"
        ),
    )

    with pytest.raises(
        agent_scanner.EvaluationEvidenceUnavailableError,
        match="consumed-embedding-bytes-unattested",
    ):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2099-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=llm_client,
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256
                )
            ),
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=requested,
            decoding_config_requested_sha256=requested_sha256,
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
            module_similarity_config={
                "threshold": 0.8,
                "model_name": "metadata-model",
                "device": "cpu",
            },
        )

    payload = _assert_durable_preflight_failure(
        output_base,
        cve_id="CVE-2099-0001",
    )
    assert payload["execution"]["failure_control"] == (
        "module_similarity_embedding"
    )
    assert payload["execution"]["failure_class"] == (
        "EvaluationEvidenceUnavailableError"
    )
    assert payload["execution"]["blocker_code"] == (
        "consumed-embedding-bytes-unattested"
    )


@pytest.mark.parametrize(
    ("fallback_on_retry_exhausted", "enforce_exact_decoding", "message"),
    [
        (True, True, "prohibits provider fallback"),
        (False, False, "requires exact decoding enforcement"),
    ],
)
def test_evaluation_rejects_nonexact_runtime_policy_before_output(
    tmp_path,
    fallback_on_retry_exhausted,
    enforce_exact_decoding,
    message,
):
    bound, reference_provenance = _bound_prioritized_evaluation_projection()
    endpoint_snapshot, _snapshot_json, endpoint_snapshot_sha256 = (
        _endpoint_snapshot_binding()
    )
    output_base = tmp_path / "scan-out"
    requested, _requested_json, requested_sha256 = (
        _decoding_config_binding()
    )

    with pytest.raises(ValueError, match=message):
        agent_scanner.run_single_target_scan(
            cve_id="CVE-2099-0001",
            output_base=output_base,
            repo_base_path=tmp_path / "repos",
            max_iterations=1,
            vulnerability_profile={},
            llm_client=_evaluation_llm_client(
                fallback_on_retry_exhausted=(
                    fallback_on_retry_exhausted
                ),
                enforce_exact_decoding=enforce_exact_decoding,
            ),
            target=agent_scanner.ScanTarget("target", "a" * 40),
            evaluation_mode=True,
            model_revision="revision-a",
            model_revision_attestation=(
                _model_revision_attestation_binding(
                    endpoint_snapshot_sha256=endpoint_snapshot_sha256
                )
            ),
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=requested,
            decoding_config_requested_sha256=requested_sha256,
            target_path_projection=bound,
            reference_context_provenance=reference_provenance,
        )

    _assert_durable_preflight_failure(
        output_base,
        cve_id="CVE-2099-0001",
    )


def test_public_scanner_diagnostic_does_not_embed_target_cli_literals():
    source = Path(agent_scanner.__file__).read_text(encoding="utf-8")

    assert "--target-commit requires --target-repo" not in source
    assert "Manual target commits require an explicit target repository" in source


def test_decoding_config_rejects_duplicate_and_raw_nonfinite_without_echo():
    _config, config_json, _config_sha256 = _decoding_config_binding()
    malformed_values = [
        config_json.replace(
            '"service_tier":null',
            '"service_tier":null,"service_tier":"priority"',
        ),
        config_json.replace('"temperature":0.0', '"temperature":NaN'),
        config_json.replace(
            '"temperature":0.0',
            '"temperature":Infinity',
        ),
    ]
    for malformed in malformed_values:
        with pytest.raises(ValueError) as exc_info:
            agent_scanner.validate_decoding_config_contract(
                malformed,
                hashlib.sha256(malformed.encode("utf-8")).hexdigest(),
            )
        assert malformed not in str(exc_info.value)

    secret_sentinel = "secret-" + "sentinel-" + "value"
    malformed = config_json.replace(
        '"reasoning_effort":null',
        json.dumps(
            "reasoning_effort",
        )
        + ":"
        + json.dumps(secret_sentinel),
    )
    with pytest.raises(ValueError) as exc_info:
        agent_scanner.validate_decoding_config_contract(
            malformed,
            hashlib.sha256(malformed.encode("utf-8")).hexdigest(),
        )
    assert secret_sentinel not in str(exc_info.value)
