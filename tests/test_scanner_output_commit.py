from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from cli import agent_scanner, batch_scanner, batch_scanner_execution
from scanner import output_commit

REFERENCE_ID = "CVE-2026-1000"
REPO_NAME = "repo"
COMMIT = "a" * 40


def _stable_hash(payload):
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _fingerprint(run_id: str):
    payload = {
        "schema_version": 1,
        "scan_config": {"run_id": run_id},
    }
    return {**payload, "hash": _stable_hash(payload)}


def _coverage(status: str):
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


def _formal_identity_usage(*, matched: bool = True):
    """构造正式响应身份用量证据。"""
    return {
        "calls_total": 1,
        "response_identity_checks_total": 1,
        "response_identity_matches_total": 1 if matched else 0,
        "response_identity_mismatches_total": 0 if matched else 1,
        "calls_without_response_identity_check": 0,
        "response_identity_all_matched": matched,
        "request_model_ids": ["GLM-5.2"],
        "expected_response_model_ids": ["GLM-5.2"],
        "observed_response_model_ids": [
            "GLM-5.2" if matched else "GLM-5.2-proxy"
        ],
    }


def _write_committed_outputs(run_dir: Path, status: str = "complete"):
    run_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"run-{status}"
    fingerprint = _fingerprint(run_id)
    provenance = {
        "reference_id": REFERENCE_ID,
        "run_id": run_id,
        "repo": {
            "name": REPO_NAME,
            "requested_commit": COMMIT,
            "actual_commit": COMMIT,
        },
        "execution": {
            "status": status,
            "termination": "finished",
            "partial": status == "partial",
            "failure_reason": None,
        },
        "coverage": _coverage(status),
        "scan_fingerprint": fingerprint,
    }
    findings = {
        **_coverage(status),
        "vulnerabilities": [],
        "run_provenance": provenance,
        "scan_fingerprint": fingerprint,
    }
    texts = {
        output_commit.SCAN_FINDINGS_FILENAME: json.dumps(
            findings, indent=2, ensure_ascii=False
        ),
        output_commit.SCAN_PROVENANCE_FILENAME: json.dumps(
            provenance, indent=2, ensure_ascii=False
        ),
        output_commit.SCAN_CONVERSATION_FILENAME: json.dumps(
            [], indent=2, ensure_ascii=False
        ),
    }
    artifact_bytes = {}
    for name, text in texts.items():
        raw = text.encode("utf-8")
        (run_dir / name).write_bytes(raw)
        artifact_bytes[name] = raw
    marker = output_commit.build_scan_output_commit(
        reference_id=REFERENCE_ID,
        terminal_status=status,
        run_id=run_id,
        scan_fingerprint_hash=fingerprint["hash"],
        artifact_bytes=artifact_bytes,
    )
    marker_raw = json.dumps(
        marker, indent=2, ensure_ascii=False
    ).encode("utf-8")
    (run_dir / output_commit.SCAN_OUTPUT_COMMIT_FILENAME).write_bytes(
        marker_raw
    )
    return hashlib.sha256(marker_raw).hexdigest(), fingerprint


@pytest.mark.parametrize(
    ("status", "headline"),
    [("complete", True), ("partial", False)],
)
def test_terminal_marker_distinguishes_headline(status, headline, tmp_path):
    marker_hash, _ = _write_committed_outputs(tmp_path, status)

    validated = output_commit.validate_committed_scan_outputs(
        tmp_path,
        expected_commit_sha256=marker_hash,
        require_complete=False,
    )

    assert validated["terminal_status"] == status
    assert validated["headline_eligible"] is headline
    if not headline:
        with pytest.raises(
            output_commit.ScanOutputCommitError,
            match="not headline eligible",
        ):
            output_commit.validate_committed_scan_outputs(
                tmp_path,
                expected_commit_sha256=marker_hash,
                require_complete=True,
            )


def test_terminal_marker_rejects_boolean_schema_version(tmp_path):
    _marker_hash, _ = _write_committed_outputs(tmp_path)
    marker_path = tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema_version"] = True
    marker_raw = json.dumps(
        marker, indent=2, ensure_ascii=False
    ).encode("utf-8")
    marker_path.write_bytes(marker_raw)

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="schema is unsupported",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=hashlib.sha256(marker_raw).hexdigest(),
        )


def test_external_binding_rejects_self_reseal(tmp_path):
    old_marker_hash, fingerprint = _write_committed_outputs(tmp_path)
    findings_path = tmp_path / output_commit.SCAN_FINDINGS_FILENAME
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    findings["vulnerabilities"] = [{"forged": True}]
    findings_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    artifact_bytes = {
        name: (tmp_path / name).read_bytes()
        for name in (
            output_commit.SCAN_FINDINGS_FILENAME,
            output_commit.SCAN_PROVENANCE_FILENAME,
            output_commit.SCAN_CONVERSATION_FILENAME,
        )
    }
    marker = output_commit.build_scan_output_commit(
        reference_id=REFERENCE_ID,
        terminal_status="complete",
        run_id="run-complete",
        scan_fingerprint_hash=fingerprint["hash"],
        artifact_bytes=artifact_bytes,
    )
    marker_raw = json.dumps(
        marker, indent=2, ensure_ascii=False
    ).encode("utf-8")
    (tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME).write_bytes(
        marker_raw
    )

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="external binding",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=old_marker_hash,
        )


@pytest.mark.parametrize("mutation", ["partial_coverage", "failed_termination"])
def test_complete_commit_rejects_noncomplete_semantics(tmp_path, mutation):
    _marker_hash, fingerprint = _write_committed_outputs(tmp_path)
    findings_path = tmp_path / output_commit.SCAN_FINDINGS_FILENAME
    provenance_path = tmp_path / output_commit.SCAN_PROVENANCE_FILENAME
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if mutation == "partial_coverage":
        coverage = _coverage("partial")
        provenance["coverage"] = coverage
        findings.update(coverage)
    else:
        provenance["execution"]["termination"] = "runtime_failure"
        provenance["execution"]["failure_reason"] = "forged failure"
    findings["run_provenance"] = provenance
    findings_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    provenance_path.write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    artifact_bytes = {
        name: (tmp_path / name).read_bytes()
        for name in (
            output_commit.SCAN_FINDINGS_FILENAME,
            output_commit.SCAN_PROVENANCE_FILENAME,
            output_commit.SCAN_CONVERSATION_FILENAME,
        )
    }
    marker = output_commit.build_scan_output_commit(
        reference_id=REFERENCE_ID,
        terminal_status="complete",
        run_id="run-complete",
        scan_fingerprint_hash=fingerprint["hash"],
        artifact_bytes=artifact_bytes,
    )
    marker_raw = json.dumps(
        marker, indent=2, ensure_ascii=False
    ).encode("utf-8")
    (tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME).write_bytes(
        marker_raw
    )

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="coverage status|failure reason",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=hashlib.sha256(marker_raw).hexdigest(),
            require_complete=False,
        )


def test_state_and_failure_records_invalidate_old_marker(tmp_path):
    _write_committed_outputs(tmp_path)
    agent_scanner._write_run_state(  # pylint: disable=protected-access
        tmp_path,
        {"execution": {"status": "running"}},
    )
    assert not (
        tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME
    ).exists()
    assert (tmp_path / output_commit.SCAN_RUN_STATE_FILENAME).is_file()

    agent_scanner._write_run_failure(  # pylint: disable=protected-access
        tmp_path,
        {
            "execution": {
                "status": "failed",
                "termination": "runtime_failure",
            }
        },
    )
    assert not (tmp_path / output_commit.SCAN_RUN_STATE_FILENAME).exists()
    saved = batch_scanner_execution._load_saved_scan_quality(tmp_path)
    assert saved["run_provenance_source"] == "failure"
    assert saved["run_status"] == "failed"
    assert saved["terminal_commit_valid"] is False


def test_complete_evaluation_output_rejects_mismatched_response_identity(
    monkeypatch,
    tmp_path,
):
    fingerprint = _fingerprint("run-identity-mismatch")
    provenance = {
        "reference_id": REFERENCE_ID,
        "run_id": "run-identity-mismatch",
        "repo": {
            "name": REPO_NAME,
            "requested_commit": COMMIT,
            "actual_commit": COMMIT,
        },
        "execution": {
            "status": "complete",
            "termination": "finished",
            "partial": False,
            "failure_reason": None,
        },
        "coverage": _coverage("complete"),
        "scan_fingerprint": fingerprint,
        "evaluation_mode": True,
        "usage": _formal_identity_usage(matched=False),
    }
    monkeypatch.setattr(
        agent_scanner,
        "_build_scan_quality_metadata",
        lambda _finder: _coverage("complete"),
    )

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="response identity evidence",
    ):
        agent_scanner._save_scan_outputs(  # pylint: disable=protected-access
            tmp_path,
            SimpleNamespace(conversation_history=[]),
            {"vulnerabilities": []},
            agent_scanner.ScanTarget(REPO_NAME, COMMIT),
            scan_fingerprint=fingerprint,
            run_provenance=provenance,
        )

    assert not (
        tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME
    ).exists()


def test_failure_sidecar_cannot_coexist_with_terminal_marker(tmp_path):
    marker_hash, _ = _write_committed_outputs(tmp_path)
    (tmp_path / output_commit.SCAN_RUN_FAILURE_FILENAME).write_text(
        json.dumps({"execution": {"status": "failed"}}),
        encoding="utf-8",
    )

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="running/failure record",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=marker_hash,
        )


@pytest.mark.parametrize("crash_after", [1, 2, 3, 4])
def test_marker_is_last_publish_point(monkeypatch, tmp_path, crash_after):
    fingerprint = _fingerprint("run-crash")
    provenance = {
        "reference_id": REFERENCE_ID,
        "run_id": "run-crash",
        "repo": {
            "name": REPO_NAME,
            "requested_commit": COMMIT,
            "actual_commit": COMMIT,
        },
        "execution": {
            "status": "complete",
            "termination": "finished",
            "partial": False,
            "failure_reason": None,
        },
        "coverage": _coverage("complete"),
        "scan_fingerprint": fingerprint,
    }
    finder = SimpleNamespace(conversation_history=[])
    monkeypatch.setattr(
        agent_scanner,
        "_build_scan_quality_metadata",
        lambda _finder: _coverage("complete"),
    )
    original_write = agent_scanner._write_atomic_text_durable
    writes = 0

    def crash_after_write(path, content):
        nonlocal writes
        original_write(path, content)
        writes += 1
        if writes == crash_after:
            raise RuntimeError("simulated crash")

    monkeypatch.setattr(
        agent_scanner,
        "_write_atomic_text_durable",
        crash_after_write,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        agent_scanner._save_scan_outputs(  # pylint: disable=protected-access
            tmp_path,
            finder,
            {"vulnerabilities": []},
            agent_scanner.ScanTarget("repo", "a" * 40),
            scan_fingerprint=fingerprint,
            run_provenance=provenance,
        )

    marker_path = tmp_path / output_commit.SCAN_OUTPUT_COMMIT_FILENAME
    if crash_after < 4:
        assert not marker_path.exists()
    else:
        marker_hash = output_commit.scan_output_commit_sha256(tmp_path)
        validated = output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=marker_hash,
        )
        assert validated["headline_eligible"] is True


def test_same_byte_replacement_during_read_is_rejected(monkeypatch, tmp_path):
    filename = output_commit.SCAN_CONVERSATION_FILENAME
    path = tmp_path / filename
    raw = b"same bytes"
    path.write_bytes(raw)
    replacement = tmp_path / "replacement.tmp"
    replacement.write_bytes(raw)
    directory_fd = output_commit._open_directory_without_symlinks(  # pylint: disable=protected-access
        tmp_path
    )
    real_read = output_commit.os.read
    replaced = False

    def replace_during_read(file_fd, size):
        nonlocal replaced
        data = real_read(file_fd, size)
        if data and not replaced:
            replacement.replace(path)
            replaced = True
        return data

    monkeypatch.setattr(output_commit.os, "read", replace_during_read)
    try:
        with pytest.raises(
            output_commit.ScanOutputCommitError,
            match="changed while reading",
        ):
            output_commit._read_regular_file_at(  # pylint: disable=protected-access
                directory_fd,
                filename,
            )
    finally:
        os.close(directory_fd)


def test_commit_rejects_artifact_changed_after_its_read(
    monkeypatch, tmp_path
):
    marker_hash, _ = _write_committed_outputs(tmp_path)
    findings_path = tmp_path / output_commit.SCAN_FINDINGS_FILENAME
    directory_before = output_commit._stable_stat_identity(  # pylint: disable=protected-access
        tmp_path.stat()
    )
    real_read = output_commit._read_regular_file_at  # pylint: disable=protected-access
    changed = False

    def read_then_change(directory_fd, filename):
        nonlocal changed
        raw = real_read(directory_fd, filename)
        if filename == output_commit.SCAN_FINDINGS_FILENAME and not changed:
            offset = raw.index(b'"vulnerabilities": []') + len(
                b'"vulnerabilities": '
            )
            file_fd = os.open(
                findings_path,
                os.O_RDWR | os.O_NOFOLLOW,
            )
            try:
                os.pwrite(file_fd, b"{}", offset)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            changed = True
        return raw

    monkeypatch.setattr(
        output_commit,
        "_read_regular_file_at",
        read_then_change,
    )
    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="changed during validation",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=marker_hash,
        )
    assert output_commit._stable_stat_identity(  # pylint: disable=protected-access
        tmp_path.stat()
    ) == directory_before


def test_commit_rejects_oversized_opaque_artifact(monkeypatch, tmp_path):
    marker_hash, _ = _write_committed_outputs(tmp_path)
    conversation_size = (
        tmp_path / output_commit.SCAN_CONVERSATION_FILENAME
    ).stat().st_size
    monkeypatch.setattr(
        output_commit,
        "_MAX_OPAQUE_ARTIFACT_BYTES",
        conversation_size - 1,
    )

    with pytest.raises(
        output_commit.ScanOutputCommitError,
        match="size limit",
    ):
        output_commit.validate_committed_scan_outputs(
            tmp_path,
            expected_commit_sha256=marker_hash,
        )


def test_scan_output_commit_manifest_round_trip(tmp_path):
    marker_sha256 = "b" * 64
    summary = {
        "status": "complete",
        "partial": False,
        "termination": "batch_finished",
        "failure_reason": None,
        "total_scans": 1,
        "successful_scans": 1,
        "skipped_scans": 0,
        "incomplete_scans": 0,
        "failed_profile_generation": 0,
        "invalid_vuln_entries": 0,
        "zero_target_vulnerabilities": 0,
        "failed_scans": 0,
        "coverage_complete_scans": 1,
        "coverage_partial_scans": 0,
        "coverage_empty_scans": 0,
        "coverage_unknown_scans": 0,
        "entries": [
            {
                "cve_id": REFERENCE_ID,
                "scan_results": [
                    {
                        "repo_name": REPO_NAME,
                        "commit_hash": COMMIT,
                        "status": "ok",
                        "headline_eligible": True,
                        "scan_output_commit_sha256": marker_sha256,
                    }
                ],
            }
        ],
    }
    summary_raw = json.dumps(summary, indent=2).encode("utf-8")
    summary_path = tmp_path / "batch-summary-fixture.json"
    summary_path.write_bytes(summary_raw)
    payload = {
        "schema_version": 2,
        "kind": "scanner_output_commit_bindings",
        "batch_summary": {
            "path": summary_path.name,
            "sha256": hashlib.sha256(summary_raw).hexdigest(),
        },
        "bindings": [
            {
                "cve_id": REFERENCE_ID,
                "repo_name": REPO_NAME,
                "commit": COMMIT,
                "scan_output_commit_sha256": marker_sha256,
            }
        ],
    }
    raw = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    path = tmp_path / "scan-output-commit-bindings-fixture.json"
    path.write_bytes(raw)

    loaded = batch_scanner.load_scan_output_commit_manifest(
        path,
        hashlib.sha256(raw).hexdigest(),
    )

    key = batch_scanner_execution.scan_output_binding_key(
        REFERENCE_ID, REPO_NAME, COMMIT
    )
    assert loaded["bindings"] == {key: marker_sha256}
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        batch_scanner.load_scan_output_commit_manifest(path, "c" * 64)

    payload["schema_version"] = True
    boolean_raw = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
    path.write_bytes(boolean_raw)
    with pytest.raises(ValueError, match="schema_version=2"):
        batch_scanner.load_scan_output_commit_manifest(
            path,
            hashlib.sha256(boolean_raw).hexdigest(),
        )


def test_batch_summary_exports_terminal_binding_manifest(tmp_path):
    marker_sha256 = "b" * 64
    summary = {
        "status": "complete",
        "partial": False,
        "termination": "batch_finished",
        "failure_reason": None,
        "total_scans": 1,
        "successful_scans": 1,
        "skipped_scans": 0,
        "incomplete_scans": 0,
        "failed_profile_generation": 0,
        "invalid_vuln_entries": 0,
        "zero_target_vulnerabilities": 0,
        "failed_scans": 0,
        "coverage_complete_scans": 1,
        "coverage_partial_scans": 0,
        "coverage_empty_scans": 0,
        "coverage_unknown_scans": 0,
        "entries": [
            {
                "cve_id": REFERENCE_ID,
                "scan_results": [
                    {
                        "repo_name": REPO_NAME,
                        "commit_hash": COMMIT,
                        "status": "ok",
                        "headline_eligible": True,
                        "scan_output_commit_sha256": marker_sha256,
                    }
                ],
            }
        ]
    }
    summary_path = tmp_path / "batch-summary-fixture.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    manifest_path, manifest_sha256 = (
        batch_scanner._write_scan_output_commit_manifest(  # pylint: disable=protected-access
            summary,
            summary_path,
        )
    )
    loaded = batch_scanner.load_scan_output_commit_manifest(
        manifest_path,
        manifest_sha256,
    )

    key = batch_scanner_execution.scan_output_binding_key(
        REFERENCE_ID, REPO_NAME, COMMIT
    )
    assert loaded["bindings"] == {key: marker_sha256}
