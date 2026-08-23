#!/usr/bin/env python3
"""Scan execution helpers for the batch scanning pipeline."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
import multiprocessing
import os
from pathlib import Path
import queue
import re
import signal
import time
import uuid
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from config import _path_config
from llm import LLMConfig, create_llm_client
from profiler.fingerprint import stable_data_hash
from scanner.agent.shared_memory import SharedPublicMemoryManager
from scanner.output_commit import (
    SCAN_FINDINGS_FILENAME,
    SCAN_OUTPUT_COMMIT_FILENAME,
    SCAN_PROVENANCE_FILENAME,
    SCAN_RUN_FAILURE_FILENAME,
    SCAN_RUN_STATE_FILENAME,
    ScanOutputCommitError,
    canonical_scan_commit,
    canonical_scan_reference_id,
    canonical_scan_repo_name,
    validate_committed_scan_outputs,
)
from scanner.similarity import SimilarProfileCandidate
from utils.git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from utils.logger import get_logger
from utils.repo_lock import hold_repo_lock

try:
    from cli import agent_scanner
except ImportError:  # pragma: no cover - direct script execution fallback
    import agent_scanner

logger = get_logger(__name__)


def _resolve_shared_public_memory_dir_from_args(
    batch_args: argparse.Namespace,
) -> Optional[Path]:
    """Resolve the run-scoped shared public memory directory from batch args."""
    if getattr(batch_args, "ablate_memory", False):
        return None
    configured_dir = getattr(batch_args, "shared_public_memory_dir", None)
    if configured_dir:
        path = Path(str(configured_dir)).expanduser()
        return path if path.is_absolute() else _path_config["repo_root"] / path

    run_id = str(getattr(batch_args, "run_id", "") or "").strip()
    if not run_id:
        return None

    scan_output_dir = Path(str(getattr(batch_args, "scan_output_dir", ""))).expanduser()
    if not scan_output_dir.is_absolute():
        scan_output_dir = _path_config["repo_root"] / scan_output_dir
    sanitized_run_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip("-") or "run"
    return scan_output_dir / "_runs" / sanitized_run_id / "shared-public-memory"


def _build_shared_public_memory_scope(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    repo_path: Path,
    repo_name: str,
    repo_commit: str,
) -> Dict[str, Any]:
    """Build the shared-public-memory scope descriptor used by fingerprints."""
    shared_public_memory_dir = _resolve_shared_public_memory_dir_from_args(batch_args)
    if shared_public_memory_dir is None:
        return {"enabled": False, "root_hash": "", "scope_key": "", "state_hash": ""}
    manager = SharedPublicMemoryManager(
        root_dir=shared_public_memory_dir,
        repo_name=repo_name,
        repo_commit=repo_commit,
        repo_scope_key=stable_data_hash(str(repo_path.resolve()))[:12],
        producer_id="",
        visibility_scope_id=agent_scanner.build_shared_public_memory_visibility_scope_id(
            cve_id=cve_id,
            target_repo=repo_name,
            target_commit=repo_commit,
            target_output_dir=agent_scanner.resolve_output_dir(
                cve_id=cve_id,
                target_repo=repo_name,
                target_commit=repo_commit,
                output_base=str(getattr(batch_args, "scan_output_dir", "")),
            ),
        ),
    )
    return manager.describe_scope()


def _resolve_software_profile_locator(
    batch_args: argparse.Namespace,
) -> tuple[str | None, str]:
    """Resolve the software-profile locator passed through to agent scanning."""
    profile_base_path = getattr(batch_args, "profile_base_path", None)
    software_profile_dirname = str(getattr(batch_args, "target_soft_profiles_dir", "")).strip()
    return (
        None if profile_base_path is None else str(profile_base_path),
        software_profile_dirname,
    )


def _resolve_hash_bound_profile_for_fingerprint(
    *,
    batch_args: argparse.Namespace,
    target: SimilarProfileCandidate,
    unprioritized_file_schedule: Optional[Dict[str, Any]],
) -> Any:
    """决定候选消融跳过前重载精确哈希绑定画像。"""
    if not agent_scanner.ablation_config_from_args(batch_args)["candidate_priority"]:
        return target.profile_ref.profile
    expected_sha256 = agent_scanner._resolve_scheduled_target_profile_sha256(  # pylint: disable=protected-access
        unprioritized_file_schedule
    )
    profile_base_path, software_profile_dirname = _resolve_software_profile_locator(
        batch_args
    )
    software_profiles_dir = agent_scanner._resolve_soft_profiles_dir_for_scan(  # pylint: disable=protected-access
        profile_base_path=profile_base_path,
        software_profile_dirname=software_profile_dirname,
    )
    software_profile = agent_scanner._load_hash_bound_software_profile(  # pylint: disable=protected-access
        repo_name=target.profile_ref.repo_name,
        commit_hash=target.profile_ref.commit_hash,
        base_dir=software_profiles_dir,
        expected_sha256=expected_sha256,
    )
    agent_scanner.validate_frozen_scan_controls(
        software_profile,
        None,
        unprioritized_file_schedule,
    )
    return software_profile


def _resolve_module_similarity_config_from_args(
    batch_args: argparse.Namespace,
) -> Dict[str, Any]:
    """Resolve module-similarity overrides passed through batch CLI args."""
    return {
        "model_name": getattr(batch_args, "similarity_model_name", None),
        "device": getattr(batch_args, "similarity_device", None),
        "require_embedding": bool(getattr(batch_args, "evaluation_mode", False)),
    }


def _scan_output_signature(
    output_dir: Path,
) -> Tuple[Tuple[str, int, int, int, int, int, int], ...]:
    """记录输出文件身份；同字节替换也会改变签名。"""
    signatures: List[Tuple[str, int, int, int, int, int, int]] = []
    for filename in (
        SCAN_FINDINGS_FILENAME,
        "scan_memory.json",
        SCAN_PROVENANCE_FILENAME,
        SCAN_OUTPUT_COMMIT_FILENAME,
        SCAN_RUN_STATE_FILENAME,
        SCAN_RUN_FAILURE_FILENAME,
    ):
        path = output_dir / filename
        try:
            stat_result = path.lstat()
        except FileNotFoundError:
            continue
        signatures.append(
            (
                filename,
                int(stat_result.st_dev),
                int(stat_result.st_ino),
                int(stat_result.st_mode),
                int(stat_result.st_size),
                int(stat_result.st_mtime_ns),
                int(stat_result.st_ctime_ns),
            )
        )
    return tuple(signatures)


def scan_output_binding_key(cve_id: str, repo_name: str, commit: str) -> str:
    """返回 batch 与 RQ2 共用的终态绑定键。"""
    return ":".join(
        (
            canonical_scan_reference_id(cve_id),
            canonical_scan_repo_name(repo_name),
            canonical_scan_commit(commit),
        )
    )


def _expected_scan_output_commit_sha256(
    batch_args: argparse.Namespace,
    *,
    cve_id: str,
    repo_name: str,
    commit: str,
) -> Optional[str]:
    bindings = getattr(batch_args, "scan_output_commit_hashes", None)
    if not isinstance(bindings, dict):
        return None
    value = bindings.get(scan_output_binding_key(cve_id, repo_name, commit))
    if (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    ):
        return value
    return None


def _build_expected_scan_fingerprint_for_skip(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    llm_client: Any,
    target: SimilarProfileCandidate,
    scan_target: Any,
    target_repo_path: Path,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Build the skip-existing fingerprint against the exact target checkout tree."""
    if not target_repo_path.is_dir():
        return None
    lock_purpose = f"skip_scan_fingerprint:{cve_id}:{scan_target.commit_hash[:12]}"
    with hold_repo_lock(target_repo_path, purpose=lock_purpose):
        original_commit = get_git_commit(str(target_repo_path))
        original_restore_target = get_git_restore_target(str(target_repo_path))
        changed_commit = False
        restore_error: Optional[RuntimeError] = None
        expected_scan_fingerprint: Optional[Dict[str, Any]] = None

        try:
            needs_checkout = original_commit != scan_target.commit_hash
            if needs_checkout and not original_restore_target:
                logger.warning(
                    "Unable to resolve original git position for %s while validating skip-existing fingerprint",
                    scan_target.repo_name,
                )
                return None
            if has_uncommitted_changes(str(target_repo_path)):
                logger.warning(
                    "Repository %s has local changes; skip-existing fingerprint validation requires a clean tree",
                    scan_target.repo_name,
                )
                return None
            if needs_checkout:
                if not checkout_commit(str(target_repo_path), scan_target.commit_hash):
                    logger.warning(
                        "Failed to checkout %s to %s for skip-existing fingerprint validation",
                        scan_target.repo_name,
                        scan_target.commit_hash[:12],
                    )
                    return None
                changed_commit = True

            fingerprint_profile = _resolve_hash_bound_profile_for_fingerprint(
                batch_args=batch_args,
                target=target,
                unprioritized_file_schedule=unprioritized_file_schedule,
            )
            scan_languages = agent_scanner._resolve_scan_languages(  # pylint: disable=protected-access
                target_repo_path,
                fingerprint_profile,
            )
            codeql_database_names = agent_scanner._resolve_codeql_database_names(  # pylint: disable=protected-access
                scan_target,
                scan_languages,
                fingerprint_profile,
            )
            expected_scan_fingerprint = agent_scanner.build_scan_fingerprint(
                vulnerability_profile=vulnerability_profile,
                software_profile=fingerprint_profile,
                llm_client=llm_client,
                max_iterations=batch_args.max_iterations_cap,
                stop_when_critical_complete=not batch_args.disable_critical_stop,
                critical_stop_mode=batch_args.critical_stop_mode,
                critical_stop_max_priority=getattr(batch_args, "critical_stop_max_priority", 2),
                require_full_universe_completion=bool(
                    getattr(batch_args, "require_full_universe_completion", False)
                ),
                scan_languages=scan_languages,
                codeql_database_names=codeql_database_names,
                shared_public_memory_scope=_build_shared_public_memory_scope(
                    batch_args=batch_args,
                    cve_id=cve_id,
                    repo_path=target_repo_path,
                    repo_name=scan_target.repo_name,
                    repo_commit=scan_target.commit_hash,
                ),
                module_similarity_config=_resolve_module_similarity_config_from_args(batch_args),
                ablation_config=agent_scanner.ablation_config_from_args(batch_args),
                unprioritized_file_schedule=unprioritized_file_schedule,
                run_id=getattr(batch_args, "run_id", None),
            )
        finally:
            if changed_commit and original_restore_target:
                restored = restore_git_position(str(target_repo_path), original_restore_target)
                if not restored:
                    restore_error = RuntimeError(
                        "Failed to restore "
                        f"{scan_target.repo_name} after skip-existing fingerprint validation"
                    )
        if restore_error is not None:
            raise restore_error
        return expected_scan_fingerprint


def _build_profile_based_scan_fingerprint_for_skip(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    llm_client: Any,
    target: SimilarProfileCandidate,
    scan_target: Any,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Build one skip-existing fingerprint using only persisted profile metadata."""
    fingerprint_profile = _resolve_hash_bound_profile_for_fingerprint(
        batch_args=batch_args,
        target=target,
        unprioritized_file_schedule=unprioritized_file_schedule,
    )
    repo_analysis = agent_scanner._extract_repo_analysis(  # pylint: disable=protected-access
        fingerprint_profile
    )
    profile_languages = []
    configured_languages = repo_analysis.get("languages", [])
    if isinstance(configured_languages, list):
        profile_languages = agent_scanner._dedupe_languages(configured_languages)  # pylint: disable=protected-access
    if not profile_languages:
        configured_codeql_languages = repo_analysis.get("codeql_languages", [])
        if isinstance(configured_codeql_languages, list):
            profile_languages = agent_scanner._dedupe_languages(  # pylint: disable=protected-access
                configured_codeql_languages
            )
    if not profile_languages:
        return None

    codeql_database_names = agent_scanner._resolve_codeql_database_names(  # pylint: disable=protected-access
        scan_target,
        profile_languages,
        fingerprint_profile,
    )
    target_repos_root = Path(
        str(getattr(batch_args, "target_repos_root", _path_config["repo_base_path"]))
    ).expanduser()
    if not target_repos_root.is_absolute():
        target_repos_root = _path_config["repo_root"] / target_repos_root
    target_repo_path = target_repos_root / scan_target.repo_name
    return agent_scanner.build_scan_fingerprint(
        vulnerability_profile=vulnerability_profile,
        software_profile=fingerprint_profile,
        llm_client=llm_client,
        max_iterations=batch_args.max_iterations_cap,
        stop_when_critical_complete=not batch_args.disable_critical_stop,
        critical_stop_mode=batch_args.critical_stop_mode,
        critical_stop_max_priority=getattr(batch_args, "critical_stop_max_priority", 2),
        require_full_universe_completion=bool(
            getattr(batch_args, "require_full_universe_completion", False)
        ),
        scan_languages=profile_languages,
        codeql_database_names=codeql_database_names,
        shared_public_memory_scope=_build_shared_public_memory_scope(
            batch_args=batch_args,
            cve_id=cve_id,
            repo_path=target_repo_path,
            repo_name=scan_target.repo_name,
            repo_commit=scan_target.commit_hash,
        ),
        module_similarity_config=_resolve_module_similarity_config_from_args(batch_args),
        ablation_config=agent_scanner.ablation_config_from_args(batch_args),
        unprioritized_file_schedule=unprioritized_file_schedule,
        run_id=getattr(batch_args, "run_id", None),
    )


def _run_target_scan(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    llm_client: Any,
    target: SimilarProfileCandidate,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
    terminal_binding_out: Optional[Dict[str, str]] = None,
) -> Literal["ok", "skipped", "incomplete", "failed"]:
    """Run one target repository scan with skip-existing validation."""
    profile_base_path, software_profile_dirname = _resolve_software_profile_locator(batch_args)
    scan_target = agent_scanner.ScanTarget(
        repo_name=target.profile_ref.repo_name,
        commit_hash=target.profile_ref.commit_hash,
        similarity=target,
        selection_provenance=getattr(batch_args, "selection_similarity_provenance", None),
    )
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=scan_target.repo_name,
        target_commit=scan_target.commit_hash,
        output_base=str(getattr(batch_args, "scan_output_dir", str(_path_config["results_base_path"] / "scan-results-batch"))),
    )
    findings_path = output_dir / "agentic_vuln_findings.json"
    marker_path = output_dir / SCAN_OUTPUT_COMMIT_FILENAME
    resolved_target_repos_root = Path(batch_args.target_repos_root).expanduser()
    if not resolved_target_repos_root.is_absolute():
        resolved_target_repos_root = _path_config["repo_root"] / resolved_target_repos_root
    target_repo_path = resolved_target_repos_root / scan_target.repo_name
    if batch_args.skip_existing_scans and not getattr(batch_args, "force_regenerate_profiles", False):
        if (
            getattr(batch_args, "skip_any_existing_scan_result", False)
            and findings_path.is_file()
        ):
            logger.info(
                "[Skip] Existing scan result present without validation: %s",
                findings_path,
            )
            return "skipped"
        if marker_path.exists() or findings_path.exists():
            expected_commit_sha256 = _expected_scan_output_commit_sha256(
                batch_args,
                cve_id=cve_id,
                repo_name=scan_target.repo_name,
                commit=scan_target.commit_hash,
            )
            saved_quality = _load_saved_scan_quality(
                output_dir,
                expected_commit_sha256=expected_commit_sha256,
                expected_reference_id=cve_id,
                expected_repo_name=scan_target.repo_name,
                expected_commit=scan_target.commit_hash,
            )
            coverage_status = str(saved_quality.get("coverage_status", "unknown"))
            current_run_status = saved_quality.get("run_status")
            current_provenance_present = (
                saved_quality.get("run_provenance_source") == "committed"
            )
            saved_fingerprint_hash = str(saved_quality.get("scan_fingerprint_hash", "")).strip()
            expected_scan_fingerprint = _build_expected_scan_fingerprint_for_skip(
                batch_args=batch_args,
                cve_id=cve_id,
                vulnerability_profile=vulnerability_profile,
                llm_client=llm_client,
                target=target,
                scan_target=scan_target,
                target_repo_path=target_repo_path,
                unprioritized_file_schedule=unprioritized_file_schedule,
            )
            fingerprint_validation_mode = "live"
            if not isinstance(expected_scan_fingerprint, dict) and not target_repo_path.is_dir():
                expected_scan_fingerprint = _build_profile_based_scan_fingerprint_for_skip(
                    batch_args=batch_args,
                    cve_id=cve_id,
                    vulnerability_profile=vulnerability_profile,
                    llm_client=llm_client,
                    target=target,
                    scan_target=scan_target,
                    unprioritized_file_schedule=unprioritized_file_schedule,
                )
                fingerprint_validation_mode = "profile"
            elif not isinstance(expected_scan_fingerprint, dict):
                logger.warning(
                    "[Skip->Rescan] Live target fingerprint validation failed for existing checkout: %s",
                    target_repo_path,
                )
            expected_fingerprint_hash = (
                str(expected_scan_fingerprint.get("hash", "")).strip()
                if isinstance(expected_scan_fingerprint, dict)
                else ""
            )
            if not saved_quality.get("terminal_commit_valid"):
                logger.warning(
                    "[Skip->Rescan] Existing outputs lack a valid externally bound marker: %s (%s)",
                    output_dir,
                    saved_quality.get(
                        "scan_output_commit_error",
                        "missing external marker binding",
                    ),
                )
            elif current_provenance_present and current_run_status != "complete":
                logger.warning(
                    "[Skip->Rescan] Current scan attempt is not complete: %s (%s)",
                    findings_path,
                    current_run_status,
                )
            elif coverage_status != "complete":
                logger.warning(
                    "[Skip->Rescan] Existing scan result lacks complete coverage metadata: %s (%s)",
                    findings_path,
                    coverage_status,
                )
            elif isinstance(expected_scan_fingerprint, dict) and expected_fingerprint_hash:
                if saved_fingerprint_hash and saved_fingerprint_hash == expected_fingerprint_hash:
                    logger.info(
                        "[Skip] Existing scan result (%s fingerprint validation): %s",
                        fingerprint_validation_mode,
                        findings_path,
                    )
                    if terminal_binding_out is not None:
                        terminal_binding_out[
                            "scan_output_commit_sha256"
                        ] = expected_commit_sha256
                    return "skipped"
                if not saved_fingerprint_hash:
                    logger.warning(
                        "[Skip->Rescan] Existing scan fingerprint is missing: %s",
                        findings_path,
                    )
                else:
                    logger.warning(
                        "[Skip->Rescan] Existing scan fingerprint mismatch (%s validation): %s "
                        "(saved=%s expected=%s)",
                        fingerprint_validation_mode,
                        findings_path,
                        saved_fingerprint_hash,
                        expected_fingerprint_hash,
                    )
            else:
                logger.warning(
                    "[Skip->Rescan] Existing scan fingerprint validation unavailable or missing: %s (saved=%s)",
                    findings_path,
                    saved_fingerprint_hash or "missing",
                )

    # 一旦决定重跑，旧 marker 立即失效；本次失败不能回落到旧终态。
    agent_scanner._invalidate_scan_output_commit(  # pylint: disable=protected-access
        output_dir
    )
    pre_run_signature = _scan_output_signature(output_dir)
    scan_outcome = agent_scanner.run_single_target_scan(
        cve_id=cve_id,
        output_base=batch_args.scan_output_dir,
        repo_base_path=batch_args.target_repos_root,
        max_iterations=batch_args.max_iterations_cap,
        vulnerability_profile=vulnerability_profile,
        llm_client=llm_client,
        target=scan_target,
        verbose=batch_args.verbose,
        stop_when_critical_complete=not batch_args.disable_critical_stop,
        critical_stop_mode=batch_args.critical_stop_mode,
        critical_stop_max_priority=getattr(batch_args, "critical_stop_max_priority", 2),
        require_full_universe_completion=bool(
            getattr(batch_args, "require_full_universe_completion", False)
        ),
        profile_base_path=profile_base_path,
        software_profile_dirname=software_profile_dirname,
        shared_public_memory_dir=_resolve_shared_public_memory_dir_from_args(batch_args),
        ablation_config=agent_scanner.ablation_config_from_args(batch_args),
        evaluation_mode=bool(getattr(batch_args, "evaluation_mode", False)),
        run_id=getattr(batch_args, "run_id", None),
        selection_similarity_provenance=getattr(
            batch_args, "selection_similarity_provenance", None
        ),
        module_similarity_config=_resolve_module_similarity_config_from_args(batch_args),
        unprioritized_file_schedule=unprioritized_file_schedule,
        return_terminal_receipt=True,
    )
    post_run_signature = _scan_output_signature(output_dir)
    expected_commit_sha256: Optional[str] = None
    scan_succeeded = False
    if isinstance(scan_outcome, dict):
        scan_succeeded = scan_outcome.get("succeeded") is True
        candidate_hash = scan_outcome.get("scan_output_commit_sha256")
        if candidate_hash is not None:
            candidate_hash = str(candidate_hash)
            if re.fullmatch(r"[0-9a-f]{64}", candidate_hash):
                expected_commit_sha256 = candidate_hash
        receipt_identity_valid = (
            scan_outcome.get("cve_id") == cve_id
            and scan_outcome.get("repo_name") == scan_target.repo_name
            and scan_outcome.get("commit") == scan_target.commit_hash
        )
        if not receipt_identity_valid:
            logger.error(
                "Scanner terminal receipt identity mismatch: %s",
                output_dir,
            )
            expected_commit_sha256 = None
            scan_succeeded = False
    else:
        logger.error(
            "Scanner did not return a terminal receipt: %s",
            output_dir,
        )
    saved_quality = _load_saved_scan_quality(
        output_dir,
        expected_commit_sha256=expected_commit_sha256,
        expected_reference_id=cve_id,
        expected_repo_name=scan_target.repo_name,
        expected_commit=scan_target.commit_hash,
    )
    if (
        saved_quality.get("terminal_commit_valid")
        and expected_commit_sha256 is not None
        and terminal_binding_out is not None
    ):
        terminal_binding_out["scan_output_commit_sha256"] = (
            expected_commit_sha256
        )
    if scan_succeeded:
        if not saved_quality.get("terminal_commit_valid"):
            logger.error(
                "Scanner returned success without a valid terminal marker: %s",
                output_dir,
            )
            return "failed"
        return "ok" if saved_quality.get("headline_eligible") else "incomplete"
    if saved_quality.get("terminal_commit_valid"):
        return (
            "ok"
            if saved_quality.get("headline_eligible")
            else "incomplete"
        )
    if (
        saved_quality.get("run_provenance_source") == "failure"
        and saved_quality.get("run_status") == "failed"
    ):
        return "failed"
    if (
        pre_run_signature != post_run_signature
        and str(saved_quality.get("coverage_status", "")) in {"partial", "empty"}
    ):
        return "incomplete"
    return "failed"


_DEFAULT_CREATE_LLM_CLIENT = create_llm_client
_DEFAULT_RUN_TARGET_SCAN = _run_target_scan


def _build_timed_out_scan_task_result(
    *,
    started_at: datetime,
    batch_args: argparse.Namespace,
    cve_id: str,
    target: SimilarProfileCandidate,
    timeout_seconds: int,
    status: str = "incomplete",
    termination: str = "timeout",
    failure_reason: Optional[str] = None,
) -> Dict[str, object]:
    """返回 timeout 结果；未提交运行只能写入 failure sidecar。"""
    finished_at = datetime.now()
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=target.profile_ref.repo_name,
        target_commit=target.profile_ref.commit_hash,
        output_base=str(getattr(batch_args, "scan_output_dir", str(_path_config["results_base_path"] / "scan-results-batch"))),
    )
    saved_quality = _load_saved_scan_quality(
        output_dir,
    )
    resolved_failure_reason = failure_reason or f"target scan timed out after {timeout_seconds}s"
    recovered_coverage = (
        {
            "coverage_status": saved_quality.get("coverage_status"),
            "critical_scope_present": saved_quality.get("critical_scope_present"),
            "critical_complete": saved_quality.get("critical_complete"),
            "critical_scope_total_files": saved_quality.get("critical_scope_total_files"),
            "critical_scope_completed_files": saved_quality.get("critical_scope_completed_files"),
            "full_universe_required": saved_quality.get("full_universe_required"),
            "full_universe_complete": saved_quality.get("full_universe_complete"),
            "full_universe_total_files": saved_quality.get("full_universe_total_files"),
            "full_universe_completed_files": saved_quality.get("full_universe_completed_files"),
            "scan_progress": saved_quality.get("scan_progress"),
        }
        if saved_quality.get("coverage_status") != "unknown"
        else None
    )
    existing_provenance = saved_quality.get("run_provenance")
    if (
        isinstance(existing_provenance, dict)
        and saved_quality.get("run_provenance_source") in {"running", "failure"}
    ):
        run_provenance = dict(existing_provenance)
        execution = dict(run_provenance.get("execution", {}))
        execution.update(
            {
                "finished_at": finished_at.isoformat(),
                "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
                "termination": termination,
                "status": "failed",
                "partial": recovered_coverage is not None,
                "failure_reason": resolved_failure_reason,
            }
        )
        run_provenance["execution"] = execution
    else:
        run_provenance = {
            "schema_version": agent_scanner.RUN_PROVENANCE_SCHEMA_VERSION,
            "kind": "scanner_run",
            "config_hashes": agent_scanner._failure_scanner_config_hashes(),
            "repo": {
                "name": target.profile_ref.repo_name,
                "requested_commit": target.profile_ref.commit_hash,
                "actual_commit": None,
            },
            "llm": {
                "provider": getattr(batch_args, "llm_provider", None),
                "model": getattr(batch_args, "llm_name", None),
                "reasoning_effort": None,
                "enable_thinking": None,
                "service_tier": None,
            },
            "execution": {
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
                "iterations_requested": getattr(batch_args, "max_iterations_cap", None),
                "iterations_completed": None,
                "iteration_durations_seconds": None,
                "termination": termination,
                "status": "failed",
                "partial": recovered_coverage is not None,
                "failure_reason": resolved_failure_reason,
            },
            "coverage": None,
            "usage": None,
            "usage_unavailable_reason": "scan process ended before final usage could be collected",
            "evaluation_mode": bool(getattr(batch_args, "evaluation_mode", False)),
            "ablations": agent_scanner.ablation_config_from_args(batch_args),
            "ablation_scope": {
                "memory": (
                    "shared public memory, persisted semantic resume guidance, and explicit "
                    "memory-derived scanned/findings/progress prompt state disabled; ordinary "
                    "within-run conversation remains; host cursor, page completion, first-"
                    "presentation, reached-work, and finding-dedup control-plane ledgers retained"
                ),
                "verifier": (
                    "scanner claim contract and same-type gate only; "
                    "external exploitability verification controlled separately"
                ),
            },
            "selection_similarity": getattr(
                batch_args, "selection_similarity_provenance", None
            ),
            "module_similarity": None,
        }
    run_provenance.setdefault(
        "config_hashes",
        agent_scanner._failure_scanner_config_hashes(),
    )
    run_provenance.setdefault("run_id", uuid.uuid4().hex)
    if recovered_coverage is not None:
        run_provenance["coverage"] = recovered_coverage
    agent_scanner._write_run_failure(  # pylint: disable=protected-access
        output_dir,
        run_provenance,
    )
    return {
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
        "coverage_status": saved_quality.get("coverage_status", "unknown"),
        "critical_scope_present": saved_quality.get("critical_scope_present"),
        "critical_complete": saved_quality.get("critical_complete"),
        "critical_scope_total_files": saved_quality.get("critical_scope_total_files"),
        "critical_scope_completed_files": saved_quality.get("critical_scope_completed_files"),
        "full_universe_required": saved_quality.get("full_universe_required"),
        "full_universe_complete": saved_quality.get("full_universe_complete"),
        "full_universe_total_files": saved_quality.get("full_universe_total_files"),
        "full_universe_completed_files": saved_quality.get("full_universe_completed_files"),
        "scan_progress": saved_quality.get("scan_progress"),
        "failure_reason": resolved_failure_reason,
        "termination": termination,
        "run_provenance": run_provenance,
        "scan_output_commit_sha256": None,
        "headline_eligible": False,
    }


def _run_target_scan_task_inner(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    target: SimilarProfileCandidate,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
) -> Dict[str, object]:
    """Run one target scan with isolated task-local LLM state.

    Args:
        batch_args: Parsed batch CLI arguments.
        cve_id: Vulnerability identifier.
        vulnerability_profile: Loaded vulnerability profile object.
        target: Selected target candidate.

    Returns:
        Scan execution metadata including status and timing fields.
    """
    started_at = datetime.now()
    status: Literal["ok", "skipped", "incomplete", "failed"] = "failed"
    failure_reason: Optional[str] = None
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=target.profile_ref.repo_name,
        target_commit=target.profile_ref.commit_hash,
        output_base=str(getattr(batch_args, "scan_output_dir", str(_path_config["results_base_path"] / "scan-results-batch"))),
    )
    try:
        run_target_scan = _run_target_scan
        try:
            from cli import batch_scanner as batch_scanner_module
        except ImportError:  # pragma: no cover - direct script execution fallback
            batch_scanner_module = None
        if run_target_scan is not _DEFAULT_RUN_TARGET_SCAN:
            pass
        elif batch_scanner_module is not None:
            candidate_run_target_scan = getattr(
                batch_scanner_module,
                "_run_target_scan",
                _DEFAULT_RUN_TARGET_SCAN,
            )
            if candidate_run_target_scan is not _DEFAULT_RUN_TARGET_SCAN:
                run_target_scan = candidate_run_target_scan
        llm_client = (
            create_llm_client(LLMConfig(provider=batch_args.llm_provider, model=batch_args.llm_name))
            if run_target_scan is _DEFAULT_RUN_TARGET_SCAN or create_llm_client is not _DEFAULT_CREATE_LLM_CLIENT
            else None
        )
        scan_kwargs = {
            "batch_args": batch_args,
            "cve_id": cve_id,
            "vulnerability_profile": vulnerability_profile,
            "llm_client": llm_client,
            "target": target,
        }
        if unprioritized_file_schedule is not None:
            scan_kwargs["unprioritized_file_schedule"] = unprioritized_file_schedule
        terminal_binding: Dict[str, str] = {}
        scan_kwargs["terminal_binding_out"] = terminal_binding
        status = run_target_scan(**scan_kwargs)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "Target scan task failed before completion for %s@%s: %s",
            target.profile_ref.repo_name,
            target.profile_ref.commit_hash[:12],
            exc,
        )
        status = "failed"
        failure_reason = str(exc)

    finished_at = datetime.now()
    saved_quality = _load_saved_scan_quality(
        output_dir,
        expected_commit_sha256=(
            terminal_binding.get("scan_output_commit_sha256")
            if "terminal_binding" in locals()
            else None
        ),
        expected_reference_id=cve_id,
        expected_repo_name=target.profile_ref.repo_name,
        expected_commit=target.profile_ref.commit_hash,
    )
    skip_any_result = (
        status == "skipped"
        and bool(getattr(batch_args, "skip_any_existing_scan_result", False))
    )
    if status in {"ok", "skipped"} and not skip_any_result and not (
        saved_quality.get("terminal_commit_valid")
        and saved_quality.get("headline_eligible")
    ):
        status = "failed"
        failure_reason = (
            failure_reason
            or "scanner success lacks a complete externally bound terminal commit"
        )
    if skip_any_result:
        saved_quality = dict(saved_quality)
        saved_quality["coverage_status"] = "unknown"
        saved_quality["scan_output_commit_sha256"] = None
        saved_quality["headline_eligible"] = False
    return {
        "status": status,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
        "coverage_status": saved_quality.get("coverage_status", "unknown"),
        "critical_scope_present": saved_quality.get("critical_scope_present"),
        "critical_complete": saved_quality.get("critical_complete"),
        "critical_scope_total_files": saved_quality.get("critical_scope_total_files"),
        "critical_scope_completed_files": saved_quality.get("critical_scope_completed_files"),
        "full_universe_required": saved_quality.get("full_universe_required"),
        "full_universe_complete": saved_quality.get("full_universe_complete"),
        "full_universe_total_files": saved_quality.get("full_universe_total_files"),
        "full_universe_completed_files": saved_quality.get("full_universe_completed_files"),
        "scan_progress": saved_quality.get("scan_progress"),
        "failure_reason": failure_reason or saved_quality.get("run_failure_reason"),
        "termination": saved_quality.get("termination"),
        "run_provenance": saved_quality.get("run_provenance"),
        "usage": saved_quality.get("usage"),
        "scan_output_commit_sha256": saved_quality.get(
            "scan_output_commit_sha256"
        ),
        "headline_eligible": saved_quality.get("headline_eligible", False),
    }


def _target_scan_process_entry(result_queue, kwargs: Dict[str, Any]) -> None:
    """Run one target scan in a child process so it can be killed on timeout."""
    try:
        os.setsid()
    except OSError:
        pass
    try:
        result_queue.put({"ok": True, "result": _run_target_scan_task_inner(**kwargs)})
    except BaseException as exc:  # pylint: disable=broad-except
        result_queue.put(
            {
                "ok": False,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
        )


def _terminate_process_tree(process: multiprocessing.Process) -> None:
    """Terminate one scan child process group with a kill fallback."""
    if process.pid is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        if process.is_alive():
            process.terminate()
    except OSError:
        process.terminate()
    process.join(timeout=10)
    if process.is_alive():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            if process.is_alive():
                process.kill()
        except OSError:
            process.kill()
        process.join(timeout=5)


def _run_target_scan_task(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    target: SimilarProfileCandidate,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
) -> Dict[str, object]:
    """Run one target scan with an optional process-level timeout."""
    timeout_seconds = int(getattr(batch_args, "target_scan_timeout", 0) or 0)
    if timeout_seconds <= 0:
        inner_kwargs = {
            "batch_args": batch_args,
            "cve_id": cve_id,
            "vulnerability_profile": vulnerability_profile,
            "target": target,
        }
        if unprioritized_file_schedule is not None:
            inner_kwargs["unprioritized_file_schedule"] = unprioritized_file_schedule
        return _run_target_scan_task_inner(
            **inner_kwargs,
        )

    started_at = datetime.now()
    result_queue = multiprocessing.Queue(maxsize=1)
    inner_kwargs = {
        "batch_args": batch_args,
        "cve_id": cve_id,
        "vulnerability_profile": vulnerability_profile,
        "target": target,
    }
    if unprioritized_file_schedule is not None:
        inner_kwargs["unprioritized_file_schedule"] = unprioritized_file_schedule
    process = multiprocessing.Process(
        target=_target_scan_process_entry,
        kwargs={
            "result_queue": result_queue,
            "kwargs": inner_kwargs,
        },
    )
    process.start()
    try:
        deadline = time.monotonic() + timeout_seconds
        payload = None
        while payload is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                payload = result_queue.get(timeout=min(0.1, remaining))
            except queue.Empty:
                if not process.is_alive():
                    process.join(timeout=0)
                    break

        if payload is None and process.is_alive():
            logger.error(
                "Target scan timed out after %ss: %s@%s",
                timeout_seconds,
                target.profile_ref.repo_name,
                target.profile_ref.commit_hash[:12],
            )
            _terminate_process_tree(process)
            return _build_timed_out_scan_task_result(
                started_at=started_at,
                batch_args=batch_args,
                cve_id=cve_id,
                target=target,
                timeout_seconds=timeout_seconds,
            )

        if payload is None:
            if process.exitcode == 0:
                error_message = "target scan child exited without returning a result"
            else:
                error_message = f"target scan child exited with code {process.exitcode}"
            logger.error(
                "%s: %s@%s",
                error_message,
                target.profile_ref.repo_name,
                target.profile_ref.commit_hash[:12],
            )
            return _build_timed_out_scan_task_result(
                started_at=started_at,
                batch_args=batch_args,
                cve_id=cve_id,
                target=target,
                timeout_seconds=timeout_seconds,
                status="failed",
                termination="child_process_failure",
                failure_reason=error_message,
            )

        # Drain the multiprocessing pipe before joining. Joining first can
        # deadlock a successful child while its Queue feeder flushes a large
        # provenance payload.
        process.join(timeout=1.0)
        if process.is_alive():
            _terminate_process_tree(process)
            error_message = "target scan child returned a result but did not exit"
            return _build_timed_out_scan_task_result(
                started_at=started_at,
                batch_args=batch_args,
                cve_id=cve_id,
                target=target,
                timeout_seconds=timeout_seconds,
                status="failed",
                termination="child_process_failure",
                failure_reason=error_message,
            )

        if payload.get("ok"):
            return payload["result"]

        logger.error(
            "Target scan child failed for %s@%s: %s: %s",
            target.profile_ref.repo_name,
            target.profile_ref.commit_hash[:12],
            payload.get("error_type", "Error"),
            payload.get("error_message", ""),
        )
        return _build_timed_out_scan_task_result(
            started_at=started_at,
            batch_args=batch_args,
            cve_id=cve_id,
            target=target,
            timeout_seconds=timeout_seconds,
            status="failed",
            termination="child_process_failure",
            failure_reason=payload.get("error_message", "target scan child failed"),
        )
    finally:
        result_queue.close()
        result_queue.join_thread()


def _run_selected_target_scans(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    similar_targets: Sequence[SimilarProfileCandidate],
) -> List[Dict[str, object]]:
    """Execute selected target scans while preserving selection order.

    Args:
        batch_args: Parsed batch CLI arguments.
        cve_id: Vulnerability identifier.
        vulnerability_profile: Loaded vulnerability profile object.
        similar_targets: Selected targets in final ranking order.

    Returns:
        Ordered scan result records ready for batch summary output.
    """
    if not similar_targets:
        return []

    deduplicated_targets: List[SimilarProfileCandidate] = []
    seen_target_ids = set()
    for candidate in similar_targets:
        target_id = (
            f"{cve_id}:{candidate.profile_ref.repo_name}:{candidate.profile_ref.commit_hash}"
        )
        if target_id in seen_target_ids:
            continue
        seen_target_ids.add(target_id)
        deduplicated_targets.append(candidate)

    ordered_results: List[Optional[Dict[str, object]]] = [None] * len(deduplicated_targets)

    def _build_record(index: int, task_result: Dict[str, object]) -> Dict[str, object]:
        candidate = deduplicated_targets[index]
        return {
            "repo_name": candidate.profile_ref.repo_name,
            "commit_hash": candidate.profile_ref.commit_hash,
            "overall_similarity": candidate.metrics.overall_sim if candidate.metrics is not None else None,
            "similarity_computed": candidate.metrics is not None,
            "status": task_result["status"],
            "coverage_status": task_result.get("coverage_status", "unknown"),
            "critical_scope_present": task_result.get("critical_scope_present"),
            "critical_complete": task_result.get("critical_complete"),
            "critical_scope_total_files": task_result.get("critical_scope_total_files"),
            "critical_scope_completed_files": task_result.get("critical_scope_completed_files"),
            "full_universe_required": task_result.get("full_universe_required"),
            "full_universe_complete": task_result.get("full_universe_complete"),
            "full_universe_total_files": task_result.get("full_universe_total_files"),
            "full_universe_completed_files": task_result.get("full_universe_completed_files"),
            "scan_progress": task_result.get("scan_progress"),
            "failure_reason": task_result.get("failure_reason"),
            "termination": task_result.get("termination"),
            "usage": task_result.get("usage"),
            "run_provenance": task_result.get("run_provenance"),
            "started_at": task_result["started_at"],
            "finished_at": task_result["finished_at"],
            "duration_seconds": task_result["duration_seconds"],
        }

    worker_count = max(1, int(getattr(batch_args, "jobs", 1)))

    def _run_and_build_record(
        index: int,
        candidate: SimilarProfileCandidate,
    ) -> Dict[str, object]:
        try:
            task_result = _run_target_scan_task(
                batch_args=batch_args,
                cve_id=cve_id,
                vulnerability_profile=vulnerability_profile,
                target=candidate,
            )
        except Exception as exc:  # pylint: disable=broad-except
            finished_at = datetime.now()
            logger.exception(
                "Target scan task raised unexpectedly: %s@%s",
                candidate.profile_ref.repo_name,
                candidate.profile_ref.commit_hash[:12],
            )
            task_result = {
                "status": "failed",
                "coverage_status": "unknown",
                "failure_reason": (
                    "target scan task raised unexpectedly: "
                    f"{type(exc).__name__}: {exc}"
                ),
                "termination": "worker_exception",
                "started_at": finished_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration_seconds": 0.0,
            }
        return _build_record(index, task_result)

    if worker_count == 1 or len(deduplicated_targets) == 1:
        for index, candidate in enumerate(deduplicated_targets):
            ordered_results[index] = _run_and_build_record(index, candidate)
        return [result for result in ordered_results if result is not None]

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_index = {
            executor.submit(
                _run_and_build_record,
                index,
                candidate,
            ): index
            for index, candidate in enumerate(deduplicated_targets)
        }
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            ordered_results[index] = future.result()

    return [result for result in ordered_results if result is not None]


def _load_scan_memory_quality(output_dir: Path) -> Optional[Dict[str, Any]]:
    """最终 findings 缺失时从私有扫描 ledger 恢复覆盖率。"""
    memory_path = output_dir / "scan_memory.json"
    if not memory_path.is_file():
        return None
    try:
        payload = json.loads(memory_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to load scan memory coverage from %s: %s", memory_path, exc)
        return None
    if not isinstance(payload, dict):
        return None
    file_status = payload.get("file_status", {})
    module_priorities = payload.get("module_priorities", {})
    file_to_module = payload.get("file_to_module", {})
    findings = payload.get("findings", [])
    scan_signature = payload.get("scan_signature", {})
    if not isinstance(file_status, dict):
        return None
    if not isinstance(module_priorities, dict):
        module_priorities = {}
    if not isinstance(file_to_module, dict):
        file_to_module = {}
    if not isinstance(scan_signature, dict):
        return None
    scan_config = scan_signature.get("scan_config", {})
    if not isinstance(scan_config, dict):
        return None
    raw_full_universe_required = scan_config.get(
        "require_full_universe_completion",
        False,
    )
    if not isinstance(raw_full_universe_required, bool):
        return None
    full_universe_required = raw_full_universe_required
    max_priority = 1 if payload.get("critical_stop_max_priority") == 1 else 2
    completed = sum(1 for status in file_status.values() if status == "completed")
    pending = sum(1 for status in file_status.values() if status == "pending")
    priority_stats = {1: {"total": 0, "completed": 0}, 2: {"total": 0, "completed": 0}}
    critical_total = 0
    critical_completed = 0
    for file_path, status in file_status.items():
        module_name = file_to_module.get(file_path, "")
        try:
            priority = int(module_priorities.get(module_name, 3))
        except (TypeError, ValueError):
            priority = 3
        if priority in priority_stats:
            priority_stats[priority]["total"] += 1
            if status == "completed":
                priority_stats[priority]["completed"] += 1
        if priority <= max_priority:
            critical_total += 1
            if status != "pending":
                critical_completed += 1
    critical_complete = (
        critical_total > 0 and critical_completed == critical_total
    )
    full_universe_complete = bool(file_status) and completed == len(file_status)
    finding_count = len(findings) if isinstance(findings, list) else 0
    if critical_total <= 0:
        coverage_status = (
            "partial" if completed > 0 or finding_count > 0 else "empty"
        )
    elif full_universe_required:
        coverage_status = "complete" if full_universe_complete else "partial"
    elif critical_complete:
        coverage_status = "complete"
    elif completed > 0 or finding_count > 0:
        coverage_status = "partial"
    else:
        coverage_status = "empty"
    return {
        "coverage_status": coverage_status,
        "critical_scope_present": critical_total > 0,
        "critical_complete": critical_complete,
        "critical_scope_total_files": critical_total,
        "critical_scope_completed_files": critical_completed,
        "full_universe_required": full_universe_required,
        "full_universe_complete": full_universe_complete,
        "full_universe_total_files": len(file_status),
        "full_universe_completed_files": completed,
        "scan_progress": {
            "total_files": len(file_status),
            "completed": completed,
            "pending": pending,
            "findings": finding_count,
            "priority_1": priority_stats[1],
            "priority_2": priority_stats[2],
        },
    }


def _load_saved_scan_quality(
    output_dir: Path,
    *,
    expected_commit_sha256: Optional[str] = None,
    expected_reference_id: Optional[str] = None,
    expected_repo_name: Optional[str] = None,
    expected_commit: Optional[str] = None,
    allow_unanchored_terminal: bool = False,
) -> Dict[str, Any]:
    """读取扫描状态；只有通过 marker 校验的终态才可用于跳过。"""
    payload: Dict[str, Any] = {}
    run_provenance: Optional[Dict[str, Any]] = None
    provenance_source: Optional[str] = None
    commit_sha256: Optional[str] = None
    commit_error: Optional[str] = None
    terminal_commit_valid = False
    headline_eligible = False

    try:
        marker_present = (
            output_dir / SCAN_OUTPUT_COMMIT_FILENAME
        ).lstat().st_size >= 0
    except FileNotFoundError:
        marker_present = False

    if expected_commit_sha256 is not None:
        try:
            commit_sha256 = expected_commit_sha256
            validated = validate_committed_scan_outputs(
                output_dir,
                expected_commit_sha256=commit_sha256,
                require_complete=False,
            )
        except ScanOutputCommitError as exc:
            commit_error = str(exc)
        else:
            try:
                reference_id = canonical_scan_reference_id(
                    expected_reference_id
                )
                repo_name = canonical_scan_repo_name(
                    expected_repo_name
                )
                commit = canonical_scan_commit(expected_commit)
            except ScanOutputCommitError:
                commit_error = (
                    "external scanner output identity binding is required"
                )
            else:
                provenance = validated["run_provenance"]
                repo = (
                    provenance.get("repo")
                    if isinstance(provenance, dict)
                    else None
                )
                if (
                    validated.get("reference_id") != reference_id
                    or not isinstance(repo, dict)
                    or repo.get("name") != repo_name
                    or repo.get("requested_commit") != commit
                    or repo.get("actual_commit") != commit
                ):
                    commit_error = (
                        "scanner output identity disagrees with external binding"
                    )
                else:
                    payload = validated["findings"]
                    run_provenance = provenance
                    provenance_source = "committed"
                    terminal_commit_valid = True
                    headline_eligible = bool(
                        validated["headline_eligible"]
                    )
    elif allow_unanchored_terminal and marker_present:
        commit_error = "external scanner output commit binding is required"

    def load_record(filename: str) -> Optional[Dict[str, Any]]:
        path = output_dir / filename
        if not path.is_file() or path.is_symlink():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load scanner record from %s: %s", path, exc)
            return None
        return loaded if isinstance(loaded, dict) else None

    if not terminal_commit_valid:
        failure_record = load_record(SCAN_RUN_FAILURE_FILENAME)
        state_record = load_record(SCAN_RUN_STATE_FILENAME)
        if failure_record is not None:
            run_provenance = failure_record
            provenance_source = "failure"
        elif state_record is not None:
            run_provenance = state_record
            provenance_source = "running"
        else:
            payload = load_record(SCAN_FINDINGS_FILENAME) or {}
            run_provenance = load_record(SCAN_PROVENANCE_FILENAME)
            if run_provenance is not None:
                provenance_source = "legacy_uncommitted"
            else:
                embedded = payload.get("run_provenance")
                if isinstance(embedded, dict):
                    run_provenance = embedded
                    provenance_source = "legacy_embedded"

    scan_memory_quality = _load_scan_memory_quality(output_dir)
    if not payload and run_provenance is None and not scan_memory_quality:
        if marker_present:
            return {
                "terminal_commit_valid": False,
                "scan_output_commit_sha256": commit_sha256,
                "scan_output_commit_error": commit_error or "missing external marker binding",
                "headline_eligible": False,
            }
        return {}

    execution = run_provenance.get("execution", {}) if run_provenance else {}
    provenance_coverage = run_provenance.get("coverage") if run_provenance else None
    if isinstance(provenance_coverage, dict):
        coverage = provenance_coverage
        coverage_source = "run_provenance"
    elif provenance_source in {"failure", "running", "legacy_uncommitted"}:
        coverage = scan_memory_quality or {}
        coverage_source = "scan_memory" if coverage else "unknown"
    elif not payload and scan_memory_quality:
        coverage = scan_memory_quality
        coverage_source = "scan_memory"
    else:
        coverage = payload
        coverage_source = "findings"

    scan_fingerprint = (
        run_provenance.get("scan_fingerprint")
        if isinstance(run_provenance, dict)
        else None
    )
    if not isinstance(scan_fingerprint, dict) and terminal_commit_valid:
        scan_fingerprint = payload.get("scan_fingerprint")
    return {
        "coverage_status": coverage.get("coverage_status", "unknown"),
        "critical_scope_present": coverage.get("critical_scope_present"),
        "critical_complete": coverage.get("critical_complete"),
        "critical_scope_total_files": coverage.get("critical_scope_total_files"),
        "critical_scope_completed_files": coverage.get("critical_scope_completed_files"),
        "full_universe_required": coverage.get("full_universe_required"),
        "full_universe_complete": coverage.get("full_universe_complete"),
        "full_universe_total_files": coverage.get("full_universe_total_files"),
        "full_universe_completed_files": coverage.get("full_universe_completed_files"),
        "scan_progress": coverage.get("scan_progress"),
        "coverage_source": coverage_source,
        "scan_fingerprint": scan_fingerprint,
        "scan_fingerprint_hash": (
            scan_fingerprint.get("hash") if isinstance(scan_fingerprint, dict) else ""
        ),
        "run_provenance": run_provenance,
        "run_provenance_source": provenance_source,
        "termination": execution.get("termination"),
        "run_status": execution.get("status"),
        "run_failure_reason": execution.get("failure_reason"),
        "usage": run_provenance.get("usage") if isinstance(run_provenance, dict) else None,
        "terminal_commit_valid": terminal_commit_valid,
        "scan_output_commit_sha256": commit_sha256,
        "scan_output_commit_error": commit_error,
        "headline_eligible": headline_eligible,
    }
