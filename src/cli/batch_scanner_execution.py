#!/usr/bin/env python3
"""Scan execution helpers for the batch scanning pipeline."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple

from config import _path_config
from llm import LLMConfig, create_llm_client
from profiler.fingerprint import stable_data_hash
from scanner.agent.shared_memory import SharedPublicMemoryManager
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


def _scan_output_signature(output_dir: Path) -> Tuple[Tuple[str, int, int], ...]:
    """Capture a lightweight signature for persisted scan outputs."""
    signatures: List[Tuple[str, int, int]] = []
    for filename in ("agentic_vuln_findings.json", "scan_memory.json"):
        path = output_dir / filename
        if not path.exists():
            continue
        try:
            stat_result = path.stat()
        except OSError:
            continue
        signatures.append((filename, int(stat_result.st_size), int(stat_result.st_mtime_ns)))
    return tuple(signatures)


def _build_expected_scan_fingerprint_for_skip(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    llm_client: Any,
    target: SimilarProfileCandidate,
    scan_target: Any,
    target_repo_path: Path,
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

            scan_languages = agent_scanner._resolve_scan_languages(  # pylint: disable=protected-access
                target_repo_path,
                target.profile_ref.profile,
            )
            codeql_database_names = agent_scanner._resolve_codeql_database_names(  # pylint: disable=protected-access
                scan_target,
                scan_languages,
                target.profile_ref.profile,
            )
            expected_scan_fingerprint = agent_scanner.build_scan_fingerprint(
                vulnerability_profile=vulnerability_profile,
                software_profile=target.profile_ref.profile,
                llm_client=llm_client,
                max_iterations=batch_args.max_iterations_cap,
                stop_when_critical_complete=not batch_args.disable_critical_stop,
                critical_stop_mode=batch_args.critical_stop_mode,
                critical_stop_max_priority=getattr(batch_args, "critical_stop_max_priority", 2),
                scan_languages=scan_languages,
                codeql_database_names=codeql_database_names,
                shared_public_memory_scope=_build_shared_public_memory_scope(
                    batch_args=batch_args,
                    cve_id=cve_id,
                    repo_path=target_repo_path,
                    repo_name=scan_target.repo_name,
                    repo_commit=scan_target.commit_hash,
                ),
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
) -> Optional[Dict[str, Any]]:
    """Build one skip-existing fingerprint using only persisted profile metadata."""
    repo_analysis = agent_scanner._extract_repo_analysis(  # pylint: disable=protected-access
        target.profile_ref.profile
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
        target.profile_ref.profile,
    )
    target_repos_root = Path(
        str(getattr(batch_args, "target_repos_root", _path_config["repo_base_path"]))
    ).expanduser()
    if not target_repos_root.is_absolute():
        target_repos_root = _path_config["repo_root"] / target_repos_root
    target_repo_path = target_repos_root / scan_target.repo_name
    return agent_scanner.build_scan_fingerprint(
        vulnerability_profile=vulnerability_profile,
        software_profile=target.profile_ref.profile,
        llm_client=llm_client,
        max_iterations=batch_args.max_iterations_cap,
        stop_when_critical_complete=not batch_args.disable_critical_stop,
        critical_stop_mode=batch_args.critical_stop_mode,
        critical_stop_max_priority=getattr(batch_args, "critical_stop_max_priority", 2),
        scan_languages=profile_languages,
        codeql_database_names=codeql_database_names,
        shared_public_memory_scope=_build_shared_public_memory_scope(
            batch_args=batch_args,
            cve_id=cve_id,
            repo_path=target_repo_path,
            repo_name=scan_target.repo_name,
            repo_commit=scan_target.commit_hash,
        ),
    )


def _run_target_scan(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    llm_client: Any,
    target: SimilarProfileCandidate,
) -> Literal["ok", "skipped", "incomplete", "failed"]:
    """Run one target repository scan with skip-existing validation."""
    profile_base_path, software_profile_dirname = _resolve_software_profile_locator(batch_args)
    scan_target = agent_scanner.ScanTarget(
        repo_name=target.profile_ref.repo_name,
        commit_hash=target.profile_ref.commit_hash,
        similarity=target,
    )
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=scan_target.repo_name,
        target_commit=scan_target.commit_hash,
        output_base=str(batch_args.scan_output_dir),
    )
    findings_path = output_dir / "agentic_vuln_findings.json"
    resolved_target_repos_root = Path(batch_args.target_repos_root).expanduser()
    if not resolved_target_repos_root.is_absolute():
        resolved_target_repos_root = _path_config["repo_root"] / resolved_target_repos_root
    target_repo_path = resolved_target_repos_root / scan_target.repo_name
    if (
        batch_args.skip_existing_scans
        and not getattr(batch_args, "force_regenerate_profiles", False)
        and findings_path.exists()
    ):
        saved_quality = _load_saved_scan_quality(output_dir)
        coverage_status = str(saved_quality.get("coverage_status", "unknown"))
        saved_fingerprint_hash = str(saved_quality.get("scan_fingerprint_hash", "")).strip()
        expected_scan_fingerprint = _build_expected_scan_fingerprint_for_skip(
            batch_args=batch_args,
            cve_id=cve_id,
            vulnerability_profile=vulnerability_profile,
            llm_client=llm_client,
            target=target,
            scan_target=scan_target,
            target_repo_path=target_repo_path,
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
        if coverage_status != "complete":
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

    pre_run_signature = _scan_output_signature(output_dir)
    scan_succeeded = agent_scanner.run_single_target_scan(
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
        profile_base_path=profile_base_path,
        software_profile_dirname=software_profile_dirname,
        shared_public_memory_dir=_resolve_shared_public_memory_dir_from_args(batch_args),
    )
    if scan_succeeded:
        return "ok"

    post_run_signature = _scan_output_signature(output_dir)
    saved_quality = _load_saved_scan_quality(output_dir)
    if (
        pre_run_signature != post_run_signature
        and str(saved_quality.get("coverage_status", "")) in {"partial", "empty"}
    ):
        return "incomplete"
    return "failed"


_DEFAULT_RUN_TARGET_SCAN = _run_target_scan


def _run_target_scan_task(
    *,
    batch_args: argparse.Namespace,
    cve_id: str,
    vulnerability_profile: Any,
    target: SimilarProfileCandidate,
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
    output_dir = agent_scanner.resolve_output_dir(
        cve_id=cve_id,
        target_repo=target.profile_ref.repo_name,
        target_commit=target.profile_ref.commit_hash,
        output_base=str(batch_args.scan_output_dir),
    )
    try:
        llm_client = create_llm_client(LLMConfig(provider=batch_args.llm_provider, model=batch_args.llm_name))
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
        status = run_target_scan(
            batch_args=batch_args,
            cve_id=cve_id,
            vulnerability_profile=vulnerability_profile,
            llm_client=llm_client,
            target=target,
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(
            "Target scan task failed before completion for %s@%s: %s",
            target.profile_ref.repo_name,
            target.profile_ref.commit_hash[:12],
            exc,
        )
        status = "failed"

    finished_at = datetime.now()
    saved_quality = (
        _load_saved_scan_quality(output_dir)
        if status in {"ok", "skipped", "incomplete"}
        else {}
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
        "scan_progress": saved_quality.get("scan_progress"),
    }


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
            "overall_similarity": candidate.metrics.overall_sim,
            "status": task_result["status"],
            "coverage_status": task_result.get("coverage_status", "unknown"),
            "critical_scope_present": task_result.get("critical_scope_present"),
            "critical_complete": task_result.get("critical_complete"),
            "critical_scope_total_files": task_result.get("critical_scope_total_files"),
            "critical_scope_completed_files": task_result.get("critical_scope_completed_files"),
            "scan_progress": task_result.get("scan_progress"),
            "started_at": task_result["started_at"],
            "finished_at": task_result["finished_at"],
            "duration_seconds": task_result["duration_seconds"],
        }

    worker_count = max(1, int(getattr(batch_args, "jobs", 1)))

    if worker_count == 1 or len(deduplicated_targets) == 1:
        for index, candidate in enumerate(deduplicated_targets):
            ordered_results[index] = _build_record(
                index,
                _run_target_scan_task(
                    batch_args=batch_args,
                    cve_id=cve_id,
                    vulnerability_profile=vulnerability_profile,
                    target=candidate,
                ),
            )
        return [result for result in ordered_results if result is not None]

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_index = {
            executor.submit(
                _run_target_scan_task,
                batch_args=batch_args,
                cve_id=cve_id,
                vulnerability_profile=vulnerability_profile,
                target=candidate,
            ): index
            for index, candidate in enumerate(deduplicated_targets)
        }
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            ordered_results[index] = _build_record(index, future.result())

    return [result for result in ordered_results if result is not None]


def _load_saved_scan_quality(output_dir: Path) -> Dict[str, Any]:
    """Load persisted coverage metadata from agentic_vuln_findings.json."""
    findings_path = output_dir / "agentic_vuln_findings.json"
    if not findings_path.is_file():
        return {}
    try:
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to load saved scan quality from %s: %s", findings_path, exc)
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        "coverage_status": payload.get("coverage_status", "unknown"),
        "critical_scope_present": payload.get("critical_scope_present"),
        "critical_complete": payload.get("critical_complete"),
        "critical_scope_total_files": payload.get("critical_scope_total_files"),
        "critical_scope_completed_files": payload.get("critical_scope_completed_files"),
        "scan_progress": payload.get("scan_progress"),
        "scan_fingerprint": payload.get("scan_fingerprint"),
        "scan_fingerprint_hash": (
            payload.get("scan_fingerprint", {}).get("hash")
            if isinstance(payload.get("scan_fingerprint"), dict)
            else ""
        ),
    }
