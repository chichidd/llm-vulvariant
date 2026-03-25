#!/usr/bin/env python3
"""Batch vulnerability scanning pipeline for all entries in vuln.json."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from config import DEFAULT_SOFTWARE_PROFILE_DIRNAME, DEFAULT_VULN_PROFILE_DIRNAME, _path_config
from llm import LLMConfig, create_llm_client
from scanner.agent import load_software_profile, load_vulnerability_profile
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME
from scanner.similarity import (
    ProfileRef,
    SimilarProfileCandidate,
    build_text_retriever,
    compute_profile_similarity,
)
from utils.concurrency import RepoPathLockManager, run_thread_pool_tasks
from utils.git_utils import (
    get_git_commit,
    has_uncommitted_changes,
)
from utils.io_utils import write_atomic_text
from utils.logger import get_logger
from utils.number_utils import to_int
from utils.repo_lock import hold_repo_lock
from utils.vuln_utils import normalize_cve_id, read_vuln_data

try:
    from cli import agent_scanner
    from cli.common import resolve_cli_path, resolve_profile_dirs, setup_logging
    from cli.profile_generation import (
        build_vulnerability_entry,
        create_profile_llm_client,
        run_software_profile_generation,
        run_vulnerability_profile_generation,
    )
except ImportError:  # pragma: no cover - direct script execution fallback
    import agent_scanner
    from common import resolve_cli_path, resolve_profile_dirs, setup_logging
    from profile_generation import (
        build_vulnerability_entry,
        create_profile_llm_client,
        run_software_profile_generation,
        run_vulnerability_profile_generation,
    )

try:
    from cli import batch_scanner_execution as batch_scanner_execution_module
    from cli.batch_scanner_cache import (
        _cached_vulnerability_profile_matches_current_inputs,
        _cached_vulnerability_profile_matches_missing_repo_inputs,
        _load_cached_software_profile_if_compatible,
        _load_vuln_entries,
    )
    from cli.batch_scanner_execution import (
        _build_expected_scan_fingerprint_for_skip,
        _build_profile_based_scan_fingerprint_for_skip,
        _load_saved_scan_quality,
        _run_selected_target_scans,
        _run_target_scan,
    )
except ImportError:  # pragma: no cover - direct script execution fallback
    import batch_scanner_execution as batch_scanner_execution_module
    from batch_scanner_cache import (
        _cached_vulnerability_profile_matches_current_inputs,
        _cached_vulnerability_profile_matches_missing_repo_inputs,
        _load_cached_software_profile_if_compatible,
        _load_vuln_entries,
    )
    from batch_scanner_execution import (
        _build_expected_scan_fingerprint_for_skip,
        _build_profile_based_scan_fingerprint_for_skip,
        _load_saved_scan_quality,
        _run_selected_target_scans,
        _run_target_scan,
    )

logger = get_logger(__name__)
_IMPORTED_RUN_TARGET_SCAN = _run_target_scan

__all__ = [
    "agent_scanner",
    "_build_expected_scan_fingerprint_for_skip",
    "_build_profile_based_scan_fingerprint_for_skip",
    "_cached_vulnerability_profile_matches_current_inputs",
    "_cached_vulnerability_profile_matches_missing_repo_inputs",
    "_load_cached_software_profile_if_compatible",
    "_load_saved_scan_quality",
    "_load_vuln_entries",
    "_run_selected_target_scans",
    "_run_target_scan",
]


@dataclass(frozen=True)
class BatchScanPaths:
    """Resolved filesystem inputs for one batch scan run."""

    vuln_json: Path
    source_repos_root: Path
    target_repos_root: Path
    source_repo_profiles_dir: Path
    target_repo_profiles_dir: Path
    vuln_profiles_dir: Path
    scan_output_dir: Path


@dataclass
class BatchScanCaches:
    """Cached profile state reused across vulnerability entries."""

    source_software_cache: Dict[Tuple[str, str], object]
    target_software_cache: Dict[Tuple[str, str], object]
    vulnerability_cache: Dict[Tuple[str, str], object]
    regenerated_source_software_keys: Set[Tuple[str, str]]
    regenerated_target_software_keys: Set[Tuple[str, str]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Batch pipeline: ensure profiles, select similar latest repos by similarity threshold, "
            "and scan all vuln entries from vuln.json."
        )
    )
    parser.add_argument(
        "--vuln-json",
        type=str,
        default=str(_path_config["vuln_data_path"]),
        help="Path to vuln.json (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--source-repos-root",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Root directory of source repositories referenced by vuln.json (default: data/repos)",
    )
    parser.add_argument(
        "--target-repos-root",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Root directory of target repositories to scan (default: data/repos)",
    )
    parser.add_argument(
        "--profile-base-path",
        type=str,
        default=str(_path_config["profile_base_path"]),
        help="Base directory containing profile folders (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--source-soft-profiles-dir",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help=(
            "Source software profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--target-soft-profiles-dir",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help=(
            "Target software profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--vuln-profiles-dir",
        type=str,
        default=DEFAULT_VULN_PROFILE_DIRNAME,
        help=(
            "Vulnerability profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--scan-output-dir",
        type=str,
        default="scan-results-batch",
        help="Base output directory for scan results",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.7,
        help="Minimum overall profile similarity to keep a target repo (default: 0.7)",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=None,
        help="Optional max number of targets to scan per vulnerability after threshold filtering",
    )
    parser.add_argument(
        "--fallback-top-n",
        type=int,
        default=3,
        help=(
            "If no repository meets similarity-threshold, scan top-N most similar repositories "
            "(default: 3)"
        ),
    )
    parser.add_argument(
        "--include-same-repo",
        action="store_true",
        help="Include same repository as source vulnerability during target selection",
    )
    parser.add_argument(
        "--similarity-model-name",
        type=str,
        default=DEFAULT_EMBEDDING_MODEL_NAME,
        help="Embedding model name for text similarity",
    )
    parser.add_argument(
        "--similarity-device",
        type=str,
        default="cpu",
        help="Device used by similarity embedding model",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider used for profile generation and scanning (deepseek, openai, lab)",
    )
    parser.add_argument(
        "--llm-name",
        type=str,
        default=None,
        help="Optional model name override",
    )
    parser.add_argument(
        "--max-iterations-cap",
        type=int,
        default=10,
        help="Iteration cap used with critical-stop mode (default: 10)",
    )
    parser.add_argument(
        "--disable-critical-stop",
        action="store_true",
        help=(
            "Disable priority-1 completion aware stopping behavior."
        ),
    )
    parser.add_argument(
        "--critical-stop-mode",
        type=str,
        choices=["min", "max"],
        default="max",
        help=(
            "When critical stop is enabled: "
            "min => stop at min(max-iterations-cap, X); "
            "max => stop at max(max-iterations-cap, X). Default: max"
        ),
    )
    parser.add_argument(
        "--critical-stop-max-priority",
        type=int,
        choices=[1, 2],
        default=2,
        help=(
            "Highest module priority included in critical-stop completion checks. "
            "1 => affected only; 2 => affected + related. Default: 2"
        ),
    )
    parser.add_argument(
        "--force-regenerate-profiles",
        action="store_true",
        help="Regenerate software/vulnerability profiles even when cached profile files exist",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Maximum worker count for scan stage (default: 1)",
    )
    parser.add_argument(
        "--scan-workers",
        type=int,
        default=None,
        help=(
            "Worker count for target scan stage; if omitted, inherits --max-workers "
            "(default: inherit)"
        ),
    )
    parser.add_argument(
        "--skip-existing-scans",
        action="store_true",
        help=(
            "Skip target scan only when existing agentic_vuln_findings.json has "
            "complete coverage metadata and a matching fingerprint"
        ),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of concurrent target scans per vulnerability (default: 1)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit on number of vuln entries from vuln.json",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logs")
    return parser.parse_args()


def _validate_args(args: argparse.Namespace) -> bool:
    max_workers = getattr(args, "max_workers", 1)
    scan_workers = getattr(args, "scan_workers", None)
    if not (0.0 <= args.similarity_threshold <= 1.0):
        logger.error("--similarity-threshold must be between 0 and 1")
        return False
    if args.max_targets is not None and args.max_targets <= 0:
        logger.error("--max-targets must be >= 1 when provided")
        return False
    if max_workers <= 0:
        logger.error("--max-workers must be >= 1")
        return False
    if scan_workers is not None and scan_workers <= 0:
        logger.error("--scan-workers must be >= 1")
        return False
    if args.fallback_top_n <= 0:
        logger.error("--fallback-top-n must be >= 1")
        return False
    if args.max_iterations_cap <= 0:
        logger.error("--max-iterations-cap must be >= 1")
        return False
    if getattr(args, "jobs", 1) <= 0:
        logger.error("--jobs must be >= 1")
        return False
    if args.limit is not None and args.limit < 0:
        logger.error("--limit must be >= 0 when provided")
        return False
    if not str(args.source_soft_profiles_dir).strip():
        logger.error("--source-soft-profiles-dir must not be empty")
        return False
    if not str(args.target_soft_profiles_dir).strip():
        logger.error("--target-soft-profiles-dir must not be empty")
        return False
    if not str(args.vuln_profiles_dir).strip():
        logger.error("--vuln-profiles-dir must not be empty")
        return False
    return True


def _resolve_scan_workers(args: argparse.Namespace) -> int:
    """Resolve scan worker count with default inheritance from --max-workers."""
    raw_scan_workers = getattr(args, "scan_workers", None)
    scan_workers = to_int(raw_scan_workers)
    max_workers = max(1, to_int(getattr(args, "max_workers", 1)))
    if raw_scan_workers is None:
        if max_workers != 1:
            return max_workers
        return max(1, to_int(getattr(args, "jobs", 1)))
    return max(1, scan_workers)


def _resolve_source_software_profile_dir_from_args(args: argparse.Namespace) -> Path:
    return resolve_profile_dirs(
        profile_base_path=args.profile_base_path,
        software_profile_dirname=args.source_soft_profiles_dir,
        vuln_profile_dirname=None,
    )[0]


def _resolve_target_and_vuln_profile_dirs_from_args(args: argparse.Namespace) -> tuple[Path, Path]:
    return resolve_profile_dirs(
        profile_base_path=args.profile_base_path,
        software_profile_dirname=args.target_soft_profiles_dir,
        vuln_profile_dirname=args.vuln_profiles_dir,
    )


def _resolve_batch_scan_paths(args: argparse.Namespace) -> Optional[BatchScanPaths]:
    """Resolve and validate batch-scan paths from CLI args."""
    target_repo_profiles_dir, vuln_profiles_dir = _resolve_target_and_vuln_profile_dirs_from_args(args)
    repo_root = _path_config["repo_root"]
    paths = BatchScanPaths(
        vuln_json=resolve_cli_path(args.vuln_json, base_dir=repo_root),
        source_repos_root=resolve_cli_path(args.source_repos_root, base_dir=repo_root),
        target_repos_root=resolve_cli_path(args.target_repos_root, base_dir=repo_root),
        source_repo_profiles_dir=_resolve_source_software_profile_dir_from_args(args),
        target_repo_profiles_dir=target_repo_profiles_dir,
        vuln_profiles_dir=vuln_profiles_dir,
        scan_output_dir=resolve_cli_path(args.scan_output_dir, base_dir=repo_root),
    )
    if not paths.vuln_json.is_file():
        logger.error(f"vuln.json not found or is not a file: {paths.vuln_json}")
        return None
    if not paths.target_repos_root.is_dir():
        logger.error(f"target repos root not found or is not a directory: {paths.target_repos_root}")
        return None
    if paths.scan_output_dir.exists() and not paths.scan_output_dir.is_dir():
        logger.error(f"scan output dir exists but is not a directory: {paths.scan_output_dir}")
        return None
    return paths


def _ensure_source_inputs_available(
    *,
    args: argparse.Namespace,
    paths: BatchScanPaths,
    entries: Sequence[Tuple[int, Dict[str, object]]],
) -> bool:
    """Validate source-root access or cached profile availability."""
    if paths.source_repos_root.exists() and not paths.source_repos_root.is_dir():
        logger.error(
            "source repos root exists but is not a directory: %s",
            paths.source_repos_root,
        )
        return False
    if paths.source_repos_root.exists():
        return True
    if args.force_regenerate_profiles:
        logger.error(
            "source repos root not found for forced regeneration: %s",
            paths.source_repos_root,
        )
        return False

    missing_cached_inputs = _find_missing_cached_source_inputs(
        entries=entries,
        source_repo_profiles_dir=paths.source_repo_profiles_dir,
        vuln_profiles_dir=paths.vuln_profiles_dir,
    )
    if missing_cached_inputs:
        preview = ", ".join(missing_cached_inputs[:3])
        suffix = " ..." if len(missing_cached_inputs) > 3 else ""
        logger.error(
            "source repos root not found: %s; missing cached source/vulnerability profiles: %s%s",
            paths.source_repos_root,
            preview,
            suffix,
        )
        return False

    logger.warning(
        "source repos root not found: %s; reusing cached source/vulnerability profiles only",
        paths.source_repos_root,
    )
    return True


def _initialize_profile_caches(paths: BatchScanPaths) -> BatchScanCaches:
    """Build shared or independent source/target caches based on resolved paths."""
    target_software_cache: Dict[Tuple[str, str], object] = {}
    regenerated_target_software_keys: Set[Tuple[str, str]] = set()
    shared_source_target_profile_state = (
        _paths_resolve_equal(paths.source_repos_root, paths.target_repos_root)
        and _paths_resolve_equal(paths.source_repo_profiles_dir, paths.target_repo_profiles_dir)
    )
    if shared_source_target_profile_state:
        source_software_cache = target_software_cache
        regenerated_source_software_keys = regenerated_target_software_keys
    else:
        source_software_cache = {}
        regenerated_source_software_keys = set()

    return BatchScanCaches(
        source_software_cache=source_software_cache,
        target_software_cache=target_software_cache,
        vulnerability_cache={},
        regenerated_source_software_keys=regenerated_source_software_keys,
        regenerated_target_software_keys=regenerated_target_software_keys,
    )


def _build_batch_summary(args: argparse.Namespace, paths: BatchScanPaths) -> Dict[str, object]:
    """Build the batch summary document header."""
    return {
        "started_at": datetime.now().isoformat(),
        "vuln_json": str(paths.vuln_json),
        "source_repos_root": str(paths.source_repos_root),
        "target_repos_root": str(paths.target_repos_root),
        "source_soft_profiles_dir": str(paths.source_repo_profiles_dir),
        "target_soft_profiles_dir": str(paths.target_repo_profiles_dir),
        "vuln_profiles_dir": str(paths.vuln_profiles_dir),
        "similarity_threshold": args.similarity_threshold,
        "max_targets": args.max_targets,
        "fallback_top_n": args.fallback_top_n,
        "include_same_repo": args.include_same_repo,
        "limit": args.limit,
        "max_iterations_cap": args.max_iterations_cap,
        "critical_stop_enabled": not args.disable_critical_stop,
        "critical_stop_mode": args.critical_stop_mode,
        "critical_stop_max_priority": getattr(args, "critical_stop_max_priority", 2),
        "force_regenerate_profiles": args.force_regenerate_profiles,
        "skip_existing_scans": args.skip_existing_scans,
        "jobs": getattr(args, "jobs", 1),
        "llm_provider": args.llm_provider,
        "llm_name": args.llm_name,
        "entries": [],
    }


def _build_scan_task_id(cve_id: str, candidate: SimilarProfileCandidate) -> str:
    """Build stable task id for one scan target."""
    return f"{cve_id}:{candidate.profile_ref.repo_name}:{candidate.profile_ref.commit_hash}"


def _run_target_scan_task(
    task: Dict[str, Any],
    *,
    batch_args: argparse.Namespace,
    target_repos_root: Path,
    repo_lock_manager: RepoPathLockManager,
) -> Dict[str, Any]:
    """Run one scan task in a worker with private llm client and repo lock."""
    target = task["target"]
    task_id = str(task["task_id"])
    cve_id = str(task["cve_id"])
    vulnerability_profile = task["vulnerability_profile"]
    target_repo_path = target_repos_root / target.profile_ref.repo_name
    lock = repo_lock_manager.get_lock(target_repo_path)
    output_base = getattr(batch_args, "scan_output_dir", None)
    output_dir = None
    if output_base is not None:
        output_dir = agent_scanner.resolve_output_dir(
            cve_id=cve_id,
            target_repo=target.profile_ref.repo_name,
            target_commit=target.profile_ref.commit_hash,
            output_base=str(output_base),
        )

    scan_client = create_llm_client(
        LLMConfig(provider=batch_args.llm_provider, model=batch_args.llm_name)
    )
    if _run_target_scan is not _IMPORTED_RUN_TARGET_SCAN:
        batch_scanner_execution_module._run_target_scan = _run_target_scan
    with lock:
        scan_status = batch_scanner_execution_module._run_target_scan(
            batch_args=batch_args,
            cve_id=cve_id,
            vulnerability_profile=vulnerability_profile,
            llm_client=scan_client,
            target=target,
        )

    saved_quality = (
        _load_saved_scan_quality(output_dir)
        if output_dir is not None and scan_status in {"ok", "skipped", "incomplete"}
        else {}
    )

    return {
        "task_id": task_id,
        "repo_name": target.profile_ref.repo_name,
        "commit_hash": target.profile_ref.commit_hash,
        "overall_similarity": target.metrics.overall_sim,
        "status": scan_status,
        "coverage_status": saved_quality.get("coverage_status", "unknown"),
        "critical_scope_present": saved_quality.get("critical_scope_present"),
        "critical_complete": saved_quality.get("critical_complete"),
        "critical_scope_total_files": saved_quality.get("critical_scope_total_files"),
        "critical_scope_completed_files": saved_quality.get("critical_scope_completed_files"),
        "scan_progress": saved_quality.get("scan_progress"),
    }


def _build_scan_tasks(
    cve_id: str,
    similar_targets: Sequence[SimilarProfileCandidate],
    vulnerability_profile: object,
) -> List[Dict[str, Any]]:
    """Build deduplicated scan tasks for one vulnerability entry."""
    tasks: List[Dict[str, Any]] = []
    seen_task_ids: Set[str] = set()
    for candidate in similar_targets:
        task_id = _build_scan_task_id(cve_id, candidate)
        if task_id in seen_task_ids:
            continue
        seen_task_ids.add(task_id)
        tasks.append(
            {
                "task_id": task_id,
                "cve_id": cve_id,
                "vulnerability_profile": vulnerability_profile,
                "target": candidate,
            }
        )
    return tasks


def _paths_resolve_equal(left: Path, right: Path) -> bool:
    """Compare paths after normalization so shared source/target inputs can reuse state."""
    return left.resolve() == right.resolve()


def _normalize_cve_id(entry: Dict[str, object], index: int) -> str:
    return normalize_cve_id(entry.get("cve_id"), index)


def _find_missing_cached_source_inputs(
    *,
    entries: Sequence[Tuple[int, Dict[str, object]]],
    source_repo_profiles_dir: Path,
    vuln_profiles_dir: Path,
) -> List[str]:
    """Return missing cached source profile artefacts required for source-root-free runs."""
    missing: List[str] = []
    seen: Set[str] = set()

    for vuln_index, entry in entries:
        repo_name = str(entry.get("repo_name", ""))
        commit_hash = str(entry.get("commit", ""))
        if not repo_name or not commit_hash:
            continue

        cve_id = _normalize_cve_id(entry, vuln_index)
        required_paths = [
            (
                source_repo_profiles_dir / repo_name / commit_hash / "software_profile.json",
                f"software profile {repo_name}@{commit_hash[:12]}",
            ),
            (
                vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json",
                f"vulnerability profile {repo_name}@{cve_id}",
            ),
        ]
        for path, label in required_paths:
            if path.exists() or label in seen:
                continue
            seen.add(label)
            missing.append(label)

    return missing


def _ensure_software_profile(
    *,
    repo_name: str,
    commit_hash: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    cache: Dict[Tuple[str, str], object],
    regenerated_keys: Set[Tuple[str, str]],
) -> Optional[object]:
    key = (repo_name, commit_hash)
    if force_regenerate and key in regenerated_keys and key in cache:
        return cache[key]
    if key in cache and not force_regenerate:
        return cache[key]
    if force_regenerate:
        cache.pop(key, None)

    repo_path = repos_root / repo_name
    if not repo_path.exists():
        # Cached-only batch runs can still reuse an already persisted profile even
        # when the original source repository is unavailable, but the cached
        # profile still has to pass the normal fingerprint validation.
        if not force_regenerate:
            cached_profile = _load_cached_software_profile_if_compatible(
                repo_name=repo_name,
                commit_hash=commit_hash,
                repo_profiles_dir=repo_profiles_dir,
                llm_client=llm_client,
            )
            if cached_profile:
                cache[key] = cached_profile
                return cached_profile
        logger.error(f"Repository not found for software profile generation: {repo_path}")
        return None

    if not force_regenerate and has_uncommitted_changes(str(repo_path)):
        # Dirty worktrees cannot go through the profiler's clean-worktree guard,
        # but batch resume should still reuse only a fingerprint-compatible
        # persisted profile. When the dirty checkout is already on the target
        # commit, validate against the full repo-state-aware hash; otherwise
        # fall back to commit-scoped cached-only validation because the current
        # dirty tree is unrelated to the requested profile commit.
        current_commit = get_git_commit(str(repo_path))
        cached_profile = _load_cached_software_profile_if_compatible(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            repo_path=repo_path if current_commit == commit_hash else None,
        )
        if cached_profile:
            cache[key] = cached_profile
            return cached_profile
        logger.error(
            "Repository %s has local changes and no cached software profile is available for %s",
            repo_name,
            commit_hash[:12],
        )
        return None

    logger.info(f"[Profile] Ensuring software profile: {repo_name}@{commit_hash[:12]}")
    run_software_profile_generation(
        repo_path=repo_path,
        output_dir=repo_profiles_dir,
        llm_client=llm_client,
        force_regenerate=force_regenerate,
        target_version=commit_hash,
    )

    profile = load_software_profile(repo_name, commit_hash, base_dir=repo_profiles_dir)
    if profile:
        cache[key] = profile
        if force_regenerate:
            regenerated_keys.add(key)
    return profile


def _ensure_vulnerability_profile(
    *,
    vuln_index: int,
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    vuln_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    software_cache: Dict[Tuple[str, str], object],
    regenerated_software_keys: Set[Tuple[str, str]],
    cache: Dict[Tuple[str, str], object],
    verbose: bool,
    vuln_json_path: Optional[str] = None,
) -> Optional[object]:
    key = (repo_name, cve_id)
    if key in cache and not force_regenerate:
        return cache[key]
    if force_regenerate:
        cache.pop(key, None)

    repo_path = repos_root / repo_name
    cached_profile_path = vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json"
    cached_profile = None
    if not force_regenerate and cached_profile_path.exists():
        cached_profile = load_vulnerability_profile(
            repo_name,
            cve_id,
            base_dir=vuln_profiles_dir,
        )

    if not repo_path.exists():
        source_profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            force_regenerate=force_regenerate,
            cache=software_cache,
            regenerated_keys=regenerated_software_keys,
        )
        if (
            cached_profile
            and source_profile
            and _cached_vulnerability_profile_matches_missing_repo_inputs(
                cached_profile=cached_profile,
                source_profile=source_profile,
                repo_name=repo_name,
                commit_hash=commit_hash,
                cve_id=cve_id,
                vuln_index=vuln_index,
                vuln_json_path=vuln_json_path,
                llm_client=llm_client,
            )
        ):
            cache[key] = cached_profile
            return cached_profile
        logger.error(f"Repository not found for vulnerability profile generation: {repo_path}")
        return None

    source_profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=llm_client,
        force_regenerate=force_regenerate,
        cache=software_cache,
        regenerated_keys=regenerated_software_keys,
    )
    if not source_profile:
        return None
    source_repo_dirty = False
    with hold_repo_lock(repo_path, purpose=f"vulnerability_profile_cache_probe:{cve_id}"):
        source_repo_dirty = has_uncommitted_changes(str(repo_path))
        if source_repo_dirty and cached_profile:
            if _cached_vulnerability_profile_matches_current_inputs(
                cached_profile=cached_profile,
                source_profile=source_profile,
                repo_path=repo_path,
                repo_name=repo_name,
                commit_hash=commit_hash,
                cve_id=cve_id,
                vuln_index=vuln_index,
                vuln_json_path=vuln_json_path,
                llm_client=llm_client,
            ):
                logger.warning(
                    "Repository has local changes; reusing compatible cached vulnerability profile: %s@%s",
                    repo_name,
                    cve_id,
                )
                cache[key] = cached_profile
                return cached_profile
            logger.error(
                "Repository has local changes and cached vulnerability profile is stale: %s@%s",
                repo_name,
                cve_id,
            )
    if source_repo_dirty:
        logger.error(
            "Repository has local changes and no reusable vulnerability profile: %s@%s",
            repo_name,
            cve_id,
        )
        return None

    selected = read_vuln_data(
        vuln_index,
        verbose=verbose,
        vuln_json_path=vuln_json_path,
        repo_base_path=repos_root,
    )
    if not selected:
        logger.error(f"Failed to read vulnerability entry index={vuln_index}")
        return None
    vuln_data = selected[0]
    logger.info(f"[Profile] Ensuring vulnerability profile: {repo_name}@{cve_id}")
    run_vulnerability_profile_generation(
        repo_path=repo_path,
        output_dir=vuln_profiles_dir,
        llm_client=llm_client,
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(vuln_data),
        force_regenerate=force_regenerate,
    )

    profile = load_vulnerability_profile(repo_name, cve_id, base_dir=vuln_profiles_dir)
    if profile:
        cache[key] = profile
    return profile


def _discover_latest_repo_refs(
    *,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate_profiles: bool,
    software_cache: Dict[Tuple[str, str], object],
    regenerated_software_keys: Set[Tuple[str, str]],
) -> Dict[str, ProfileRef]:
    refs: Dict[str, ProfileRef] = {}
    for repo_dir in sorted(repos_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        with hold_repo_lock(repo_dir, purpose="discover_latest_repo_ref"):
            commit_hash = get_git_commit(str(repo_dir))
        if not commit_hash:
            logger.warning(f"Skip non-git or unreadable repo: {repo_name}")
            continue
        profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            force_regenerate=force_regenerate_profiles,
            cache=software_cache,
            regenerated_keys=regenerated_software_keys,
        )
        if not profile:
            logger.warning(f"Skip repo without software profile: {repo_name}@{commit_hash[:12]}")
            continue
        refs[repo_name] = ProfileRef(repo_name=repo_name, commit_hash=commit_hash, profile=profile)
    return refs


def _rank_similar_candidates(
    *,
    source_ref: ProfileRef,
    candidate_refs: Sequence[ProfileRef],
    text_retriever,
) -> List[SimilarProfileCandidate]:
    ranked: List[SimilarProfileCandidate] = []
    for candidate in candidate_refs:
        metrics = compute_profile_similarity(
            source_profile=source_ref.profile,
            target_profile=candidate.profile,
            text_retriever=text_retriever,
        )
        ranked.append(SimilarProfileCandidate(profile_ref=candidate, metrics=metrics))

    ranked.sort(
        key=lambda item: (
            item.metrics.overall_sim,
            item.metrics.module_dependency_import_sim,
            item.metrics.module_jaccard_sim,
        ),
        reverse=True,
    )
    return ranked


def _select_similar_targets(
    *,
    ranked_candidates: Sequence[SimilarProfileCandidate],
    similarity_threshold: float,
    max_targets: Optional[int],
    fallback_top_n: int,
) -> Tuple[List[SimilarProfileCandidate], bool]:
    passed = [
        candidate
        for candidate in ranked_candidates
        if candidate.metrics.overall_sim >= similarity_threshold
    ]
    if passed:
        if max_targets is not None:
            passed = passed[:max_targets]
        return passed, False

    fallback = list(ranked_candidates[:fallback_top_n])
    if max_targets is not None:
        fallback = fallback[:max_targets]
    return fallback, bool(fallback)


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    if not _validate_args(args):
        return 1

    paths = _resolve_batch_scan_paths(args)
    if paths is None:
        return 1
    args.scan_output_dir = str(paths.scan_output_dir)

    entries = _load_vuln_entries(paths.vuln_json, limit=args.limit)
    if not entries:
        logger.warning("No vulnerability entries found")
        return 0

    if not _ensure_source_inputs_available(args=args, paths=paths, entries=entries):
        return 1

    logger.info(f"Loaded {len(entries)} vulnerabilities from {paths.vuln_json}")
    profile_llm = create_profile_llm_client(args.llm_provider, args.llm_name)
    text_retriever = build_text_retriever(
        model_name=args.similarity_model_name,
        device=args.similarity_device,
    )

    caches = _initialize_profile_caches(paths)

    logger.info("Ensuring latest software profiles for candidate repositories...")
    latest_repo_refs = _discover_latest_repo_refs(
        repos_root=paths.target_repos_root,
        repo_profiles_dir=paths.target_repo_profiles_dir,
        llm_client=profile_llm,
        force_regenerate_profiles=args.force_regenerate_profiles,
        software_cache=caches.target_software_cache,
        regenerated_software_keys=caches.regenerated_target_software_keys,
    )
    logger.info(f"Candidate repositories with latest profiles: {len(latest_repo_refs)}")
    scan_workers = _resolve_scan_workers(args)
    scan_task_lock_manager = RepoPathLockManager()

    # Keep local monkeypatches of _run_target_scan effective when tests or callers
    # replace the re-export on this module instead of the split execution module.
    if _run_target_scan is not _IMPORTED_RUN_TARGET_SCAN:
        batch_scanner_execution_module._run_target_scan = _run_target_scan

    summary = _build_batch_summary(args, paths)

    total_scans = 0
    success_scans = 0
    skipped_scans = 0
    incomplete_scans = 0
    failed_scans = 0
    failed_profile_generation = 0
    coverage_complete_scans = 0
    coverage_partial_scans = 0
    coverage_empty_scans = 0
    coverage_unknown_scans = 0

    for vuln_index, entry in entries:
        repo_name = str(entry.get("repo_name", ""))
        commit_hash = str(entry.get("commit", ""))
        cve_id = _normalize_cve_id(entry, vuln_index)
        if not repo_name or not commit_hash:
            logger.warning(f"[{vuln_index}] Skip malformed vuln entry: missing repo_name/commit")
            continue

        logger.info("")
        logger.info("=" * 100)
        logger.info(f"[Vuln {vuln_index}] {repo_name}@{commit_hash[:12]} {cve_id}")
        logger.info("=" * 100)

        source_profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=paths.source_repos_root,
            repo_profiles_dir=paths.source_repo_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            cache=caches.source_software_cache,
            regenerated_keys=caches.regenerated_source_software_keys,
        )
        vulnerability_profile = _ensure_vulnerability_profile(
            vuln_index=vuln_index,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            repos_root=paths.source_repos_root,
            repo_profiles_dir=paths.source_repo_profiles_dir,
            vuln_profiles_dir=paths.vuln_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            software_cache=caches.source_software_cache,
            regenerated_software_keys=caches.regenerated_source_software_keys,
            cache=caches.vulnerability_cache,
            verbose=args.verbose,
            vuln_json_path=str(paths.vuln_json),
        )

        if not source_profile or not vulnerability_profile:
            logger.error(f"[Vuln {vuln_index}] Missing required profiles, skip")
            failed_profile_generation += 1
            summary["entries"].append(
                {
                    "index": vuln_index,
                    "repo_name": repo_name,
                    "commit_hash": commit_hash,
                    "cve_id": cve_id,
                    "status": "failed_profile_generation",
                }
            )
            continue

        source_ref = ProfileRef(repo_name=repo_name, commit_hash=commit_hash, profile=source_profile)
        candidate_refs = list(latest_repo_refs.values())
        if not args.include_same_repo:
            # Batch auto-targeting should exclude same-repo candidates by repo identity
            # even when source and target roots come from different directories.
            candidate_refs = [
                ref
                for ref in candidate_refs
                if ref.repo_name != source_ref.repo_name
            ]
        ranked_candidates = _rank_similar_candidates(
            source_ref=source_ref,
            candidate_refs=candidate_refs,
            text_retriever=text_retriever,
        )
        logger.info(f"[Vuln {vuln_index}] Similarity details ({len(ranked_candidates)} candidates):")
        for i, candidate in enumerate(ranked_candidates, 1):
            metrics = candidate.metrics
            threshold_flag = "PASS" if metrics.overall_sim >= args.similarity_threshold else "BELOW"
            logger.info(
                f"  {i}. {candidate.profile_ref.label} "
                f"overall={metrics.overall_sim:.4f} [{threshold_flag}] "
                f"(desc={metrics.description_sim:.4f}, apps={metrics.target_application_sim:.4f}, "
                f"users={metrics.target_user_sim:.4f}, module={metrics.module_jaccard_sim:.4f}, "
                f"dep/import={metrics.module_dependency_import_sim:.4f})"
            )
        similar_targets, fallback_used = _select_similar_targets(
            ranked_candidates=ranked_candidates,
            similarity_threshold=args.similarity_threshold,
            max_targets=args.max_targets,
            fallback_top_n=args.fallback_top_n,
        )

        logger.info(
            f"[Vuln {vuln_index}] Selected {len(similar_targets)} targets "
            f"(threshold={args.similarity_threshold:.3f})"
        )
        if fallback_used:
            logger.warning(
                f"[Vuln {vuln_index}] No target reached threshold {args.similarity_threshold:.3f}; "
                f"fallback to top-{args.fallback_top_n}"
            )
        for i, candidate in enumerate(similar_targets, 1):
            logger.info(
                f"  {i}. {candidate.profile_ref.label} overall={candidate.metrics.overall_sim:.4f} "
                f"(module={candidate.metrics.module_jaccard_sim:.4f}, "
                f"dep/import={candidate.metrics.module_dependency_import_sim:.4f})"
            )

        deduplicated_targets: List[SimilarProfileCandidate] = []
        seen_scan_task_ids: Set[str] = set()
        for candidate in similar_targets:
            task_id = _build_scan_task_id(cve_id, candidate)
            if task_id in seen_scan_task_ids:
                continue
            seen_scan_task_ids.add(task_id)
            deduplicated_targets.append(candidate)

        vuln_record = {
            "index": vuln_index,
            "repo_name": repo_name,
            "commit_hash": commit_hash,
            "cve_id": cve_id,
            "selection_mode": "fallback_top_n" if fallback_used else "threshold",
            "selected_targets": [candidate.to_dict() for candidate in deduplicated_targets],
            "scan_results": [],
        }

        scan_tasks = _build_scan_tasks(
            cve_id=cve_id,
            similar_targets=deduplicated_targets,
            vulnerability_profile=vulnerability_profile,
        )
        total_scans += len(scan_tasks)
        scan_results = run_thread_pool_tasks(
            tasks=scan_tasks,
            worker_fn=lambda task: _run_target_scan_task(
                task=task,
                batch_args=args,
                target_repos_root=paths.target_repos_root,
                repo_lock_manager=scan_task_lock_manager,
            ),
            max_workers=scan_workers,
        )

        for scan_result in scan_results:
            payload = scan_result.payload or {}
            if scan_result.status == "error":
                logger.error(
                    "Scan task failed: %s (%s)",
                    payload.get("task_id", "unknown"),
                    scan_result.error_message,
                )
            scan_status = (
                str(payload.get("status", "failed"))
                if scan_result.status == "success"
                else "failed"
            )
            if scan_status == "ok":
                success_scans += 1
            elif scan_status == "skipped":
                skipped_scans += 1
            elif scan_status == "incomplete":
                incomplete_scans += 1
            else:
                failed_scans += 1

            coverage_status = str(payload.get("coverage_status", "unknown"))
            if coverage_status == "complete":
                coverage_complete_scans += 1
            elif coverage_status == "partial":
                coverage_partial_scans += 1
            elif coverage_status == "empty":
                coverage_empty_scans += 1
            else:
                coverage_unknown_scans += 1

            vuln_record["scan_results"].append(
                {
                    "repo_name": payload.get("repo_name", ""),
                    "commit_hash": payload.get("commit_hash", ""),
                    "overall_similarity": payload.get("overall_similarity", 0.0),
                    "status": scan_status,
                    "coverage_status": coverage_status,
                }
            )

        summary["entries"].append(vuln_record)

    summary["finished_at"] = datetime.now().isoformat()
    summary["total_scans"] = total_scans
    summary["successful_scans"] = success_scans
    summary["skipped_scans"] = skipped_scans
    summary["incomplete_scans"] = incomplete_scans
    summary["failed_profile_generation"] = failed_profile_generation
    summary["failed_scans"] = failed_scans
    summary["coverage_complete_scans"] = coverage_complete_scans
    summary["coverage_partial_scans"] = coverage_partial_scans
    summary["coverage_empty_scans"] = coverage_empty_scans
    summary["coverage_unknown_scans"] = coverage_unknown_scans

    paths.scan_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = paths.scan_output_dir / (
        f"batch-summary-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
    )
    write_atomic_text(
        summary_path,
        json.dumps(summary, indent=2, ensure_ascii=False),
    )

    logger.info(f"Batch summary saved to: {summary_path}")
    logger.info(
        "Finished: %s ok, %s skipped, %s incomplete, %s failed target scans, %s profile failures "
        "(coverage: %s complete, %s partial, %s empty, %s unknown; target scans total=%s)",
        success_scans,
        skipped_scans,
        incomplete_scans,
        failed_scans,
        failed_profile_generation,
        coverage_complete_scans,
        coverage_partial_scans,
        coverage_empty_scans,
        coverage_unknown_scans,
        total_scans,
    )
    # Reused results are useful for summaries, but they should not hide fresh
    # scan failures during a resumed run.
    return (
        0
        if incomplete_scans == 0
        and failed_scans == 0
        and failed_profile_generation == 0
        and (success_scans > 0 or skipped_scans > 0)
        else 1
    )
if __name__ == "__main__":
    raise SystemExit(main())
