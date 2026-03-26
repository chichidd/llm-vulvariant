#!/usr/bin/env python3
"""CLI wrapper for the agentic vulnerability finder.

Modes:
1) Manual mode:
   - `--target-repo` provided (optional `--target-commit`)
2) Auto-target mode:
   - `--target-repo` not provided
   - select top-k most similar software profiles automatically
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    DEFAULT_VULN_PROFILE_DIRNAME,
    _path_config,
    _scanner_config,
)
from llm import LLMConfig, create_llm_client
from profiler.fingerprint import extract_profile_fingerprint, stable_data_hash
from scanner.agent import AgenticVulnFinder, load_software_profile, load_vulnerability_profile
from scanner.agent.shared_memory import SharedPublicMemoryManager
from scanner.agent.utils import make_serializable
from scanner.similarity.embedding import (
    DEFAULT_EMBEDDING_MODEL_NAME,
    embedding_model_artifact_signature,
)
from scanner.similarity import (
    SimilarProfileCandidate,
    build_text_retriever,
    load_all_software_profiles,
    rank_similar_profiles,
    resolve_profile_commit,
    select_profile_ref,
)
from utils.io_utils import write_atomic_text
from utils.git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from utils.language import dedupe_languages as _dedupe_languages, detect_languages as detect_repo_languages
from utils.logger import get_logger
from utils.repo_lock import acquire_repo_lock, hold_repo_lock, release_repo_lock
try:
    from cli.common import resolve_cli_path, resolve_profile_dirs, setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import resolve_cli_path, resolve_profile_dirs, setup_logging

logger = get_logger(__name__)
SCAN_FINGERPRINT_SCHEMA_VERSION = 1


@dataclass
class ScanTarget:
    repo_name: str
    commit_hash: str
    similarity: Optional[SimilarProfileCandidate] = None


def _extract_repo_analysis(software_profile) -> Dict[str, object]:
    repo_info = {}
    if hasattr(software_profile, "repo_info"):
        repo_info = getattr(software_profile, "repo_info", {}) or {}
    elif isinstance(software_profile, dict):
        repo_info = software_profile.get("repo_info", {}) or {}

    if not isinstance(repo_info, dict):
        return {}
    repo_analysis = repo_info.get("repo_analysis", {})
    return repo_analysis if isinstance(repo_analysis, dict) else {}


def _resolve_scan_languages(target_repo_path: Path, software_profile) -> List[str]:
    repo_analysis = _extract_repo_analysis(software_profile)
    profile_languages = repo_analysis.get("languages", [])
    if isinstance(profile_languages, list):
        normalized_profile_languages = _dedupe_languages(profile_languages)
        if normalized_profile_languages:
            return normalized_profile_languages

    detected_languages = _dedupe_languages(detect_repo_languages(target_repo_path))
    return detected_languages


def _resolve_codeql_database_names(
    target: ScanTarget,
    scan_languages: List[str],
    software_profile,
) -> Dict[str, str]:
    repo_analysis = _extract_repo_analysis(software_profile)
    metadata = getattr(software_profile, "metadata", {}) if hasattr(software_profile, "metadata") else {}
    if not isinstance(metadata, dict) and isinstance(software_profile, dict):
        metadata = software_profile.get("metadata", {})
    profile_repo_path = str(metadata.get("profile_repo_path", "") or "").strip() if isinstance(metadata, dict) else ""
    repo_path_hash = stable_data_hash(profile_repo_path)[:12] if profile_repo_path else ""
    codeql_languages: List[str] = []

    configured_codeql_languages = repo_analysis.get("codeql_languages", [])
    if isinstance(configured_codeql_languages, list):
        codeql_languages = _dedupe_languages(configured_codeql_languages)

    active_languages = codeql_languages or _dedupe_languages(scan_languages)
    return {
        # Match the path-sensitive CodeQL DB identity emitted during repo analysis.
        lang: (
            f"{target.repo_name}-{repo_path_hash}-{target.commit_hash[:8]}-{lang}"
            if repo_path_hash
            else f"{target.repo_name}-{target.commit_hash[:8]}-{lang}"
        )
        for lang in active_languages
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Finder")
    parser.add_argument(
        "--vuln-repo",
        type=str,
        required=True,
        help="Repository name where vulnerability profile was generated",
    )
    parser.add_argument("--cve", type=str, required=True, help="CVE or vulnerability ID")

    parser.add_argument(
        "--target-repo",
        type=str,
        default=None,
        help=(
            "Repository name to scan. If omitted, scanner automatically picks top-k "
            "similar software profiles from configured repo profiles directory."
        ),
    )
    parser.add_argument(
        "--target-commit",
        type=str,
        default=None,
        help=(
            "Target commit hash or prefix for manual mode. If omitted, scanner tries "
            "source vulnerable commit (same repo) or current/local profile commit."
        ),
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="In auto-target mode, number of most similar profiles to scan (default: 3)",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=None,
        help=(
            "Optional minimum overall similarity for auto-target candidates. "
            "When set, only candidates with overall similarity >= threshold are kept."
        ),
    )
    parser.add_argument(
        "--include-same-repo",
        action="store_true",
        help="In auto-target mode, include profiles from the same source repository",
    )
    parser.add_argument(
        "--similarity-model-name",
        type=str,
        default=DEFAULT_EMBEDDING_MODEL_NAME,
        help="Embedding model name under paths.embedding_model_path for text similarity",
    )
    parser.add_argument(
        "--similarity-device",
        type=str,
        default="cpu",
        help="Embedding device for similarity scoring (default: cpu)",
    )
    parser.add_argument(
        "--repo-base-path",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Base directory containing target repositories (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--profile-base-path",
        type=str,
        default=str(_path_config["profile_base_path"]),
        help="Base directory containing profile folders (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--software-profile-dirname",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help="Software profile directory name under --profile-base-path (default: soft)",
    )
    parser.add_argument(
        "--vuln-profile-dirname",
        type=str,
        default=DEFAULT_VULN_PROFILE_DIRNAME,
        help="Vulnerability profile directory name under --profile-base-path (default: vuln)",
    )

    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider (deepseek, openai, lab)",
    )
    parser.add_argument(
        "--llm-name",
        type=str,
        default=None,
        help="Optional model name override for the chosen provider",
    )
    parser.add_argument("--max-iterations", type=int, default=3, help="Maximum iterations")
    parser.add_argument(
        "--stop-when-critical-complete",
        action="store_true",
        help=(
            "Enable priority-1 completion aware stopping policy. "
            "Use --critical-stop-mode to choose min/max composition."
        ),
    )
    parser.add_argument(
        "--critical-stop-mode",
        type=str,
        choices=["min", "max"],
        default="max",
        help=(
            "When --stop-when-critical-complete is enabled: "
            "min => stop at min(max-iterations, X); "
            "max => stop at max(max-iterations, X). Default: max"
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
    parser.add_argument("--output", type=str, default=None, help="Output base directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def resolve_output_dir(
    cve_id: str,
    target_repo: str,
    target_commit: str,
    output_base: Optional[str | Path],
) -> Path:
    """Resolve one target output folder under an absolute or repo-root-relative base."""
    folder_name = f"{cve_id}/{target_repo}-{target_commit[:12]}"
    output_root = resolve_cli_path(
        output_base or "scan-results",
        base_dir=_path_config["repo_root"],
    )
    return output_root / folder_name


def build_shared_public_memory_visibility_scope_id(
    cve_id: str,
    target_repo: str,
    target_commit: str,
    target_output_dir: Path,
) -> str:
    """Build the stable logical scan scope id used to hide self-produced shared memory."""
    return stable_data_hash(
        {
            "cve_id": cve_id,
            "target_repo": target_repo,
            "target_commit": target_commit,
            "target_output_dir": str(target_output_dir.resolve()),
        }
    )[:16]


def _validate_args(args: argparse.Namespace) -> bool:
    if args.target_commit and not args.target_repo:
        logger.error("--target-commit requires --target-repo")
        return False
    if args.top_k <= 0:
        logger.error("--top-k must be >= 1")
        return False
    similarity_threshold = getattr(args, "similarity_threshold", None)
    if similarity_threshold is not None and not (0.0 <= similarity_threshold <= 1.0):
        logger.error("--similarity-threshold must be between 0 and 1")
        return False
    if not str(
        getattr(args, "software_profile_dirname", DEFAULT_SOFTWARE_PROFILE_DIRNAME)
    ).strip():
        logger.error("--software-profile-dirname must not be empty")
        return False
    if not str(
        getattr(args, "vuln_profile_dirname", DEFAULT_VULN_PROFILE_DIRNAME)
    ).strip():
        logger.error("--vuln-profile-dirname must not be empty")
        return False
    return True


def _resolve_profile_dirs(args: argparse.Namespace) -> tuple[Path, Path]:
    return resolve_profile_dirs(
        profile_base_path=getattr(args, "profile_base_path", None),
        software_profile_dirname=getattr(args, "software_profile_dirname", None),
        vuln_profile_dirname=getattr(args, "vuln_profile_dirname", None),
    )


def _resolve_manual_targets(
    args: argparse.Namespace,
    vulnerability_profile,
    repo_profiles_dir: Path,
) -> List[ScanTarget]:
    repo_name = args.target_repo
    if not repo_name:
        return []

    commit_hint = args.target_commit
    source_repo = getattr(vulnerability_profile, "repo_name", "") or args.vuln_repo
    source_commit = getattr(vulnerability_profile, "affected_version", None)

    if not commit_hint and repo_name == source_repo and source_commit:
        commit_hint = source_commit

    if not commit_hint:
        repo_base_path = Path(getattr(args, "repo_base_path", _path_config["repo_base_path"])).expanduser()
        if not repo_base_path.is_absolute():
            repo_base_path = _path_config["repo_root"] / repo_base_path
        repo_path = repo_base_path / repo_name
        with hold_repo_lock(repo_path, purpose="resolve_manual_target_commit"):
            commit_hint = get_git_commit(str(repo_path))

    resolved_commit = resolve_profile_commit(repo_profiles_dir, repo_name, commit_hint)
    if not resolved_commit:
        if commit_hint:
            logger.error(
                f"Unable to resolve software profile commit for {repo_name} with hint {commit_hint[:12]}"
            )
        else:
            logger.error(f"Unable to resolve software profile commit for {repo_name}")
        return []

    return [ScanTarget(repo_name=repo_name, commit_hash=resolved_commit)]


def _resolve_auto_targets(
    args: argparse.Namespace,
    vulnerability_profile,
    repo_profiles_dir: Path,
) -> List[ScanTarget]:
    refs = load_all_software_profiles(repo_profiles_dir)
    if not refs:
        logger.error(f"No software profiles found under: {repo_profiles_dir}")
        return []

    source_repo = getattr(vulnerability_profile, "repo_name", "") or args.vuln_repo
    source_commit_hint = getattr(vulnerability_profile, "affected_version", None)
    source_ref = select_profile_ref(refs, source_repo, source_commit_hint)
    if not source_ref:
        logger.error(
            "Unable to find source software profile for auto-target selection: "
            f"{source_repo}@{(source_commit_hint or '')[:12]}"
        )
        return []

    logger.info(f"Auto-target source profile: {source_ref.label}")

    text_retriever = build_text_retriever(
        model_name=args.similarity_model_name,
        device=args.similarity_device,
    )
    similarity_threshold = getattr(args, "similarity_threshold", None)
    ranked = rank_similar_profiles(
        source_ref=source_ref,
        candidate_refs=refs,
        top_k=args.top_k,
        min_overall_similarity=float(similarity_threshold or 0.0),
        text_retriever=text_retriever,
        exclude_same_repo=not args.include_same_repo,
    )
    if not ranked:
        logger.error("No similar profiles found for auto-target mode")
        return []

    if similarity_threshold is None:
        logger.info(f"Selected top-{len(ranked)} similar targets:")
    else:
        logger.info(
            f"Selected {len(ranked)} similar targets with overall similarity >= {similarity_threshold:.3f}:"
        )
    for index, candidate in enumerate(ranked, 1):
        metrics = candidate.metrics
        logger.info(
            f"{index}. {candidate.profile_ref.label} "
            f"(overall={metrics.overall_sim:.4f}, "
            f"desc={metrics.description_sim:.4f}, "
            f"apps={metrics.target_application_sim:.4f}, "
            f"users={metrics.target_user_sim:.4f}, "
            f"module={metrics.module_jaccard_sim:.4f}, "
            f"dep/import={metrics.module_dependency_import_sim:.4f})"
        )

    return [
        ScanTarget(
            repo_name=candidate.profile_ref.repo_name,
            commit_hash=candidate.profile_ref.commit_hash,
            similarity=candidate,
        )
        for candidate in ranked
    ]


def _save_scan_outputs(
    output_dir: Path,
    finder: AgenticVulnFinder,
    results: Dict[str, object],
    target: ScanTarget,
    scan_fingerprint: Optional[Dict[str, Any]] = None,
) -> None:
    results_payload: Dict[str, Any] = dict(results)
    results_payload.update(_build_scan_quality_metadata(finder))
    if scan_fingerprint:
        results_payload["scan_fingerprint"] = scan_fingerprint
    output_path = output_dir / "agentic_vuln_findings.json"
    write_atomic_text(
        output_path,
        json.dumps(results_payload, indent=2, ensure_ascii=False),
    )

    conversation_path = output_dir / "conversation_history.json"
    write_atomic_text(
        conversation_path,
        json.dumps(make_serializable(finder.conversation_history), indent=2, ensure_ascii=False),
    )

    if target.similarity:
        similarity_path = output_dir / "target_similarity.json"
        write_atomic_text(
            similarity_path,
            json.dumps(target.similarity.to_dict(), indent=2, ensure_ascii=False),
        )

    logger.info(f"Results saved to: {output_path}")
    logger.info(f"Conversation history saved to: {conversation_path}")


def _hash_scan_source_file(path: Path) -> str:
    """Hash one source file that materially affects scan outputs."""
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _profile_hash(profile: Any) -> str:
    """Prefer persisted profile fingerprints; fall back to a stable profile hash."""
    persisted_fingerprint = extract_profile_fingerprint(profile)
    persisted_hash = str(persisted_fingerprint.get("hash", "")).strip()
    if persisted_hash:
        return persisted_hash
    profile_payload = profile.to_dict() if hasattr(profile, "to_dict") else profile
    return stable_data_hash(profile_payload)


def build_scan_fingerprint(
    *,
    vulnerability_profile: Any,
    software_profile: Any,
    llm_client: Any,
    max_iterations: int,
    stop_when_critical_complete: bool,
    critical_stop_mode: str,
    critical_stop_max_priority: int,
    scan_languages: List[str],
    codeql_database_names: Dict[str, str],
    shared_public_memory_scope: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a reproducibility fingerprint for one target scan result."""
    llm_config = getattr(llm_client, "config", None)
    cli_root = Path(__file__).resolve().parent
    agent_root = cli_root.parent / "scanner" / "agent"
    similarity_root = cli_root.parent / "scanner" / "similarity"
    shared_memory_scope = shared_public_memory_scope or {}
    payload = {
        "schema_version": SCAN_FINGERPRINT_SCHEMA_VERSION,
        "kind": "scan_result",
        "vulnerability_profile_hash": _profile_hash(vulnerability_profile),
        "target_software_profile_hash": _profile_hash(software_profile),
        "llm": {
            "provider": getattr(llm_config, "provider", ""),
            "model": getattr(llm_config, "model", ""),
            "base_url": getattr(llm_config, "base_url", ""),
            "temperature": getattr(llm_config, "temperature", None),
            "top_p": getattr(llm_config, "top_p", None),
            "max_tokens": getattr(llm_config, "max_tokens", None),
            "enable_thinking": getattr(llm_config, "enable_thinking", None),
        },
        "scan_config": {
            "max_iterations": int(max_iterations),
            "stop_when_critical_complete": bool(stop_when_critical_complete),
            "critical_stop_mode": str(critical_stop_mode),
            "critical_stop_max_priority": int(critical_stop_max_priority),
            "scan_languages": list(scan_languages or []),
            "codeql_database_names": dict(codeql_database_names or {}),
            "shared_public_memory": {
                "enabled": bool(shared_memory_scope.get("enabled", False)),
                "root_hash": str(shared_memory_scope.get("root_hash", "")).strip(),
                "scope_key": str(shared_memory_scope.get("scope_key", "")).strip(),
                "state_hash": str(shared_memory_scope.get("state_hash", "")).strip(),
            },
            "module_similarity": {
                "threshold": float(_scanner_config.get("module_similarity", {}).get("threshold", 0.8)),
                "model_name": str(_scanner_config.get("module_similarity", {}).get("model_name", "")).strip(),
                "device": str(_scanner_config.get("module_similarity", {}).get("device", "cpu")).strip(),
                **embedding_model_artifact_signature(
                    str(_scanner_config.get("module_similarity", {}).get("model_name", "")).strip() or None
                ),
            },
        },
        "source_hashes": {
            "cli/agent_scanner.py": _hash_scan_source_file(cli_root / "agent_scanner.py"),
            "scanner/agent/finder.py": _hash_scan_source_file(agent_root / "finder.py"),
            "scanner/agent/memory.py": _hash_scan_source_file(agent_root / "memory.py"),
            "scanner/agent/priority.py": _hash_scan_source_file(agent_root / "priority.py"),
            "scanner/agent/prompts.py": _hash_scan_source_file(agent_root / "prompts.py"),
            "scanner/agent/shared_memory.py": _hash_scan_source_file(agent_root / "shared_memory.py"),
            "scanner/agent/utils.py": _hash_scan_source_file(agent_root / "utils.py"),
            "scanner/agent/toolkit.py": _hash_scan_source_file(agent_root / "toolkit.py"),
            "scanner/agent/toolkit_fs.py": _hash_scan_source_file(agent_root / "toolkit_fs.py"),
            "scanner/agent/toolkit_codeql.py": _hash_scan_source_file(agent_root / "toolkit_codeql.py"),
            "scanner/similarity/retriever.py": _hash_scan_source_file(similarity_root / "retriever.py"),
            "scanner/similarity/embedding.py": _hash_scan_source_file(similarity_root / "embedding.py"),
            "config.py": _hash_scan_source_file(cli_root.parent / "config.py"),
            "utils/codeql_native.py": _hash_scan_source_file(cli_root.parent / "utils" / "codeql_native.py"),
        },
    }
    return {
        **payload,
        "hash": stable_data_hash(payload),
    }


def _build_scan_quality_metadata(finder: AgenticVulnFinder) -> Dict[str, Any]:
    """Summarize scan coverage quality for result files and batch summaries."""
    memory = getattr(finder, "memory", None)
    if memory is None:
        return {
            "coverage_status": "unknown",
            "critical_scope_present": False,
            "critical_complete": False,
            "critical_scope_total_files": 0,
            "critical_scope_completed_files": 0,
            "scan_progress": {},
        }

    progress = memory.get_progress()
    priority_1 = progress.get("priority_1", {})
    priority_2 = progress.get("priority_2", {})
    critical_stop_max_priority = int(getattr(finder, "critical_stop_max_priority", 2))
    if critical_stop_max_priority not in {1, 2}:
        critical_stop_max_priority = 2
    critical_scope_total = int(priority_1.get("total", 0))
    critical_scope_completed = int(priority_1.get("completed", 0))
    if critical_stop_max_priority >= 2:
        critical_scope_total += int(priority_2.get("total", 0))
        critical_scope_completed += int(priority_2.get("completed", 0))
    completed_files = int(progress.get("completed", 0))
    findings = int(progress.get("findings", 0))
    critical_complete = bool(memory.is_critical_complete(max_priority=critical_stop_max_priority))

    # Coverage status should reflect the configured critical scan scope rather
    # than all lower-priority pending files.
    if critical_complete:
        coverage_status = "complete"
    elif completed_files > 0 or findings > 0:
        coverage_status = "partial"
    else:
        coverage_status = "empty"

    return {
        "coverage_status": coverage_status,
        "critical_scope_present": critical_scope_total > 0,
        "critical_complete": critical_complete,
        "critical_scope_total_files": critical_scope_total,
        "critical_scope_completed_files": critical_scope_completed,
        "scan_progress": progress,
    }


def _resolve_soft_profiles_dir_for_scan(
    profile_base_path: Optional[str],
    software_profile_dirname: Optional[str],
) -> Path:
    return resolve_profile_dirs(
        profile_base_path=profile_base_path,
        software_profile_dirname=software_profile_dirname,
        vuln_profile_dirname=None,
    )[0]


def run_single_target_scan(
    *,
    cve_id: str,
    output_base: str | Path,
    repo_base_path: str | Path,
    max_iterations: int,
    vulnerability_profile,
    llm_client,
    target: ScanTarget,
    verbose: bool = False,
    stop_when_critical_complete: bool = False,
    critical_stop_mode: str = "max",
    critical_stop_max_priority: int = 2,
    profile_base_path: Optional[str] = None,
    software_profile_dirname: Optional[str] = None,
    shared_public_memory_dir: Optional[str | Path] = None,
) -> bool:
    """Run one target scan through a stable public interface used by both CLIs."""
    resolved_repo_base_path = Path(repo_base_path).expanduser()
    if not resolved_repo_base_path.is_absolute():
        resolved_repo_base_path = _path_config["repo_root"] / resolved_repo_base_path
    target_repo_path = resolved_repo_base_path / target.repo_name
    if not target_repo_path.exists():
        logger.error(f"Repository not found: {target_repo_path}")
        return False

    lock_purpose = f"agent_scan:{cve_id}:{target.commit_hash[:12]}"
    with hold_repo_lock(target_repo_path, purpose=lock_purpose):
        original_commit = get_git_commit(str(target_repo_path))
        original_restore_target = get_git_restore_target(str(target_repo_path))
        changed_commit = False
        scan_succeeded = False
        restore_failed = False
        repo_is_clean: Optional[bool] = None

        try:
            needs_checkout = original_commit != target.commit_hash
            if needs_checkout and not original_restore_target:
                logger.error(
                    "Unable to resolve original git position for %s; refuse commit switch to %s",
                    target.repo_name,
                    target.commit_hash[:12],
                )
            else:
                repo_is_clean = not has_uncommitted_changes(str(target_repo_path))
            if needs_checkout and original_restore_target and repo_is_clean:
                logger.info(f"Checking out {target.repo_name} to {target.commit_hash[:12]}...")
                if not checkout_commit(str(target_repo_path), target.commit_hash):
                    logger.error(f"Failed to checkout to {target.commit_hash}")
                else:
                    changed_commit = True
            elif repo_is_clean is False:
                logger.error(
                    "Repository %s has local changes; scan requires a clean working tree.",
                    target.repo_name,
                )

            if (
                (not needs_checkout or changed_commit)
                and repo_is_clean is True
                and (not needs_checkout or original_restore_target)
            ):
                logger.info(f"Loading software profile: {target.repo_name}@{target.commit_hash[:12]}...")
                soft_profiles_dir = _resolve_soft_profiles_dir_for_scan(
                    profile_base_path=profile_base_path,
                    software_profile_dirname=software_profile_dirname,
                )
                software_profile = load_software_profile(
                    target.repo_name,
                    target.commit_hash,
                    base_dir=soft_profiles_dir,
                )
                if not software_profile:
                    logger.error(
                        f"Failed to load software profile for {target.repo_name}@{target.commit_hash[:12]}"
                    )
                else:
                    target_output_dir = resolve_output_dir(
                        cve_id=cve_id,
                        target_repo=target.repo_name,
                        target_commit=target.commit_hash,
                        output_base=output_base,
                    )
                    target_output_dir.mkdir(parents=True, exist_ok=True)
                    shared_public_memory_root: Optional[Path] = None
                    if shared_public_memory_dir is not None:
                        shared_public_memory_root = Path(shared_public_memory_dir).expanduser()
                        if not shared_public_memory_root.is_absolute():
                            shared_public_memory_root = _path_config["repo_root"] / shared_public_memory_root

                    scan_languages = _resolve_scan_languages(target_repo_path, software_profile)
                    codeql_database_names = _resolve_codeql_database_names(
                        target,
                        scan_languages,
                        software_profile,
                    )

                    logger.info(
                        "Target languages: %s",
                        ", ".join(scan_languages) if scan_languages else "none",
                    )
                    if codeql_database_names:
                        logger.info(
                            "CodeQL databases: %s",
                            ", ".join(
                                f"{lang}={db_name}"
                                for lang, db_name in sorted(codeql_database_names.items())
                            ),
                        )
                    else:
                        logger.info("CodeQL databases: none (CodeQL tools may be unavailable)")

                    output_lock_info = None
                    output_lock_purpose = f"scan_output:{cve_id}:{target.repo_name}:{target.commit_hash[:12]}"
                    try:
                        # Serialize finder lifecycle for a shared output directory, since finder
                        # initialization and run both write scan_memory.json.
                        output_lock_info = acquire_repo_lock(
                            target_output_dir,
                            purpose=output_lock_purpose,
                        )
                        shared_public_memory_visibility_scope_id = build_shared_public_memory_visibility_scope_id(
                            cve_id=cve_id,
                            target_repo=target.repo_name,
                            target_commit=target.commit_hash,
                            target_output_dir=target_output_dir,
                        )
                        shared_public_memory_producer_id = (
                            f"{cve_id}:"
                            f"{stable_data_hash({
                                'visibility_scope_id': shared_public_memory_visibility_scope_id,
                                'scan_started_at': datetime.now().isoformat(timespec='microseconds'),
                            })[:16]}"
                        )
                        shared_public_memory_manager = (
                            SharedPublicMemoryManager(
                                root_dir=shared_public_memory_root,
                                repo_name=target.repo_name,
                                repo_commit=target.commit_hash,
                                repo_scope_key=stable_data_hash(str(target_repo_path.resolve()))[:12],
                                producer_id=shared_public_memory_producer_id,
                                visibility_scope_id=shared_public_memory_visibility_scope_id,
                            )
                            if shared_public_memory_root is not None
                            else None
                        )
                        shared_public_memory_scope = (
                            shared_public_memory_manager.describe_scope()
                            if shared_public_memory_manager is not None
                            else {"enabled": False, "root_hash": "", "scope_key": "", "state_hash": ""}
                        )
                        finder = AgenticVulnFinder(
                            llm_client=llm_client,
                            repo_path=target_repo_path,
                            software_profile=software_profile,
                            vulnerability_profile=vulnerability_profile,
                            max_iterations=max_iterations,
                            stop_when_critical_complete=stop_when_critical_complete,
                            critical_stop_mode=critical_stop_mode,
                            critical_stop_max_priority=critical_stop_max_priority,
                            verbose=verbose,
                            output_dir=target_output_dir,
                            languages=scan_languages,
                            codeql_database_names=codeql_database_names,
                            shared_public_memory_manager=shared_public_memory_manager,
                            shared_public_memory_scope=shared_public_memory_scope,
                        )
                        scan_fingerprint = build_scan_fingerprint(
                            vulnerability_profile=vulnerability_profile,
                            software_profile=software_profile,
                            llm_client=llm_client,
                            max_iterations=max_iterations,
                            stop_when_critical_complete=stop_when_critical_complete,
                            critical_stop_mode=critical_stop_mode,
                            critical_stop_max_priority=critical_stop_max_priority,
                            scan_languages=scan_languages,
                            codeql_database_names=codeql_database_names,
                            shared_public_memory_scope=shared_public_memory_scope,
                        )
                        results = finder.run()
                        _save_scan_outputs(
                            target_output_dir,
                            finder,
                            results,
                            target,
                            scan_fingerprint=scan_fingerprint,
                        )
                    finally:
                        release_repo_lock(
                            output_lock_info,
                            target_output_dir,
                            output_lock_purpose,
                        )

                    vulnerabilities = results.get("vulnerabilities", []) if isinstance(results, dict) else []
                    quality = _build_scan_quality_metadata(finder)
                    logger.info(
                        f"Target {target.repo_name}@{target.commit_hash[:12]} finished: "
                        f"{len(vulnerabilities)} potential vulnerabilities, "
                        f"coverage={quality['coverage_status']}, "
                        f"critical={quality['critical_scope_completed_files']}/"
                        f"{quality['critical_scope_total_files']}"
                    )
                    if quality["coverage_status"] != "complete":
                        logger.error(
                            "Target %s@%s did not finish with complete coverage (%s)",
                            target.repo_name,
                            target.commit_hash[:12],
                            quality["coverage_status"],
                        )
                    else:
                        scan_succeeded = True
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(f"Scan failed for {target.repo_name}@{target.commit_hash[:12]}: {exc}")
            scan_succeeded = False
        finally:
            if changed_commit and original_restore_target:
                logger.info(
                    "Restoring %s to original position %s...",
                    target.repo_name,
                    original_restore_target,
                )
                restored = restore_git_position(str(target_repo_path), original_restore_target)
                if not restored:
                    logger.error(
                        "Failed to restore %s to original position %s",
                        target.repo_name,
                        original_restore_target,
                    )
                    restore_failed = True
        if restore_failed:
            return False
        return scan_succeeded


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    if not _validate_args(args):
        return 1
    repo_profiles_dir, vuln_profiles_dir = _resolve_profile_dirs(args)

    logger.info(f"Resolved software profile dir: {repo_profiles_dir}")
    logger.info(f"Resolved vulnerability profile dir: {vuln_profiles_dir}")

    logger.info(f"Loading vulnerability profile from {args.vuln_repo}@{args.cve}...")
    vulnerability_profile = load_vulnerability_profile(
        args.vuln_repo,
        args.cve,
        base_dir=vuln_profiles_dir,
    )
    if not vulnerability_profile:
        logger.error("Failed to load vulnerability profile")
        return 1

    if args.target_repo:
        targets = _resolve_manual_targets(args, vulnerability_profile, repo_profiles_dir)
    else:
        targets = _resolve_auto_targets(args, vulnerability_profile, repo_profiles_dir)

    if not targets:
        logger.error("No scan targets resolved")
        return 1

    llm_client = create_llm_client(LLMConfig(provider=args.llm_provider, model=args.llm_name))
    logger.info(f"Using LLM provider: {args.llm_provider}")

    success_count = 0
    for idx, target in enumerate(targets, 1):
        logger.info("")
        logger.info("=" * 80)
        logger.info(
            f"[{idx}/{len(targets)}] Scanning target: "
            f"{target.repo_name}@{target.commit_hash[:12]}"
        )
        logger.info("=" * 80)
        success = run_single_target_scan(
            cve_id=args.cve,
            output_base=args.output,
            repo_base_path=getattr(args, "repo_base_path", _path_config["repo_base_path"]),
            max_iterations=args.max_iterations,
            vulnerability_profile=vulnerability_profile,
            llm_client=llm_client,
            target=target,
            verbose=args.verbose,
            stop_when_critical_complete=getattr(args, "stop_when_critical_complete", False),
            critical_stop_mode=getattr(args, "critical_stop_mode", "max"),
            critical_stop_max_priority=getattr(args, "critical_stop_max_priority", 2),
            profile_base_path=getattr(args, "profile_base_path", None),
            software_profile_dirname=getattr(args, "software_profile_dirname", None),
        )
        success_count += int(success)

    logger.info(
        f"Scan finished: {success_count}/{len(targets)} target scans succeeded"
    )
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
