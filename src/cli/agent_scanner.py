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
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    DEFAULT_VULN_PROFILE_DIRNAME,
    _path_config,
)
from llm import LLMConfig, create_llm_client
from scanner.agent import AgenticVulnFinder, load_software_profile, load_vulnerability_profile
from scanner.agent.utils import make_serializable
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
try:
    from cli.common import resolve_cli_path, resolve_profile_dirs, setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import resolve_cli_path, resolve_profile_dirs, setup_logging

logger = get_logger(__name__)


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
    codeql_languages: List[str] = []

    configured_codeql_languages = repo_analysis.get("codeql_languages", [])
    if isinstance(configured_codeql_languages, list):
        codeql_languages = _dedupe_languages(configured_codeql_languages)

    active_languages = codeql_languages or _dedupe_languages(scan_languages)
    return {
        lang: f"{target.repo_name}-{target.commit_hash[:8]}-{lang}"
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
        default="BAAI--bge-large-en-v1.5",
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
        help="LLM provider (deepseek, openai)",
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
        default="min",
        help=(
            "When --stop-when-critical-complete is enabled: "
            "min => stop at min(max-iterations, X); "
            "max => stop at max(max-iterations, X). Default: min"
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
) -> None:
    output_path = output_dir / "agentic_vuln_findings.json"
    write_atomic_text(
        output_path,
        json.dumps(results, indent=2, ensure_ascii=False),
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
    critical_stop_mode: str = "min",
    profile_base_path: Optional[str] = None,
    software_profile_dirname: Optional[str] = None,
) -> bool:
    """Run one target scan through a stable public interface used by both CLIs."""
    resolved_repo_base_path = Path(repo_base_path).expanduser()
    if not resolved_repo_base_path.is_absolute():
        resolved_repo_base_path = _path_config["repo_root"] / resolved_repo_base_path
    target_repo_path = resolved_repo_base_path / target.repo_name
    if not target_repo_path.exists():
        logger.error(f"Repository not found: {target_repo_path}")
        return False

    original_commit = get_git_commit(str(target_repo_path))
    original_restore_target = get_git_restore_target(str(target_repo_path))
    changed_commit = False

    try:
        if original_commit and original_commit != target.commit_hash:
            if has_uncommitted_changes(str(target_repo_path)):
                logger.error(
                    "Repository has local changes, refuse commit switch for %s. "
                    "Please clean/stash and retry.",
                    target.repo_name,
                )
                return False
            logger.info(f"Checking out {target.repo_name} to {target.commit_hash[:12]}...")
            if not checkout_commit(str(target_repo_path), target.commit_hash):
                logger.error(f"Failed to checkout to {target.commit_hash}")
                return False
            changed_commit = True

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
            return False

        target_output_dir = resolve_output_dir(
            cve_id=cve_id,
            target_repo=target.repo_name,
            target_commit=target.commit_hash,
            output_base=output_base,
        )
        target_output_dir.mkdir(parents=True, exist_ok=True)

        scan_languages = _resolve_scan_languages(target_repo_path, software_profile)
        codeql_database_names = _resolve_codeql_database_names(target, scan_languages, software_profile)

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

        finder = AgenticVulnFinder(
            llm_client=llm_client,
            repo_path=target_repo_path,
            software_profile=software_profile,
            vulnerability_profile=vulnerability_profile,
            max_iterations=max_iterations,
            stop_when_critical_complete=stop_when_critical_complete,
            critical_stop_mode=critical_stop_mode,
            verbose=verbose,
            output_dir=target_output_dir,
            languages=scan_languages,
            codeql_database_names=codeql_database_names,
        )
        results = finder.run()
        _save_scan_outputs(target_output_dir, finder, results, target)

        vulnerabilities = results.get("vulnerabilities", []) if isinstance(results, dict) else []
        logger.info(
            f"Target {target.repo_name}@{target.commit_hash[:12]} finished: "
            f"{len(vulnerabilities)} potential vulnerabilities"
        )
        return True
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Scan failed for {target.repo_name}@{target.commit_hash[:12]}: {exc}")
        return False
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
            critical_stop_mode=getattr(args, "critical_stop_mode", "min"),
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
