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

from config import _path_config
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
from utils.git_utils import checkout_commit, get_git_commit
from utils.language import detect_language as detect_repo_language
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanTarget:
    repo_name: str
    commit_hash: str
    similarity: Optional[SimilarProfileCandidate] = None


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
            "similar software profiles from repo-profiles."
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
        "--language",
        type=str,
        default=None,
        help=(
            "Target language (python, cpp, go, java, javascript, ruby, csharp, rust). "
            "Auto-detected from the target repository if not specified."
        ),
    )

    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider (deepseek, lab, openai, anthropic)",
    )
    parser.add_argument("--max-iterations", type=int, default=3, help="Maximum iterations")
    parser.add_argument("--output", type=str, default=None, help="Output base directory")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def resolve_output_dir(cve_id: str, target_repo: str, target_commit: str, output_base: Optional[str]) -> Path:
    folder_name = f"{cve_id}/{target_repo}-{target_commit[:12]}"
    if output_base:
        return Path(output_base) / folder_name
    return Path("scan-results") / folder_name


def _validate_args(args: argparse.Namespace) -> bool:
    if args.target_commit and not args.target_repo:
        logger.error("--target-commit requires --target-repo")
        return False
    if args.top_k <= 0:
        logger.error("--top-k must be >= 1")
        return False
    return True


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
        repo_path = _path_config["repo_base_path"] / repo_name
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
    ranked = rank_similar_profiles(
        source_ref=source_ref,
        candidate_refs=refs,
        top_k=args.top_k,
        text_retriever=text_retriever,
        exclude_same_repo=not args.include_same_repo,
    )
    if not ranked:
        logger.error("No similar profiles found for auto-target mode")
        return []

    logger.info(f"Selected top-{len(ranked)} similar targets:")
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
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False)

    conversation_path = output_dir / "conversation_history.json"
    with open(conversation_path, "w", encoding="utf-8") as handle:
        json.dump(make_serializable(finder.conversation_history), handle, indent=2, ensure_ascii=False)

    if target.similarity:
        similarity_path = output_dir / "target_similarity.json"
        with open(similarity_path, "w", encoding="utf-8") as handle:
            json.dump(target.similarity.to_dict(), handle, indent=2, ensure_ascii=False)

    logger.info(f"Results saved to: {output_path}")
    logger.info(f"Conversation history saved to: {conversation_path}")


def _run_single_target_scan(
    args: argparse.Namespace,
    vulnerability_profile,
    llm_client,
    target: ScanTarget,
) -> bool:
    target_repo_path = _path_config["repo_base_path"] / target.repo_name
    if not target_repo_path.exists():
        logger.error(f"Repository not found: {target_repo_path}")
        return False

    original_commit = get_git_commit(str(target_repo_path))
    changed_commit = False

    try:
        if original_commit and original_commit != target.commit_hash:
            logger.info(f"Checking out {target.repo_name} to {target.commit_hash[:12]}...")
            if not checkout_commit(str(target_repo_path), target.commit_hash):
                logger.error(f"Failed to checkout to {target.commit_hash}")
                return False
            changed_commit = True

        logger.info(f"Loading software profile: {target.repo_name}@{target.commit_hash[:12]}...")
        software_profile = load_software_profile(
            target.repo_name,
            target.commit_hash,
            base_dir=_path_config["repo_root"] / "repo-profiles",
        )
        if not software_profile:
            logger.error(
                f"Failed to load software profile for {target.repo_name}@{target.commit_hash[:12]}"
            )
            return False

        output_dir = resolve_output_dir(
            cve_id=args.cve,
            target_repo=target.repo_name,
            target_commit=target.commit_hash,
            output_base=args.output,
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        language = args.language or detect_repo_language(target_repo_path)
        codeql_database_name = f"{target.repo_name}-{target.commit_hash[:8]}-{language}"
        logger.info(f"Target language: {language}")
        logger.info(f"CodeQL database: {codeql_database_name}")

        finder = AgenticVulnFinder(
            llm_client=llm_client,
            repo_path=target_repo_path,
            software_profile=software_profile,
            vulnerability_profile=vulnerability_profile,
            max_iterations=args.max_iterations,
            verbose=args.verbose,
            output_dir=output_dir,
            codeql_database_name=codeql_database_name,
        )
        results = finder.run()
        _save_scan_outputs(output_dir, finder, results, target)

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
        if changed_commit and original_commit:
            logger.info(f"Restoring {target.repo_name} to original commit {original_commit[:12]}...")
            checkout_commit(str(target_repo_path), original_commit)


def main() -> int:
    args = parse_args()
    if not _validate_args(args):
        return 1

    logger.info(f"Loading vulnerability profile from {args.vuln_repo}@{args.cve}...")
    vulnerability_profile = load_vulnerability_profile(
        args.vuln_repo,
        args.cve,
        base_dir=_path_config["repo_root"] / "vuln-profiles",
    )
    if not vulnerability_profile:
        logger.error("Failed to load vulnerability profile")
        return 1

    repo_profiles_dir = _path_config["repo_root"] / "repo-profiles"
    if args.target_repo:
        targets = _resolve_manual_targets(args, vulnerability_profile, repo_profiles_dir)
    else:
        targets = _resolve_auto_targets(args, vulnerability_profile, repo_profiles_dir)

    if not targets:
        logger.error("No scan targets resolved")
        return 1

    llm_client = create_llm_client(LLMConfig(provider=args.llm_provider))
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
        success = _run_single_target_scan(
            args=args,
            vulnerability_profile=vulnerability_profile,
            llm_client=llm_client,
            target=target,
        )
        success_count += int(success)

    logger.info(
        f"Scan finished: {success_count}/{len(targets)} target scans succeeded"
    )
    return 0 if success_count > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
