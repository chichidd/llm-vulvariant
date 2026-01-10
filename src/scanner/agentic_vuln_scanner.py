#!/usr/bin/env python3
"""CLI wrapper for the agentic vulnerability finder."""

import argparse
import json
import os
from pathlib import Path

from config import _path_config
from llm import LLMConfig, create_llm_client
from utils.git_utils import checkout_commit, get_git_commit
from utils.logger import get_logger

from scanner.agent import AgenticVulnFinder, load_software_profile, load_vulnerability_profile
from scanner.agent.utils import make_serializable

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Finder")
    parser.add_argument("--repo", type=str, required=True, help="Repository name (e.g., NeMo)")
    parser.add_argument("--vuln-commit", type=str, required=True, help="Commit hash where vulnerability profile was generated")
    parser.add_argument("--target-commit", type=str, default=None, help="Commit hash to scan (defaults to vuln-commit)")
    parser.add_argument("--cve", type=str, required=True, help="CVE or vulnerability ID")
    parser.add_argument("--provider", type=str, default="deepseek", help="LLM provider (deepseek, lab, openai, anthropic)")
    parser.add_argument("--max-iterations", type=int, default=30, help="Maximum iterations")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def resolve_output_dir(args, vuln_commit: str, target_commit: str) -> Path:
    if args.output:
        return Path(args.output).parent
    if vuln_commit != target_commit:
        return Path(f"scan-results/{args.repo}_{target_commit}_{args.cve}_from_{vuln_commit[:12]}")
    return Path(f"scan-results/{args.repo}_{vuln_commit}_{args.cve}")


def main() -> None:
    args = parse_args()
    target_commit = args.target_commit or args.vuln_commit

    os.chdir(_path_config["project_root"] / "llm-vulvariant")

    logger.info(f"Loading vulnerability profile from {args.repo}@{args.vuln_commit[:8]}...")
    vulnerability_profile = load_vulnerability_profile(args.repo, args.vuln_commit, args.cve)
    if not vulnerability_profile:
        logger.error("Failed to load vulnerability profile")
        return

    repo_path = _path_config["repo_base_path"] / args.repo
    if not repo_path.exists():
        logger.error(f"Repository not found: {repo_path}")
        return

    if args.vuln_commit != target_commit:
        current = get_git_commit(str(repo_path))
        if current != target_commit:
            logger.info(f"Checking out repository to target commit {target_commit[:8]}...")
            if not checkout_commit(str(repo_path), target_commit):
                logger.error(f"Failed to checkout to {target_commit}")
                return
        logger.info(f"Will scan target commit: {target_commit[:8]} (different from vuln commit)")

    logger.info(f"Loading software profile from target commit {args.repo}@{target_commit[:8]}...")
    software_profile = load_software_profile(args.repo, target_commit)
    if not software_profile:
        logger.error(f"Failed to load software profile for target commit {target_commit}")
        logger.info(
            f"You may need to generate it first using: python generate-software-profile-llama-index.py --repo {args.repo} --commit {target_commit}"
        )
        return

    llm_client = create_llm_client(LLMConfig(provider=args.provider))
    logger.info(f"Using LLM provider: {args.provider}")

    output_dir = resolve_output_dir(args, args.vuln_commit, target_commit)
    output_dir.mkdir(parents=True, exist_ok=True)

    finder = AgenticVulnFinder(
        llm_client=llm_client,
        repo_path=repo_path,
        software_profile=software_profile,
        vulnerability_profile=vulnerability_profile,
        max_iterations=args.max_iterations,
        verbose=args.verbose,
        output_dir=output_dir,
    )

    results = finder.run()

    output_path = output_dir / "agentic_vuln_findings.json"
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False)

    conversation_path = output_dir / "conversation_history.json"
    with open(conversation_path, "w", encoding="utf-8") as handle:
        json.dump(make_serializable(finder.conversation_history), handle, indent=2, ensure_ascii=False)

    logger.info(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")
    logger.info(f"Results saved to: {output_path}")
    logger.info(f"Conversation history saved to: {conversation_path}")

    if results["vulnerabilities"]:
        logger.info("\n=== Vulnerability Summary ===")
        for vuln in results["vulnerabilities"]:
            logger.info(f"\n- {vuln.get('file_path', 'unknown')}")
            logger.info(f"  Type: {vuln.get('vulnerability_type', 'unknown')}")
            logger.info(f"  Confidence: {vuln.get('confidence', 'unknown')}")
            desc = vuln.get("description", "")
            logger.info(f"  Description: {desc[:100]}..." if len(desc) > 100 else f"  Description: {desc}")


if __name__ == "__main__":
    main()
