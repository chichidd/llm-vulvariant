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
from config import _path_config

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Finder")
    parser.add_argument("--vuln-repo", type=str, required=True, help="Repository name where vulnerability profile was generated")
    parser.add_argument("--cve", type=str, required=True, help="CVE or vulnerability ID")

    parser.add_argument("--target-repo", type=str, required=True, help="Repository name (e.g., NeMo)")
    parser.add_argument("--target-commit", type=str, default=None, help="Commit hash to scan (defaults to vuln-commit)")
    
    
    parser.add_argument("--llm-provider", type=str, default="deepseek", help="LLM provider (deepseek, lab, openai, anthropic)")
    parser.add_argument("--max-iterations", type=int, default=3, help="Maximum iterations")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def resolve_output_dir(args, ) -> Path:
    folder_name = f"{args.cve}/{args.target_repo}-{args.target_commit[:12]}"
    if args.output:
        return Path(args.output) / folder_name
    return Path(f"scan-results") / folder_name


def main() -> None:
    args = parse_args()

    logger.info(f"Loading vulnerability profile from {args.vuln_repo}@{args.cve}...")
    vulnerability_profile = load_vulnerability_profile(args.vuln_repo, args.cve, base_dir=_path_config['repo_root'] / 'vuln-profiles')
    if not vulnerability_profile:
        logger.error("Failed to load vulnerability profile")
        return

    target_repo_path = _path_config["repo_base_path"] / args.target_repo
    if not target_repo_path.exists():
        logger.error(f"Repository not found: {target_repo_path}")
        return

    changed_commit = False
    current = get_git_commit(str(target_repo_path))
    if args.target_commit and current != args.target_commit:
        logger.info(f"Checking out repository to target commit {args.target_commit[:12]}...")
        if not checkout_commit(str(target_repo_path), args.target_commit):
            logger.error(f"Failed to checkout to {args.target_commit}")
            return
        changed_commit = True
    logger.info(f"Will scan target commit: {args.target_commit[:12]} (different from current commit)")

    logger.info(f"Loading software profile from target commit {args.target_repo}@{args.target_commit[:12]}...")
    software_profile = load_software_profile(args.target_repo, args.target_commit, base_dir=_path_config['repo_root'] / 'repo-profiles')
    if not software_profile:
        logger.error(f"Failed to load software profile for target commit {args.target_commit[:12]}")
        return

    llm_client = create_llm_client(LLMConfig(provider=args.llm_provider))
    logger.info(f"Using LLM provider: {args.llm_provider}")

    output_dir = resolve_output_dir(args)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Compute CodeQL database name based on repo and commit
    # Format: {repo_name}-{commit_hash_short}-python
    commit_short = args.target_commit[:8] if args.target_commit else "unknown"
    codeql_database_name = f"{args.target_repo}-{commit_short}-python"
    logger.info(f"Using CodeQL database: {codeql_database_name}")

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

    if changed_commit:
        logger.info(f"Restoring repository {args.target_repo} to original commit {current[:12]}...")
        checkout_commit(str(target_repo_path), current)

if __name__ == "__main__":
    main()
