#!/usr/bin/env python3
"""Unified LLM-powered CodeQL scanner."""

import argparse
import json
from pathlib import Path

from config import _path_config
from llm import LLMConfig, create_llm_client
from utils.logger import get_logger

from scanner.codeql.exploitability import (
    save_exploitability_results,
    verify_exploitability_for_results,
)
from scanner.codeql.scan_runner import run_codeql_scan

logger = get_logger(__name__)


def load_similarity_results(repo_name: str, vuln_commit: str, cve_id: str, scan_llm: str) -> dict:
    save_dir = Path(f"scan-results/{repo_name}_{vuln_commit}_{cve_id}/")
    file_path = save_dir / f"{scan_llm}_find_similar_modules.json"
    if not file_path.exists():
        raise FileNotFoundError(f"Similarity results not found: {file_path}")
    return json.loads(file_path.read_text(encoding="utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLM-powered CodeQL scanner")
    parser.add_argument("--repo", required=True, help="Repository name (e.g., NeMo)")
    parser.add_argument("--vuln-commit", required=True, help="Commit hash with the known vulnerability")
    parser.add_argument("--target-commit", default=None, help="Commit hash to scan (defaults to vuln-commit)")
    parser.add_argument("--cve", required=True, help="CVE or vulnerability ID")
    parser.add_argument("--scan-llm", default="deepseek", help="LLM used for similarity scan outputs")
    parser.add_argument("--codeql-provider", default="deepseek", help="LLM provider for CodeQL generation")
    parser.add_argument(
        "--verify-exploitability",
        action="store_true",
        help="Run LLM-based exploitability verification after CodeQL",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target_commit = args.target_commit or args.vuln_commit

    logger.info("Loading similarity results...")
    similarity_results = load_similarity_results(args.repo, args.vuln_commit, args.cve, args.scan_llm)
    vulnerability_profile = similarity_results.get("vulnerability_profile", {})
    candidates = similarity_results.get("candidates", [])

    llm_client = create_llm_client(LLMConfig(provider=args.codeql_provider))

    results = run_codeql_scan(
        repo_name=args.repo,
        vuln_commit=args.vuln_commit,
        target_commit=target_commit,
        cve_id=args.cve,
        scan_llm=args.scan_llm,
        codeql_llm_provider=args.codeql_provider,
        vulnerability_profile=vulnerability_profile,
        candidates=candidates,
        llm_client=llm_client,
    )

    if not args.verify_exploitability:
        logger.info("Scan complete (exploitability verification skipped)")
        return

    output_dir = (
        Path(f"scan-results/{args.repo}_{target_commit}_{args.cve}_from_{args.vuln_commit[:12]}/")
        if args.vuln_commit != target_commit
        else Path(f"scan-results/{args.repo}_{args.vuln_commit}_{args.cve}")
    )
    exploitability_results = verify_exploitability_for_results(
        results,
        repo_name=args.repo,
        commit=target_commit,
        llm_provider=args.codeql_provider,
        project_root=_path_config["repo_base_path"],
    )
    output_file = save_exploitability_results(
        exploitability_results, output_dir, args.codeql_provider
    )
    logger.info(f"Exploitability verification complete: {output_file}")


if __name__ == "__main__":
    main()
