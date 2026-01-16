#!/usr/bin/env python3
"""Wrapper for generating software profiles via the project CLI."""

import argparse
import subprocess
import sys
from pathlib import Path
from shutil import which


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the software profile generator CLI")
    parser.add_argument("--repo-name", required=True, help="Repository name under data/repos/")
    parser.add_argument("--llm-provider", default="deepseek", help="LLM provider (openai, deepseek, lab)")
    parser.add_argument("--llm-name", default="", help="Optional LLM model name override")
    parser.add_argument("--output-dir", default=None, help="Output directory for profiles")
    parser.add_argument("--repo-base-path", default=None, help="Base path that contains repos/")
    parser.add_argument("--target-version", default=None, help="Target commit hash/version")
    parser.add_argument("--enable-deep-analysis", action="store_true", help="Enable deep analysis")
    parser.add_argument("--force-full-analysis", action="store_true", help="Ignore cached checkpoints")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if which("software-profile"):
        cmd = [
            "software-profile",
            "--repo-name",
            args.repo_name,
            "--llm-provider",
            args.llm_provider,
        ]
    else:
        cmd = [
            sys.executable,
            "-m",
            "cli.software",
            "--repo-name",
            args.repo_name,
            "--llm-provider",
            args.llm_provider,
        ]
    if args.llm_name:
        cmd.extend(["--llm-name", args.llm_name])
    if args.output_dir:
        cmd.extend(["--output-dir", args.output_dir])
    if args.repo_base_path:
        cmd.extend(["--repo-base-path", args.repo_base_path])
    if args.target_version:
        cmd.extend(["--target-version", args.target_version])
    if args.enable_deep_analysis:
        cmd.append("--enable-deep-analysis")
    if args.force_full_analysis:
        cmd.append("--force-full-analysis")
    if args.verbose:
        cmd.append("--verbose")

    subprocess.run(cmd, check=True, cwd=Path(__file__).resolve().parents[4])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
