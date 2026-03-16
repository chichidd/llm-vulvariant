"""CLI entrypoint for generating a software profile."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    _path_config,
)

try:
    from cli.common import resolve_cli_path, resolve_path_override, resolve_profile_dirs, setup_logging
    from cli.profile_generation import create_profile_llm_client, run_software_profile_generation
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import resolve_cli_path, resolve_path_override, resolve_profile_dirs, setup_logging
    from profile_generation import create_profile_llm_client, run_software_profile_generation

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for software profile generation.

    Returns:
        Parsed CLI arguments.
    """
    parser = argparse.ArgumentParser(description='Generate software profile using LLM')
    parser.add_argument('--repo-name', required=True, help='Repository name under repo base path (config/paths.yaml)')
    parser.add_argument('--llm-provider', default='deepseek', help='LLM provider name (e.g., openai, deepseek)')
    parser.add_argument('--llm-name', default=None, help='LLM model name (e.g., gpt-5.1, deepseek-chat). If not specified, use default model for the provider.')
    parser.add_argument(
        '--profile-base-path',
        default=str(_path_config["profile_base_path"]),
        help='Base directory containing profile folders (default from config/paths.yaml)'
    )
    parser.add_argument(
        '--software-profile-dirname',
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help='Software profile directory name under --profile-base-path (default: soft)'
    )
    parser.add_argument(
        '--output-dir',
        default=None,
        help='Output directory for profiles (overrides --profile-base-path/--software-profile-dirname)'
    )
    parser.add_argument('--repo-base-path', default=None, help='Base path containing repos (default from config/paths.yaml)')
    parser.add_argument('--target-version', default=None, help='Target commit hash/version. Default is the current version.')
    parser.add_argument('--force-regenerate', action='store_true', help='Ignore existing software profile/checkpoints and rebuild from scratch')

    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()


def main() -> int:
    """Generate a software profile for the requested repository."""

    args = parse_args()
    setup_logging(args.verbose)

    # Resolve repository and output directories before initializing the LLM.
    repo_base_path = (
        resolve_cli_path(args.repo_base_path, base_dir=_path_config["repo_root"])
        if args.repo_base_path
        else _path_config["repo_base_path"]
    )
    repo_path = str(repo_base_path / args.repo_name)
    logger.info(f"Repository path: {repo_path}")

    default_software_profile_dir, _ = resolve_profile_dirs(
        profile_base_path=args.profile_base_path,
        software_profile_dirname=args.software_profile_dirname,
        vuln_profile_dirname=None,
    )
    output_dir = resolve_path_override(
        args.output_dir,
        default_software_profile_dir,
        base_dir=_path_config["repo_root"],
    )
    logger.info(f"Software profile output dir: {output_dir}")

    logger.info(f"Initializing LLM client ({args.llm_provider})...")
    llm_client = create_profile_llm_client(args.llm_provider, args.llm_name)

    logger.info("Generating software profile...")
    run_software_profile_generation(
        repo_path=Path(repo_path),
        output_dir=output_dir,
        llm_client=llm_client,
        force_regenerate=args.force_regenerate,
        target_version=args.target_version,
    )

    print(f"✅ Software profile generated: {args.repo_name}@{args.target_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
