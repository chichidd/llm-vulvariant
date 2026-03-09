"""CLI entrypoint for generating a software profile."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    _path_config,
    resolve_software_profiles_path,
)

try:
    from cli.common import setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import setup_logging

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

    from profiler import SoftwareProfiler
    from llm import LLMConfig, create_llm_client

    args = parse_args()
    setup_logging(args.verbose)

    # Resolve repository and output directories before initializing the LLM.
    repo_base_path = (
        Path(args.repo_base_path).expanduser()
        if args.repo_base_path
        else _path_config["repo_base_path"]
    )
    repo_path = str(repo_base_path / args.repo_name)
    logger.info(f"Repository path: {repo_path}")

    output_dir = (
        Path(args.output_dir).expanduser()
        if args.output_dir
        else resolve_software_profiles_path(
            profile_base_path=args.profile_base_path,
            software_profile_dirname=args.software_profile_dirname,
        )
    )
    logger.info(f"Software profile output dir: {output_dir}")

    # Provider/model provenance is important because profile quality and retry
    # behaviour differ between models during long-running jobs.
    llm_config = LLMConfig(provider=args.llm_provider, model=args.llm_name)
    llm_config.enable_thinking = True
    logger.debug(f"LLM config: {llm_config}")

    logger.info(f"Initializing LLM client ({args.llm_provider})...")
    llm_client = create_llm_client(llm_config)
    profiler = SoftwareProfiler(
        llm_client=llm_client,
        output_dir=str(output_dir),
    )

    logger.info("Generating software profile...")
    profiler.generate_profile(
        repo_path=repo_path,
        force_regenerate=args.force_regenerate,
        target_version=args.target_version,
    )

    print(f"✅ Software profile generated: {args.repo_name}@{args.target_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
