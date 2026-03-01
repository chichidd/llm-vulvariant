"""CLI entrypoint for generating a software profile."""

import sys
import logging
from pathlib import Path
import argparse

try:
    from cli.common import setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import setup_logging

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description='Generate software profile using LLM')
    parser.add_argument('--repo-name', required=True, help='Repository name under repo base path (config/paths.yaml)')
    parser.add_argument('--llm-provider', default='deepseek', help='LLM provider name (e.g., openai, deepseek)')
    parser.add_argument('--llm-name', default=None, help='LLM model name (e.g., gpt-5.1, deepseek-chat). If not specified, use default model for the provider.')
    parser.add_argument('--output-dir', default=None, help='Output directory for profiles')
    parser.add_argument('--repo-base-path', default=None, help='Base path containing repos (default from config/paths.yaml)')
    parser.add_argument('--target-version', default=None, help='Target commit hash/version. Default is the current version.')

    parser.add_argument('--force-full-analysis', action='store_true', help='Force full analysis')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def main():
    """Main entrypoint."""

    from profiler import SoftwareProfiler
    from llm import LLMConfig, create_llm_client
    
    args = parse_args()
    setup_logging(args.verbose)
    
    # Build the repository path
    from config import load_paths_config
    path_config = load_paths_config()
    repo_base_path = Path(args.repo_base_path).expanduser() if args.repo_base_path else path_config["repo_base_path"]
    repo_path = str(repo_base_path / args.repo_name)
    logger.info(f"Repository path: {repo_path}")
    
    # Configure the LLM
    llm_config = LLMConfig(provider=args.llm_provider, model=args.llm_name)
    llm_config.enable_thinking = True
    logger.debug(f"LLM config: {llm_config}")
    
    # Create the client and profiler
    logger.info(f"Initializing LLM client ({args.llm_provider})...")
    llm_client = create_llm_client(llm_config)
    profiler = SoftwareProfiler(
        llm_client=llm_client, 
        output_dir=args.output_dir,
    )
    
    # Generate the profile
    logger.info("Generating software profile...")
    profile = profiler.generate_profile(
        repo_path=repo_path, 
        force_full_analysis=args.force_full_analysis, 
        target_version=args.target_version
    )
    
    print(f"✅ Software profile generated: {args.repo_name}@{args.target_version}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
