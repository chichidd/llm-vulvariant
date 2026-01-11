"""软件画像生成 CLI 入口点"""

import sys
import logging
from pathlib import Path
import argparse

logger = logging.getLogger(__name__)

def setup_logging(verbose: bool = False):
    """配置日志输出"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        stream=sys.stderr
    )


def parse_args():
    parser = argparse.ArgumentParser(description='Generate software profile using LLM')
    parser.add_argument('--repo-name', required=True, help='Repository name under vuln/data/repos/')
    parser.add_argument('--llm-provider', default='deepseek', help='LLM provider name (e.g., openai, deepseek)')
    parser.add_argument('--llm-name', default=None, help='LLM model name (e.g., gpt-5.1, deepseek-chat). If not specified, use default model for the provider.')
    parser.add_argument('--output-dir', default=None, help='Output directory for profiles')
    parser.add_argument('--target-version', default=None, help='Target commit hash/version. Default is the current version.')
    parser.add_argument('--enable-deep-analysis', action='store_true', help='Enable deep analysis mode')
    parser.add_argument('--force-full-analysis', action='store_true', help='Force full analysis')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def main():
    """主入口函数"""

    from profiler import SoftwareProfiler
    from llm import LLMConfig, create_llm_client
    
    args = parse_args()
    setup_logging(args.verbose)
    
    # 构建仓库路径
    repo_path = str(Path.home() / "vuln/data/repos" / args.repo_name)
    logger.info(f"Repository path: {repo_path}")
    
    # 配置 LLM
    llm_config = LLMConfig(provider=args.llm_provider, model=args.llm_name)
    llm_config.enable_thinking = False
    logger.debug(f"LLM config: {llm_config}")
    
    # 创建客户端和 Profiler
    logger.info(f"Initializing LLM client ({args.llm_provider})...")
    llm_client = create_llm_client(llm_config)
    profiler = SoftwareProfiler(
        llm_client=llm_client, 
        output_dir=args.output_dir,
        enable_deep_analysis=args.enable_deep_analysis
    )
    
    # 生成画像
    logger.info("Generating software profile...")
    profile = profiler.generate_profile(
        repo_path=repo_path, 
        force_full_analysis=args.force_full_analysis, 
        target_version=args.target_version
    )
    
    print(f"✅ 软件画像已生成: {args.repo_name}@{args.target_version}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
