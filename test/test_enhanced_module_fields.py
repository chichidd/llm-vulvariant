#!/usr/bin/env python3
"""测试enhanced module fields是否正确填充

这个测试脚本用于验证修复后的代码是否正确提取和填充：
- external_dependencies: 外部依赖
- internal_dependencies: 内部依赖  
- called_by_modules: 被哪些模块调用
- calls_modules: 调用哪些模块
"""

import json
import sys
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from profiler import SoftwareProfile
from utils.logger import get_logger

logger = get_logger(__name__)


def test_existing_profile(profile_path: str):
    """测试已存在的profile是否包含enhanced字段"""
    logger.info(f"Loading profile from: {profile_path}")
    
    with open(profile_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    profile = SoftwareProfile.from_dict(data)
    
    logger.info(f"Profile: {profile.name}@{profile.version[:8] if profile.version else 'N/A'}")
    logger.info(f"Total modules: {len(profile.modules)}")
    
    # 检查每个模块的enhanced字段
    empty_enhanced_count = 0
    total_enhanced_count = 0
    
    for module in profile.modules:
        has_external_deps = len(module.external_dependencies) > 0
        has_internal_deps = len(module.internal_dependencies) > 0
        has_called_by = len(module.called_by_modules) > 0
        has_calls = len(module.calls_modules) > 0
        
        if has_external_deps or has_internal_deps or has_called_by or has_calls:
            total_enhanced_count += 1
        else:
            empty_enhanced_count += 1
            logger.debug(f"Module '{module.name}' has empty enhanced fields")
    
    logger.info(f"Modules with enhanced data: {total_enhanced_count}")
    logger.info(f"Modules without enhanced data: {empty_enhanced_count}")
    
    # 显示几个有数据的模块作为示例
    if total_enhanced_count > 0:
        logger.info("\nSample modules with enhanced data:")
        count = 0
        for module in profile.modules:
            if len(module.external_dependencies) > 0 or len(module.called_by_modules) > 0:
                logger.info(f"\n  Module: {module.name}")
                if module.external_dependencies:
                    logger.info(f"    External deps: {module.external_dependencies[:5]}")
                if module.internal_dependencies:
                    logger.info(f"    Internal deps: {module.internal_dependencies[:5]}")
                if module.called_by_modules:
                    logger.info(f"    Called by: {module.called_by_modules}")
                if module.calls_modules:
                    logger.info(f"    Calls: {module.calls_modules}")
                count += 1
                if count >= 3:
                    break
    
    return empty_enhanced_count == 0


def test_checkpoint_data(checkpoint_dir: str):
    """测试checkpoint中的数据结构"""
    checkpoint_path = Path(checkpoint_dir)
    
    # 读取repo_info.json中的deep_analysis
    repo_info_path = checkpoint_path / "repo_info.json"
    if repo_info_path.exists():
        logger.info(f"\nChecking checkpoint data in: {checkpoint_dir}")
        with open(repo_info_path, 'r', encoding='utf-8') as f:
            repo_info = json.load(f)
        
        deep_analysis = repo_info.get('deep_analysis', {})
        dependencies = deep_analysis.get('dependencies', [])
        call_graph_edges = deep_analysis.get('call_graph_edges', [])
        
        logger.info(f"Dependencies count: {len(dependencies)}")
        logger.info(f"Call graph edges count: {len(call_graph_edges)}")
        
        # 检查dependencies是否包含import_files字段
        if dependencies:
            sample_dep = dependencies[0]
            logger.info(f"\nSample dependency structure:")
            logger.info(f"  {json.dumps(sample_dep, indent=2)}")
            
            has_import_files = 'import_files' in sample_dep
            logger.info(f"\nDependencies have 'import_files' field: {has_import_files}")
            
            if not has_import_files:
                logger.warning("⚠️  Dependencies missing 'import_files' field!")
                logger.warning("This means deep_analyzer.py needs to be updated to include import location information")
        
        # 检查call_graph_edges结构
        if call_graph_edges:
            sample_edge = call_graph_edges[0]
            logger.info(f"\nSample call graph edge structure:")
            logger.info(f"  {json.dumps(sample_edge, indent=2)}")


def main():
    """主测试函数"""
    # 测试ms-swift profile
    ms_swift_profile = Path.home() / "vuln/llm-vulvariant/repo-profiles-ds/ms-swift/2c19674fe612d0b94fe671789d8a87a594838db0/software_profile.json"
    
    if ms_swift_profile.exists():
        logger.info("="*80)
        logger.info("Testing ms-swift profile")
        logger.info("="*80)
        result1 = test_existing_profile(str(ms_swift_profile))
        
        # 测试checkpoint数据
        checkpoint_dir = ms_swift_profile.parent / "checkpoints"
        if checkpoint_dir.exists():
            test_checkpoint_data(str(checkpoint_dir))
    else:
        logger.error(f"Profile not found: {ms_swift_profile}")
        result1 = False
    
    # 测试LLaMA-Factory profile
    llama_factory_profile = Path.home() / "vuln/llm-vulvariant/repo-profiles-ds/LLaMA-Factory/9f73a6eb234fe3df67d9d921c157fde4a0faca6a/software_profile.json"
    
    if llama_factory_profile.exists():
        logger.info("\n" + "="*80)
        logger.info("Testing LLaMA-Factory profile")
        logger.info("="*80)
        result2 = test_existing_profile(str(llama_factory_profile))
    else:
        logger.warning(f"Profile not found: {llama_factory_profile}")
        result2 = None
    
    # 总结
    logger.info("\n" + "="*80)
    logger.info("TEST SUMMARY")
    logger.info("="*80)
    if result1:
        logger.info("✅ All modules have enhanced fields")
    else:
        logger.warning("⚠️  Some modules are missing enhanced fields")
        logger.info("\nTo fix this, you need to regenerate the profiles using:")
        logger.info("  software-profile --repo-name ms-swift --enable-deep-analysis --force-full-analysis")
    
    return 0 if result1 else 1


if __name__ == "__main__":
    sys.exit(main())
