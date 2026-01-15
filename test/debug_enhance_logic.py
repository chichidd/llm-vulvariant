#!/usr/bin/env python3
"""直接测试_enhance_modules_with_deep_analysis逻辑"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from profiler.software.analyzer import SoftwareProfiler
from utils.logger import get_logger

logger = get_logger(__name__)

def test_enhance_logic():
    """测试enhance逻辑"""
    
    # 加载checkpoint数据
    checkpoint_dir = Path.home() / "vuln/llm-vulvariant/repo-profiles-ds/ms-swift/2c19674fe612d0b94fe671789d8a87a594838db0/checkpoints"
    
    logger.info("Loading checkpoint data...")
    with open(checkpoint_dir / "repo_info.json", 'r') as f:
        repo_info = json.load(f)
    
    with open(checkpoint_dir / "modules.json", 'r') as f:
        modules_data = json.load(f)
    
    deep_analysis = repo_info.get('deep_analysis', {})
    base_modules = modules_data.get('modules', [])
    
    logger.info(f"Base modules count: {len(base_modules)}")
    logger.info(f"Dependencies count: {len(deep_analysis.get('dependencies', []))}")
    logger.info(f"Call graph edges count: {len(deep_analysis.get('call_graph_edges', []))}")
    
    # 检查dependencies是否有import_files
    deps = deep_analysis.get('dependencies', [])
    if deps:
        has_import_files = 'import_files' in deps[0]
        logger.info(f"Dependencies have import_files: {has_import_files}")
        if not has_import_files:
            logger.warning("⚠️ Dependencies missing import_files! This will cause issues.")
    
    # 创建profiler实例并调用enhance方法
    profiler = SoftwareProfiler(llm_client=None, enable_deep_analysis=True)
    
    logger.info("\nCalling _enhance_modules_with_deep_analysis...")
    enhanced_modules = profiler._enhance_modules_with_deep_analysis(base_modules, deep_analysis)
    
    logger.info(f"\nEnhanced modules count: {len(enhanced_modules)}")
    
    # 检查结果
    for idx, module in enumerate(enhanced_modules):
        logger.info(f"\nModule {idx+1}: {module.name}")
        logger.info(f"  Files: {len(module.files)}")
        logger.info(f"  External deps: {len(module.external_dependencies)}")
        logger.info(f"  Internal deps: {len(module.internal_dependencies)}")
        logger.info(f"  Called by: {len(module.called_by_modules)}")
        logger.info(f"  Calls: {len(module.calls_modules)}")
        
        if module.external_dependencies:
            logger.info(f"    Sample external deps: {module.external_dependencies[:5]}")
        if module.called_by_modules:
            logger.info(f"    Called by: {module.called_by_modules}")
        if module.calls_modules:
            logger.info(f"    Calls: {module.calls_modules}")
    
    # 统计
    empty_count = sum(1 for m in enhanced_modules 
                     if not m.external_dependencies and not m.internal_dependencies 
                     and not m.called_by_modules and not m.calls_modules)
    
    logger.info(f"\n{'='*80}")
    logger.info(f"Summary:")
    logger.info(f"  Total modules: {len(enhanced_modules)}")
    logger.info(f"  Modules with NO enhanced data: {empty_count}")
    logger.info(f"  Modules with enhanced data: {len(enhanced_modules) - empty_count}")

if __name__ == "__main__":
    test_enhance_logic()
