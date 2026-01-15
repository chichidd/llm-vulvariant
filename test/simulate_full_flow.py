#!/usr/bin/env python3
"""模拟完整的profile生成流程，使用已有的checkpoint数据"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from profiler.software.models import SoftwareProfile
from profiler.software.analyzer import SoftwareProfiler
from utils.logger import get_logger

logger = get_logger(__name__)

def simulate_profile_generation():
    """模拟profile生成"""
    
    checkpoint_dir = Path.home() / "vuln/llm-vulvariant/repo-profiles-ds/ms-swift/2c19674fe612d0b94fe671789d8a87a594838db0/checkpoints"
    
    logger.info("Loading checkpoint data...")
    with open(checkpoint_dir / "repo_info.json", 'r') as f:
        repo_info = json.load(f)
    
    with open(checkpoint_dir / "modules.json", 'r') as f:
        modules_data = json.load(f)
    
    with open(checkpoint_dir / "basic_info.json", 'r') as f:
        basic_info = json.load(f)
    
    # 模拟_generate_profile_full的逻辑
    modules_result = modules_data
    repo_name = "ms-swift"
    version = "2c19674fe612d0b94fe671789d8a87a594838db0"
    
    logger.info("Step 4: Building software profile...")
    profile = SoftwareProfile(
        name=repo_name,
        version=version,
        description=basic_info.get("description", ""),
        target_application=basic_info.get("target_application", []),
        target_user=basic_info.get("target_user", []),
        repo_info=repo_info,
        modules=modules_result.get('modules', []) if modules_result else [],
    )
    
    logger.info(f"Initial profile.modules: {len(profile.modules)}, type: {type(profile.modules[0]).__name__ if profile.modules else 'N/A'}")
    
    # 如果有深度分析，增强profile
    deep_analysis = repo_info.get('deep_analysis')
    if deep_analysis:
        logger.info("Enhancing profile with deep analysis...")
        
        profiler = SoftwareProfiler(llm_client=None, enable_deep_analysis=True)
        
        base_modules = modules_result.get('modules', []) if modules_result else []
        logger.info(f"Base modules: {len(base_modules)}, type: {type(base_modules[0]).__name__ if base_modules else 'N/A'}")
        
        modules = profiler._enhance_modules_with_deep_analysis(base_modules, deep_analysis)
        logger.info(f"Enhanced modules: {len(modules)}, type: {type(modules[0]).__name__ if modules else 'N/A'}")
        
        if modules:
            logger.info(f"First enhanced module:")
            logger.info(f"  name: {modules[0].name}")
            logger.info(f"  external_deps: {len(modules[0].external_dependencies)}")
            logger.info(f"  called_by: {len(modules[0].called_by_modules)}")
            logger.info(f"  calls: {len(modules[0].calls_modules)}")
        
        profile.modules = modules
        logger.info(f"After assignment - profile.modules: {len(profile.modules)}, type: {type(profile.modules[0]).__name__ if profile.modules else 'N/A'}")
    
    # 转换为dict并保存
    logger.info("\nConverting to dict...")
    profile_dict = profile.to_dict()
    
    logger.info(f"Profile dict modules: {len(profile_dict.get('modules', []))}")
    if profile_dict.get('modules'):
        first_module = profile_dict['modules'][0]
        logger.info(f"First module in dict:")
        logger.info(f"  type: {type(first_module).__name__}")
        logger.info(f"  keys: {list(first_module.keys()) if isinstance(first_module, dict) else 'NOT A DICT'}")
        if isinstance(first_module, dict):
            logger.info(f"  external_dependencies: {first_module.get('external_dependencies', 'MISSING')[:5] if first_module.get('external_dependencies') else 'EMPTY'}")
            logger.info(f"  called_by_modules: {first_module.get('called_by_modules', 'MISSING')}")
            logger.info(f"  calls_modules: {first_module.get('calls_modules', 'MISSING')}")
    
    # JSON序列化
    logger.info("\nSerializing to JSON...")
    json_str = profile.to_json()
    
    # 反序列化检查
    logger.info("Deserializing JSON...")
    loaded_dict = json.loads(json_str)
    
    if loaded_dict.get('modules'):
        first_module = loaded_dict['modules'][0]
        logger.info(f"First module after JSON round-trip:")
        logger.info(f"  external_dependencies: {first_module.get('external_dependencies', 'MISSING')[:5] if first_module.get('external_dependencies') else 'EMPTY'}")
        logger.info(f"  called_by_modules: {first_module.get('called_by_modules', 'MISSING')}")
        logger.info(f"  calls_modules: {first_module.get('calls_modules', 'MISSING')}")
        
        # 检查是否为空
        if not first_module.get('external_dependencies'):
            logger.error("❌ external_dependencies is EMPTY!")
        else:
            logger.info(f"✅ external_dependencies has {len(first_module['external_dependencies'])} items")
        
        if not first_module.get('called_by_modules'):
            logger.error("❌ called_by_modules is EMPTY!")  
        else:
            logger.info(f"✅ called_by_modules has {len(first_module['called_by_modules'])} items")
    
    # 保存到测试文件
    test_file = Path("/tmp/test_profile.json")
    logger.info(f"\nSaving to {test_file}...")
    with open(test_file, 'w') as f:
        f.write(json_str)
    logger.info(f"✅ Saved successfully")

if __name__ == "__main__":
    simulate_profile_generation()
