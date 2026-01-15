#!/usr/bin/env python3
"""测试to_dict序列化"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from profiler.software.models import ModuleInfo, SoftwareProfile
from utils.logger import get_logger

logger = get_logger(__name__)

def test_to_dict():
    """测试ModuleInfo和SoftwareProfile的to_dict"""
    
    # 创建一个ModuleInfo对象
    module = ModuleInfo(
        name="Test Module",
        description="Test description",
        files=["file1.py", "file2.py"],
        external_dependencies=["numpy", "pandas"],
        internal_dependencies=["core_module"],
        called_by_modules=["module_a"],
        calls_modules=["module_b", "module_c"]
    )
    
    logger.info("Created ModuleInfo:")
    logger.info(f"  external_dependencies: {module.external_dependencies}")
    logger.info(f"  called_by_modules: {module.called_by_modules}")
    logger.info(f"  calls_modules: {module.calls_modules}")
    
    # 转换为dict
    module_dict = module.to_dict()
    logger.info("\nModule to_dict():")
    logger.info(f"  external_dependencies: {module_dict.get('external_dependencies')}")
    logger.info(f"  called_by_modules: {module_dict.get('called_by_modules')}")
    logger.info(f"  calls_modules: {module_dict.get('calls_modules')}")
    
    # 创建SoftwareProfile
    profile = SoftwareProfile(
        name="Test Repo",
        version="abc123",
        modules=[module]
    )
    
    logger.info("\nCreated SoftwareProfile with 1 module")
    
    # 转换为dict
    profile_dict = profile.to_dict()
    
    logger.info("\nProfile to_dict():")
    logger.info(f"  modules type: {type(profile_dict.get('modules'))}")
    logger.info(f"  modules count: {len(profile_dict.get('modules', []))}")
    
    if profile_dict.get('modules'):
        first_module = profile_dict['modules'][0]
        logger.info(f"\n  First module type: {type(first_module)}")
        if isinstance(first_module, dict):
            logger.info(f"  First module keys: {list(first_module.keys())}")
            logger.info(f"  external_dependencies: {first_module.get('external_dependencies')}")
            logger.info(f"  called_by_modules: {first_module.get('called_by_modules')}")
            logger.info(f"  calls_modules: {first_module.get('calls_modules')}")
        else:
            logger.error(f"  ❌ First module is not a dict! It's {type(first_module)}")
    
    # 测试JSON序列化
    logger.info("\nTesting JSON serialization...")
    try:
        json_str = json.dumps(profile_dict, indent=2)
        logger.info("✅ JSON serialization successful")
        
        # 反序列化并检查
        loaded_dict = json.loads(json_str)
        if loaded_dict.get('modules'):
            first_module = loaded_dict['modules'][0]
            logger.info(f"\nAfter JSON round-trip:")
            logger.info(f"  external_dependencies: {first_module.get('external_dependencies')}")
            logger.info(f"  called_by_modules: {first_module.get('called_by_modules')}")
            logger.info(f"  calls_modules: {first_module.get('calls_modules')}")
            
            # 检查是否为空
            if not first_module.get('external_dependencies'):
                logger.error("❌ external_dependencies is empty after serialization!")
            if not first_module.get('called_by_modules'):
                logger.error("❌ called_by_modules is empty after serialization!")
            if not first_module.get('calls_modules'):
                logger.error("❌ calls_modules is empty after serialization!")
                
    except Exception as e:
        logger.error(f"❌ JSON serialization failed: {e}")

if __name__ == "__main__":
    test_to_dict()
