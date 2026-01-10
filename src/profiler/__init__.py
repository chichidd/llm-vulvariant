"""
画像生成模块

提供软件画像和漏洞画像的生成功能。
"""

# 软件画像模块（向后兼容）
from .software import (
    SoftwareProfiler,
    SoftwareProfile,
    ModuleInfo,
    EnhancedModuleInfo,
    DataFlowPattern,
)

# 漏洞画像模块（向后兼容）
from .vulnerability import (
    VulnerabilityProfiler,
    VulnerabilityProfile,
    VulnEntry,
    SourceFeature,
    FlowFeature,
    SinkFeature,
)

# 存储管理器
from .profile_storage import ProfileStorageManager

# 从原始位置保持向后兼容（逐步弃用）
# from .software_profile import SoftwareProfiler  # 已移动到 software/analyzer.py
# from .vuln_profile import VulnerabilityProfiler  # 已移动到 vulnerability/analyzer.py

__all__ = [
    # 软件画像
    "SoftwareProfiler",
    "SoftwareProfile",
    "ModuleInfo",
    "EnhancedModuleInfo",
    "DataFlowPattern",
    # 漏洞画像
    "VulnerabilityProfiler",
    "VulnerabilityProfile",
    "VulnEntry",
    "SourceFeature",
    "FlowFeature",
    "SinkFeature",
    # 存储
    "ProfileStorageManager",
]
