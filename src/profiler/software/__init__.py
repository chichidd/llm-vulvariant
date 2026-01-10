"""
软件画像模块（重构版）

架构说明：
- models.py: 数据模型定义
- analyzer.py: 轻量级协调器（已重构）
- prompts.py: LLM Prompt 模板
- repo_collector.py: 仓库信息收集
- basic_info_analyzer.py: 基本信息分析
- module_analyzer.py: 模块结构分析
- file_summarizer.py: 文件摘要生成
- deep_analyzer.py: 深度静态分析
"""

from .models import (
    EXTENSION_MAPPING,
    ModuleInfo,
    EnhancedModuleInfo,
    DataFlowPattern,
    SoftwareProfile,
)
from .analyzer import SoftwareProfiler
from .repo_collector import RepoInfoCollector
from .basic_info_analyzer import BasicInfoAnalyzer
from .module_analyzer import ModuleAnalyzer
from .file_summarizer import FileSummarizer
from .deep_analyzer import DeepAnalyzer

__all__ = [
    # 配置
    "EXTENSION_MAPPING",
    # 数据模型
    "ModuleInfo",
    "EnhancedModuleInfo",
    "DataFlowPattern",
    "SoftwareProfile",
    # 主要分析器
    "SoftwareProfiler",
    # 子组件分析器（可单独使用）
    "RepoInfoCollector",
    "BasicInfoAnalyzer",
    "ModuleAnalyzer",
    "FileSummarizer",
    "DeepAnalyzer",
]
