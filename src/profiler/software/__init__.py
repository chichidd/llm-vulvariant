"""Software profiling module (refactored version).

Architecture:
- models.py: Data model definitions
- analyzer.py: Lightweight orchestrator (refactored)
- prompts.py: LLM prompt templates
- repo_collector.py: Repository information collection
- basic_info_analyzer.py: Basic information analysis
- module_analyzer.py: Module structure analysis (agent-based or skill-based)
- deep_analyzer.py: Deep static analysis
"""

from .models import (
    EXTENSION_MAPPING,
    ModuleInfo,
    DataFlowPattern,
    SoftwareProfile,
)
from .analyzer import SoftwareProfiler
from .repo_collector import RepoInfoCollector
from .basic_info_analyzer import BasicInfoAnalyzer
from .module_analyzer import ModuleAnalyzer
from .repo_analyzer import RepoAnalyzer

__all__ = [
    # Configuration
    "EXTENSION_MAPPING",
    # Data models
    "ModuleInfo",
    "DataFlowPattern",
    "SoftwareProfile",
    # Main profiler
    "SoftwareProfiler",
    # Sub-component analyzers (can be used standalone)
    "RepoInfoCollector",
    "BasicInfoAnalyzer",
    "ModuleAnalyzer",
    "RepoAnalyzer",
]
