"""软件画像数据模型。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


# 扩展名到语言的映射
EXTENSION_MAPPING = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
    ".c": "C/C++",
    ".cc": "C/C++",
    ".cpp": "C/C++",
    ".cxx": "C/C++",
    ".h": "C/C++",
    ".hh": "C/C++",
    ".hpp": "C/C++",
    ".hxx": "C/C++",
    ".cu": "C/C++",
    ".cuh": "C/C++",
}


def normalize_file_extensions(extensions: Optional[Iterable[str]]) -> List[str]:
    """Normalize configured file extensions while preserving order."""
    normalized: List[str] = []
    seen = set()
    for ext in extensions or []:
        if not isinstance(ext, str):
            continue
        value = ext.strip().lower()
        if not value:
            continue
        if not value.startswith("."):
            value = f".{value}"
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


DEFAULT_FILE_EXTENSIONS = normalize_file_extensions(EXTENSION_MAPPING.keys())
VALID_BASIC_INFO_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})
NON_EMPTY_BASIC_INFO_LIST_FIELDS = (
    "target_application",
    "target_user",
    "capabilities",
)
OPTIONAL_BASIC_INFO_LIST_FIELDS = (
    "interfaces",
    "deployment_style",
    "operator_inputs",
    "external_surfaces",
    "open_questions",
)


def is_valid_software_basic_info(basic_info: Optional[Dict[str, Any]]) -> bool:
    """Return whether a basic-info payload satisfies the Task 5 contract."""
    if not isinstance(basic_info, dict):
        return False

    for key in ("description", "evidence_summary"):
        value = basic_info.get(key)
        if not isinstance(value, str) or not value.strip():
            return False

    confidence = basic_info.get("confidence")
    if not isinstance(confidence, str) or confidence.strip().lower() not in VALID_BASIC_INFO_CONFIDENCE_VALUES:
        return False

    for key in NON_EMPTY_BASIC_INFO_LIST_FIELDS:
        values = basic_info.get(key)
        if not isinstance(values, list) or not values:
            return False
        if any(not isinstance(item, str) or not item.strip() for item in values):
            return False

    for key in OPTIONAL_BASIC_INFO_LIST_FIELDS:
        values = basic_info.get(key)
        if not isinstance(values, list):
            return False
        if any(not isinstance(item, str) or not item.strip() for item in values):
            return False

    return True


@dataclass
class ModuleInfo:
    """增强的模块信息(支持相似性比较)"""
    # 基本信息
    name: str
    category: str = ""  # 功能类别: data_loading, model_serving, api_interface, etc.
    description: str = ""
    responsibility: str = ""  # 模块边界内的核心职责
    entry_points: List[str] = field(default_factory=list)            # 对外入口
    files: List[str] = field(default_factory=list)
    
    # 功能特征（从 RepoAnalyzer 提取）
    key_functions: List[str] = field(default_factory=list)            # 关键函数
    interfaces: List[str] = field(default_factory=list)               # 模块暴露/依赖的接口

    # 数据流特征
    data_sources: List[str] = field(default_factory=list)             # 数据来源: file, network, database, user_input
    data_formats: List[str] = field(default_factory=list)             # 数据格式: json, yaml, pickle, csv
    processing_operations: List[str] = field(default_factory=list)    # 处理操作: parse, validate, transform
    
    # 依赖特征
    external_dependencies: List[str] = field(default_factory=list)    # 外部库依赖
    internal_dependencies: List[str] = field(default_factory=list)    # 内部模块依赖
    depends_on: List[str] = field(default_factory=list)               # 新模块分析依赖
    dependencies: List[str] = field(default_factory=list)             # 原始模块分析依赖
    boundary_rationale: str = ""                                      # 模块边界划分依据
    evidence_paths: List[str] = field(default_factory=list)           # 支撑该模块划分的证据路径
    confidence: str = "unknown"                                       # 模块画像置信度

    # 调用关系（来自调用图）
    called_by_modules: List[str] = field(default_factory=list)        # 被哪些模块调用
    calls_modules: List[str] = field(default_factory=list)            # 调用哪些模块

    def __post_init__(self) -> None:
        if not self.depends_on and self.dependencies:
            self.depends_on = list(self.dependencies)
        if not self.dependencies and self.depends_on:
            self.dependencies = list(self.depends_on)
        if not self.confidence:
            self.confidence = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        resolved_depends_on = self.depends_on or self.dependencies
        resolved_dependencies = self.dependencies or self.depends_on
        data = {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "responsibility": self.responsibility,
            "entry_points": self.entry_points,
            "files": self.files,
            "key_functions": self.key_functions,
            "interfaces": self.interfaces,
            "depends_on": resolved_depends_on,
            "boundary_rationale": self.boundary_rationale,
            "evidence_paths": self.evidence_paths,
            "confidence": self.confidence,
            "data_sources": self.data_sources,
            "data_formats": self.data_formats,
            "processing_operations": self.processing_operations,
            "external_dependencies": self.external_dependencies,
            "internal_dependencies": self.internal_dependencies,
            "called_by_modules": self.called_by_modules,
            "calls_modules": self.calls_modules,
        }
        if resolved_dependencies:
            data["dependencies"] = resolved_dependencies
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleInfo":
        depends_on = data.get("depends_on", [])
        if not isinstance(depends_on, list):
            depends_on = []

        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            dependencies = []

        if not depends_on and dependencies:
            depends_on = list(dependencies)
        if not dependencies and depends_on:
            dependencies = list(depends_on)

        return cls(
            name=data.get("name", ""),
            category=data.get("category", ""),
            description=data.get("description", ""),
            responsibility=data.get("responsibility", ""),
            entry_points=data.get("entry_points", []),
            files=data.get("files", []),
            key_functions=data.get("key_functions", []),
            interfaces=data.get("interfaces", []),
            data_sources=data.get("data_sources", []),
            data_formats=data.get("data_formats", []),
            processing_operations=data.get("processing_operations", []),
            external_dependencies=data.get("external_dependencies", []),
            internal_dependencies=data.get("internal_dependencies", []),
            depends_on=depends_on,
            dependencies=dependencies,
            boundary_rationale=data.get("boundary_rationale", ""),
            evidence_paths=data.get("evidence_paths", []),
            confidence=data.get("confidence", "unknown"),
            called_by_modules=data.get("called_by_modules", []),
            calls_modules=data.get("calls_modules", []),
        )


@dataclass
class DataFlowPattern:
    """数据流模式"""
    pattern_type: str = ""                   # "file_to_memory", "network_to_file", etc.
    source_apis: List[str] = field(default_factory=list)              # 数据源 API
    sink_apis: List[str] = field(default_factory=list)                # 数据汇 API
    intermediate_operations: List[str] = field(default_factory=list)  # 中间处理操作
    file_paths: List[str] = field(default_factory=list)               # 涉及的文件路径
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "source_apis": self.source_apis,
            "sink_apis": self.sink_apis,
            "intermediate_operations": self.intermediate_operations,
            "file_paths": self.file_paths,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DataFlowPattern":
        return cls(
            pattern_type=data.get("pattern_type", ""),
            source_apis=data.get("source_apis", []),
            sink_apis=data.get("sink_apis", []),
            intermediate_operations=data.get("intermediate_operations", []),
            file_paths=data.get("file_paths", []),
        )


@dataclass
class SoftwareProfile:
    """软件画像 - 完整的软件特征描述"""
    
    # 1.1 基本信息
    name: str
    version: Optional[str] = None  # commit hash or version string
    description: str = ""
    target_application: List[str] = field(default_factory=list)  # 目标场景
    target_user: List[str] = field(default_factory=list)  # 目标人群
    capabilities: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    deployment_style: List[str] = field(default_factory=list)
    operator_inputs: List[str] = field(default_factory=list)
    external_surfaces: List[str] = field(default_factory=list)
    evidence_summary: str = ""
    confidence: str = "unknown"
    open_questions: List[str] = field(default_factory=list)

    # 1.2 架构信息
    repo_info: Dict[str, Any] = field(default_factory=dict)
    

    modules: List[ModuleInfo] = field(default_factory=list)
    
    # 项目级数据流特征（可选）
    data_flow_patterns: List[DataFlowPattern] = field(default_factory=list)
    common_data_sources: List[str] = field(default_factory=list)     # file, network, database
    common_data_formats: List[str] = field(default_factory=list)     # json, yaml, pickle
    
    # 调用图特征（可选）
    total_functions: int = 0
    
    # 依赖特征详细信息（可选）
    third_party_libraries: List[str] = field(default_factory=list)
    builtin_libraries: List[str] = field(default_factory=list)
    dependency_usage_count: Dict[str, int] = field(default_factory=dict)  # {lib: import_count}
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        serialized_modules = [
            module.to_dict()
            if isinstance(module, ModuleInfo)
            else ModuleInfo.from_dict(module).to_dict()
            for module in self.modules
            if isinstance(module, (ModuleInfo, dict))
        ]
        serialized_patterns = [
            pattern.to_dict()
            if isinstance(pattern, DataFlowPattern)
            else DataFlowPattern.from_dict(pattern).to_dict()
            for pattern in self.data_flow_patterns
            if isinstance(pattern, (DataFlowPattern, dict))
        ]
        result = {
            "basic_info": {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "target_application": self.target_application,
                "target_user": self.target_user,
                "capabilities": self.capabilities,
                "interfaces": self.interfaces,
                "deployment_style": self.deployment_style,
                "operator_inputs": self.operator_inputs,
                "external_surfaces": self.external_surfaces,
                "evidence_summary": self.evidence_summary,
                "confidence": self.confidence,
                "open_questions": self.open_questions,
            },
            "repo_info": self.repo_info,
            "modules": serialized_modules,
        }

        if serialized_patterns:
            result["data_flow_patterns"] = serialized_patterns
        
        if self.common_data_sources:
            result["common_data_sources"] = self.common_data_sources
        
        if self.common_data_formats:
            result["common_data_formats"] = self.common_data_formats
        
        if self.total_functions > 0:
            result["call_graph_stats"] = {
                "total_functions": self.total_functions,
            }
        
        if (
            self.third_party_libraries
            or self.builtin_libraries
            or self.dependency_usage_count
        ):
            result["dependencies_detailed"] = {
                "third_party": self.third_party_libraries,
                "builtin": self.builtin_libraries,
                "usage_count": self.dependency_usage_count,
            }

        if self.metadata:
            result["metadata"] = self.metadata
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SoftwareProfile":
        """从字典创建"""
        basic = data.get("basic_info", {})
        repo_info = data.get("repo_info", {})
        if not isinstance(repo_info, dict):
            repo_info = {}

        modules_data = data.get("modules", [])
        modules = [
            module
            if isinstance(module, ModuleInfo)
            else ModuleInfo.from_dict(module)
            for module in modules_data
            if isinstance(module, (ModuleInfo, dict))
        ]

        data_flow_patterns_data = data.get("data_flow_patterns", [])
        data_flow_patterns = [
            pattern
            if isinstance(pattern, DataFlowPattern)
            else DataFlowPattern.from_dict(pattern)
            for pattern in data_flow_patterns_data
            if isinstance(pattern, (DataFlowPattern, dict))
        ]

        call_graph_stats = data.get("call_graph_stats", {})
        deps_detailed = data.get("dependencies_detailed", {})
        if not isinstance(call_graph_stats, dict):
            call_graph_stats = {}
        if not isinstance(deps_detailed, dict):
            deps_detailed = {}
        
        return cls(
            name=basic.get("name", ""),
            version=basic.get("version"),
            description=basic.get("description", ""),
            target_application=basic.get("target_application", []),
            target_user=basic.get("target_user", []),
            capabilities=basic.get("capabilities", []),
            interfaces=basic.get("interfaces", []),
            deployment_style=basic.get("deployment_style", []),
            operator_inputs=basic.get("operator_inputs", []),
            external_surfaces=basic.get("external_surfaces", []),
            evidence_summary=basic.get("evidence_summary", ""),
            confidence=basic.get("confidence", "unknown"),
            open_questions=basic.get("open_questions", []),
            repo_info=repo_info,
            modules=modules,
            data_flow_patterns=data_flow_patterns,
            common_data_sources=data.get("common_data_sources", []),
            common_data_formats=data.get("common_data_formats", []),
            total_functions=call_graph_stats.get("total_functions", 0),
            third_party_libraries=deps_detailed.get("third_party", []),
            builtin_libraries=deps_detailed.get("builtin", []),
            dependency_usage_count=deps_detailed.get("usage_count", {}),
            metadata=data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {},
        )
