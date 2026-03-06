"""
软件画像数据模型

包含软件画像相关的所有数据类定义：
- ModuleInfo: 模块信息
- DataFlowPattern: 数据流模式
- SoftwareProfile: 软件画像主类
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json


# 扩展名到语言的映射
EXTENSION_MAPPING = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".rs": "Rust",
}


@dataclass
class ModuleInfo:
    """增强的模块信息(支持相似性比较)"""
    # 基本信息
    name: str
    category: str = ""  # 功能类别: data_loading, model_serving, api_interface, etc.
    description: str = ""
    files: List[str] = field(default_factory=list)
    
    # 功能特征（从 RepoAnalyzer 提取）
    key_functions: List[str] = field(default_factory=list)            # 关键函数
    
    # 数据流特征
    data_sources: List[str] = field(default_factory=list)             # 数据来源: file, network, database, user_input
    data_formats: List[str] = field(default_factory=list)             # 数据格式: json, yaml, pickle, csv
    processing_operations: List[str] = field(default_factory=list)    # 处理操作: parse, validate, transform
    
    # 依赖特征
    external_dependencies: List[str] = field(default_factory=list)    # 外部库依赖
    internal_dependencies: List[str] = field(default_factory=list)    # 内部模块依赖
    
    # 调用关系（来自调用图）
    called_by_modules: List[str] = field(default_factory=list)        # 被哪些模块调用
    calls_modules: List[str] = field(default_factory=list)            # 调用哪些模块
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "files": self.files,
            "key_functions": self.key_functions,
            "data_sources": self.data_sources,
            "data_formats": self.data_formats,
            "processing_operations": self.processing_operations,
            "external_dependencies": self.external_dependencies,
            "internal_dependencies": self.internal_dependencies,
            "called_by_modules": self.called_by_modules,
            "calls_modules": self.calls_modules,
        }
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleInfo":
        return cls(
            name=data.get("name", ""),
            category=data.get("category", ""),
            description=data.get("description", ""),
            files=data.get("files", []),
            key_functions=data.get("key_functions", []),
            data_sources=data.get("data_sources", []),
            data_formats=data.get("data_formats", []),
            processing_operations=data.get("processing_operations", []),
            external_dependencies=data.get("external_dependencies", []),
            internal_dependencies=data.get("internal_dependencies", []),
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


@dataclass
class SoftwareProfile:
    """软件画像 - 完整的软件特征描述"""
    
    # 1.1 基本信息
    name: str
    version: Optional[str] = None  # commit hash or version string
    description: str = ""
    target_application: List[str] = field(default_factory=list)  # 目标场景
    target_user: List[str] = field(default_factory=list)  # 目标人群

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

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "basic_info": {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "target_application": self.target_application,
                "target_user": self.target_user,
            },
            "repo_info": self.repo_info,
            "modules": self.modules,
        }

        if self.modules and hasattr(self.modules[0], "to_dict"):
            result["modules"] = [m.to_dict() for m in self.modules]
        
        if self.data_flow_patterns:
            result["data_flow_patterns"] = [p.to_dict() for p in self.data_flow_patterns]
        
        if self.common_data_sources:
            result["common_data_sources"] = self.common_data_sources
        
        if self.common_data_formats:
            result["common_data_formats"] = self.common_data_formats
        
        if self.total_functions > 0:
            result["call_graph_stats"] = {
                "total_functions": self.total_functions,
            }
        
        if self.third_party_libraries:
            result["dependencies_detailed"] = {
                "third_party": self.third_party_libraries,
                "builtin": self.builtin_libraries,
                "usage_count": self.dependency_usage_count,
            }
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SoftwareProfile":
        """从字典创建"""
        basic = data.get("basic_info", {})
        repo_info = data.get("repo_info", {})
        
        # 解析模块信息 - 统一从modules字段解析
        modules = []
        if "modules" in data:
            modules_data = data["modules"]
            if modules_data and isinstance(modules_data, list):
                # 判断是否是ModuleInfo格式（包含enhanced字段）
                if isinstance(modules_data[0], dict) and "external_dependencies" in modules_data[0]:
                    # 新格式：直接包含ModuleInfo的完整字段
                    modules = [ModuleInfo.from_dict(m) for m in modules_data]
                else:
                    # 旧格式或简单格式：可能只有基本字段
                    modules = modules_data
        
        # 兼容旧版本的enhanced_modules字段
        if "enhanced_modules" in data:
            enhanced_modules_data = data["enhanced_modules"]
            if enhanced_modules_data:
                modules = [ModuleInfo.from_dict(m) for m in enhanced_modules_data]
        
        # 解析数据流模式
        data_flow_patterns = []
        if "data_flow_patterns" in data:
            data_flow_patterns = [DataFlowPattern(**p) for p in data["data_flow_patterns"]]
        
        # 解析调用图统计
        call_graph_stats = data.get("call_graph_stats", {})
        
        # 解析依赖详情
        deps_detailed = data.get("dependencies_detailed", {})
        
        return cls(
            name=basic.get("name", ""),
            version=basic.get("version"),
            description=basic.get("description", ""),
            target_application=basic.get("target_application", []),
            target_user=basic.get("target_user", []),
            repo_info=repo_info,
            modules=modules,
            data_flow_patterns=data_flow_patterns,
            common_data_sources=data.get("common_data_sources", []),
            common_data_formats=data.get("common_data_formats", []),
            total_functions=call_graph_stats.get("total_functions", 0),
            third_party_libraries=deps_detailed.get("third_party", []),
            builtin_libraries=deps_detailed.get("builtin", []),
            dependency_usage_count=deps_detailed.get("usage_count", {}),
        )
