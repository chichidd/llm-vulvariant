"""
软件画像数据模型

包含软件画像相关的所有数据类定义：
- ModuleInfo: 模块信息
- DataFlowPattern: 数据流模式
- SoftwareProfile: 软件画像主类
- FolderModule: 基于文件夹的模块信息（树状结构）
- ModuleTree: 模块树根节点
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Iterator
import json
from pathlib import Path


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
    public_apis: List[str] = field(default_factory=list)              # 对外接口（函数/类）
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
            "public_apis": self.public_apis,
            "key_functions": self.key_functions,
            "data_sources": self.data_sources,
            "data_formats": self.data_formats,
            "processing_operations": self.processing_operations,
            "external_dependencies": self.external_dependencies,
            "internal_dependencies": self.internal_dependencies,
            "called_by_modules": self.called_by_modules,
            "calls_modules": self.calls_modules,
        }
        # Keep compatibility with module analyzer output schema.
        data["paths"] = self.files
        data["dependencies"] = self.internal_dependencies
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleInfo":
        return cls(
            name=data.get("name", ""),
            category=data.get("category", ""),
            description=data.get("description", ""),
            files=data.get("files", data.get("paths", [])),
            public_apis=data.get("public_apis", []),
            key_functions=data.get("key_functions", []),
            data_sources=data.get("data_sources", []),
            data_formats=data.get("data_formats", []),
            processing_operations=data.get("processing_operations", []),
            external_dependencies=data.get("external_dependencies", []),
            internal_dependencies=data.get("internal_dependencies", data.get("dependencies", [])),
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
        
        # 解析安全特征
        security = data.get("security_features", {})

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


# =============================================================================
# 基于文件夹分割规则的模块结构（树状结构）
# =============================================================================

@dataclass
class FolderModule:
    """
    基于文件夹的模块信息（树状结构节点）
    
    支持层级嵌套，例如：
    - train (训练模块)
      - dpo (训练模块-DPO算法模块)
      - sft (训练模块-SFT算法模块)
    """
    # 基本信息
    name: str                                    # 模块名称，由LLM根据功能命名
    folder_path: str                             # 文件夹相对路径
    description: str = ""                        # 模块功能描述
    
    # 模块类型
    is_leaf: bool = False                        # 是否是叶子模块（最小子模块，全是代码文件）
    
    # 包含的文件（仅叶子模块有）
    files: List[str] = field(default_factory=list)
    
    # 子模块（非叶子模块有）
    children: List["FolderModule"] = field(default_factory=list)
    
    # 功能特征（由LLM分析得出）
    key_functions: List[str] = field(default_factory=list)     # 关键函数/类
    key_classes: List[str] = field(default_factory=list)       # 关键类
    external_dependencies: List[str] = field(default_factory=list)  # 外部依赖
    
    # 层级信息
    depth: int = 0                               # 在树中的深度（根为0）
    full_module_path: str = ""                   # 完整模块路径名，如 "训练模块/DPO算法模块"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "name": self.name,
            "folder_path": self.folder_path,
            "description": self.description,
            "is_leaf": self.is_leaf,
            "depth": self.depth,
            "full_module_path": self.full_module_path,
        }
        
        if self.files:
            result["files"] = self.files
        
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]
        
        if self.key_functions:
            result["key_functions"] = self.key_functions
        
        if self.key_classes:
            result["key_classes"] = self.key_classes
        
        if self.external_dependencies:
            result["external_dependencies"] = self.external_dependencies
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FolderModule":
        """从字典创建"""
        children = []
        if "children" in data:
            children = [cls.from_dict(c) for c in data["children"]]
        
        return cls(
            name=data.get("name", ""),
            folder_path=data.get("folder_path", ""),
            description=data.get("description", ""),
            is_leaf=data.get("is_leaf", False),
            files=data.get("files", []),
            children=children,
            key_functions=data.get("key_functions", []),
            key_classes=data.get("key_classes", []),
            external_dependencies=data.get("external_dependencies", []),
            depth=data.get("depth", 0),
            full_module_path=data.get("full_module_path", ""),
        )
    
    def iter_all_modules(self) -> Iterator["FolderModule"]:
        """迭代所有模块（包括自身和所有子模块）"""
        yield self
        for child in self.children:
            yield from child.iter_all_modules()
    
    def iter_leaf_modules(self) -> Iterator["FolderModule"]:
        """迭代所有叶子模块"""
        if self.is_leaf:
            yield self
        else:
            for child in self.children:
                yield from child.iter_leaf_modules()
    
    def get_child_by_path(self, folder_path: str) -> Optional["FolderModule"]:
        """根据文件夹路径获取子模块"""
        if self.folder_path == folder_path:
            return self
        for child in self.children:
            result = child.get_child_by_path(folder_path)
            if result:
                return result
        return None
    
    def get_flat_summary(self) -> str:
        """获取扁平化的模块摘要，用于显示"""
        lines = []
        indent = "  " * self.depth
        module_type = "[叶子]" if self.is_leaf else "[容器]"
        lines.append(f"{indent}{module_type} {self.name}: {self.description}")
        for child in self.children:
            lines.append(child.get_flat_summary())
        return "\n".join(lines)


@dataclass
class ModuleTree:
    """
    模块树 - 存储整个仓库的树状模块结构
    
    使用场景：
    1. 存储基于文件夹分割的模块分析结果
    2. 支持大小模块嵌套的层级结构
    3. 方便遍历和查询
    """
    # 根模块（代表整个仓库）
    root: FolderModule = None
    
    # 元数据
    repo_name: str = ""
    repo_path: str = ""
    analysis_timestamp: str = ""
    total_modules: int = 0
    total_leaf_modules: int = 0
    max_depth: int = 0
    
    # 分析配置
    excluded_folders: List[str] = field(default_factory=list)
    code_extensions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "metadata": {
                "repo_name": self.repo_name,
                "repo_path": self.repo_path,
                "analysis_timestamp": self.analysis_timestamp,
                "total_modules": self.total_modules,
                "total_leaf_modules": self.total_leaf_modules,
                "max_depth": self.max_depth,
            },
            "module_tree": self.root.to_dict() if self.root else None,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModuleTree":
        """从字典创建"""
        metadata = data.get("metadata", {})

        root = None
        if data.get("module_tree"):
            root = FolderModule.from_dict(data["module_tree"])
        
        return cls(
            root=root,
            repo_name=metadata.get("repo_name", ""),
            repo_path=metadata.get("repo_path", ""),
            analysis_timestamp=metadata.get("analysis_timestamp", ""),
            total_modules=metadata.get("total_modules", 0),
            total_leaf_modules=metadata.get("total_leaf_modules", 0),
            max_depth=metadata.get("max_depth", 0),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "ModuleTree":
        """从JSON字符串创建"""
        return cls.from_dict(json.loads(json_str))
    
    def save(self, file_path: Path) -> None:
        """保存到文件"""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(self.to_json())
    
    @classmethod
    def load(cls, file_path: Path) -> "ModuleTree":
        """从文件加载"""
        with open(file_path, 'r', encoding='utf-8') as f:
            return cls.from_json(f.read())
    
    def iter_all_modules(self) -> Iterator[FolderModule]:
        """迭代所有模块"""
        if self.root:
            yield from self.root.iter_all_modules()
    
    def iter_leaf_modules(self) -> Iterator[FolderModule]:
        """迭代所有叶子模块"""
        if self.root:
            yield from self.root.iter_leaf_modules()
    
    def get_module_by_path(self, folder_path: str) -> Optional[FolderModule]:
        """根据文件夹路径获取模块"""
        if self.root:
            return self.root.get_child_by_path(folder_path)
        return None
    
    def get_modules_at_depth(self, depth: int) -> List[FolderModule]:
        """获取指定深度的所有模块"""
        result = []
        for module in self.iter_all_modules():
            if module.depth == depth:
                result.append(module)
        return result
    
    def get_summary(self) -> str:
        """获取模块树摘要"""
        lines = [
            f"模块树: {self.repo_name}",
            f"总模块数: {self.total_modules}",
            f"叶子模块数: {self.total_leaf_modules}",
            f"最大深度: {self.max_depth}",
            "",
            "模块结构:",
        ]
        if self.root:
            lines.append(self.root.get_flat_summary())
        return "\n".join(lines)
