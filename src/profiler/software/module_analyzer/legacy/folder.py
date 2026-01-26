"""基于文件夹分割规则的模块分析器

使用递归方式分析 GitHub 仓库的文件夹结构，构建树状模块结构。

核心逻辑：
1. 从仓库根目录开始，递归分析每个文件夹
2. 如果文件夹下全是代码文件（叶子模块），使用 LLM agent 分析功能
3. 如果文件夹包含子文件夹，先递归分析子文件夹，然后综合分析当前模块
4. 最终构建一个树状的模块结构
"""

import json
import fnmatch
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from llm import BaseLLMClient
from utils.logger import get_logger

from profiler.software.models import FolderModule, ModuleTree
from profiler.software.module_analyzer.toolkit import FolderAnalyzerToolkit
from profiler.software.module_analyzer.base import run_agent_analysis
from profiler.software.prompts import (
    FOLDER_LEAF_MODULE_SYSTEM_PROMPT,
    FOLDER_LEAF_MODULE_INITIAL_MESSAGE,
    FOLDER_CONTAINER_MODULE_SYSTEM_PROMPT,
    FOLDER_CONTAINER_MODULE_INITIAL_MESSAGE,
)

logger = get_logger(__name__)


# 默认排除的文件夹（可在配置中覆盖）
DEFAULT_EXCLUDED_FOLDERS = [
    # 版本控制
    ".git",
    ".svn",
    ".hg",
    
    # Python
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "*.egg-info",
    ".eggs",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    ".env",
    "virtualenv",
    
    # Node.js / JavaScript
    "node_modules",
    "bower_components",
    ".npm",
    ".yarn",
    
    # Build outputs
    "build",
    "dist",
    "out",
    "target",
    "_build",
    "site-packages",
    
    # IDE / Editor
    ".idea",
    ".vscode",
    ".vs",
    ".eclipse",
    ".settings",
    
    # Documentation
    "docs/_build",
    "_site",
    
    # Coverage / Testing
    "coverage",
    "htmlcov",
    ".coverage",
    
    # Misc
    ".cache",
    ".tmp",
    "tmp",
    "temp",
    "logs",
    ".DS_Store",
    "Thumbs.db",
    
    # CI/CD
    ".github",
    ".gitlab",
    ".circleci",
    
    # Container
    ".docker",
]

# 默认代码文件扩展名
DEFAULT_CODE_EXTENSIONS = [
    ".py", ".pyx", ".pyi",  # Python
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",  # JavaScript/TypeScript
    ".java", ".kt", ".scala",  # JVM
    ".go",  # Go
    ".rs",  # Rust
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp",  # C/C++
    ".cs",  # C#
    ".rb",  # Ruby
    ".php",  # PHP
    ".swift",  # Swift
    ".r", ".R",  # R
    ".jl",  # Julia
    ".lua",  # Lua
    ".sh", ".bash",  # Shell
    ".sql",  # SQL
]

def _build_folder_structure(file_list: List[str]) -> Dict[str, Dict]:
    """
    构建文件夹结构
    
    Returns:
        Dict mapping folder_path to {
            "files": [直接包含的文件],
            "subfolders": [直接子文件夹]
        }
    """
    structure = {}
    
    for file_path in file_list:
        parts = file_path.replace("\\", "/").split("/")
        
        # 为每一级文件夹记录信息
        for i in range(len(parts)):
            if i == len(parts) - 1:
                # 最后一部分是文件名
                folder_path = "/".join(parts[:-1])
                if folder_path not in structure:
                    structure[folder_path] = {"files": [], "subfolders": set()}
                structure[folder_path]["files"].append(file_path)
            else:
                # 中间部分是文件夹
                folder_path = "/".join(parts[:i+1])
                parent_path = "/".join(parts[:i]) if i > 0 else ""
                
                if folder_path not in structure:
                    structure[folder_path] = {"files": [], "subfolders": set()}
                
                if parent_path not in structure:
                    structure[parent_path] = {"files": [], "subfolders": set()}
                
                structure[parent_path]["subfolders"].add(folder_path)
    
    # 转换 set 为 list
    for folder_path in structure:
        structure[folder_path]["subfolders"] = sorted(structure[folder_path]["subfolders"])
    
    return structure

class FolderModuleAnalyzer:
    """
    基于文件夹分割规则的模块分析器
    
    使用递归方式分析仓库结构，为每个文件夹构建模块信息，
    最终形成一个完整的树状模块结构。
    """
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        excluded_folders: List[str] = None,
        code_extensions: List[str] = None,
        max_agent_iterations: int = 10,
        max_file_content_length: int = 8000,
        skip_empty_folders: bool = True,
        min_files_for_module: int = 1,
    ):
        """
        初始化分析器
        
        Args:
            llm_client: LLM 客户端
            excluded_folders: 要排除的文件夹列表（支持通配符）
            code_extensions: 代码文件扩展名列表
            max_agent_iterations: 单个模块分析的最大迭代次数
            max_file_content_length: 读取文件内容的最大长度
            skip_empty_folders: 是否跳过空文件夹
            min_files_for_module: 成为模块的最小文件数
        """
        self.llm_client = llm_client
        self.excluded_folders = excluded_folders or DEFAULT_EXCLUDED_FOLDERS
        self.code_extensions = code_extensions or DEFAULT_CODE_EXTENSIONS
        self.max_agent_iterations = max_agent_iterations
        self.max_file_content_length = max_file_content_length
        self.skip_empty_folders = skip_empty_folders
        self.min_files_for_module = min_files_for_module
        
        # 用于 conversation 保存的上下文
        self._storage_manager = None
        self._repo_name = None
        self._version = None
        
        # 分析统计
        self._stats = {
            "total_folders_scanned": 0,
            "total_modules_created": 0,
            "leaf_modules": 0,
            "container_modules": 0,
            "skipped_folders": 0,
            "llm_calls": 0,
        }
    
    def analyze(
        self,
        repo_path: Path,
        repo_name: str = None,
        file_list: List[str] = None,
        storage_manager = None,
        version: str = None,
    ) -> ModuleTree:
        """
        分析仓库的模块结构
        
        Args:
            repo_path: 仓库路径
            repo_name: 仓库名称
            file_list: 文件列表（如果已有，避免重复扫描）
            storage_manager: 存储管理器，用于保存 conversation
            version: 版本号
        
        Returns:
            ModuleTree: 树状模块结构
        """
        repo_path = Path(repo_path)
        repo_name = repo_name or repo_path.name
        
        # 保存上下文用于 conversation 保存
        self._storage_manager = storage_manager
        self._repo_name = repo_name
        self._version = version
        
        logger.info(f"Starting folder-based module analysis for: {repo_name}")
        logger.info(f"Excluded folders: {len(self.excluded_folders)} patterns")
        logger.info(f"Code extensions: {self.code_extensions}")
        
        # 收集文件列表
        if file_list is None:
            file_list = self._collect_files(repo_path)
        
        logger.info(f"Total files to analyze: {len(file_list)}")
        
        # 构建文件夹结构
        folder_structure = _build_folder_structure(file_list)
        
        logger.info(f"Total folders to analyze: {len(folder_structure)}")
        
        # 递归分析，从根目录开始
        root_module = self._analyze_folder(
            repo_path=repo_path,
            repo_name=repo_name,
            folder_path="",
            folder_structure=folder_structure,
            file_list=file_list,
            depth=0,
            parent_path="",
        )
        
        # 计算统计信息
        total_modules = 0
        leaf_modules = 0
        max_depth = 0
        
        if root_module:
            for module in root_module.iter_all_modules():
                total_modules += 1
                if module.is_leaf:
                    leaf_modules += 1
                max_depth = max(max_depth, module.depth)
        
        # 构建 ModuleTree
        module_tree = ModuleTree(
            root=root_module,
            repo_name=repo_name,
            repo_path=str(repo_path),
            analysis_timestamp=datetime.now().isoformat(),
            total_modules=total_modules,
            total_leaf_modules=leaf_modules,
            max_depth=max_depth,
            excluded_folders=self.excluded_folders,
            code_extensions=self.code_extensions,
        )
        
        logger.info(f"Module analysis complete!")
        logger.info(f"  Total modules: {total_modules}")
        logger.info(f"  Leaf modules: {leaf_modules}")
        logger.info(f"  Max depth: {max_depth}")
        logger.info(f"  LLM calls: {self._stats['llm_calls']}")
        
        return module_tree
    
    def _collect_files(self, repo_path: Path) -> List[str]:
        """收集仓库中的所有代码文件"""
        files = []
        
        for path in repo_path.rglob("*"):
            if path.is_file():
                rel_path = str(path.relative_to(repo_path))
                
                # 检查是否在排除的文件夹中
                if self._is_excluded(rel_path):
                    continue
                
                # 检查是否是代码文件
                if path.suffix.lower() in self.code_extensions:
                    files.append(rel_path)
        
        return sorted(files)
    
    def _is_excluded(self, path: str) -> bool:
        """检查路径是否应该被排除"""
        path_parts = path.replace("\\", "/").split("/")
        
        for part in path_parts:
            for pattern in self.excluded_folders:
                if fnmatch.fnmatch(part, pattern):
                    return True
        
        return False
    
    
    
    def _analyze_folder(
        self,
        repo_path: Path,
        repo_name: str,
        folder_path: str,
        folder_structure: Dict[str, Dict],
        file_list: List[str],
        depth: int,
        parent_path: str,
    ) -> Optional[FolderModule]:
        """
        递归分析文件夹
        
        Returns:
            FolderModule or None if folder should be skipped
        """
        self._stats["total_folders_scanned"] += 1
        
        folder_info = folder_structure.get(folder_path, {"files": [], "subfolders": []})
        direct_files = folder_info.get("files", [])
        subfolders = folder_info.get("subfolders", [])
        
        logger.debug(f"Analyzing folder: {folder_path or '(root)'}")
        logger.debug(f"  Direct files: {len(direct_files)}, Subfolders: {len(subfolders)}")
        
        # 跳过空文件夹
        if self.skip_empty_folders and not direct_files and not subfolders:
            self._stats["skipped_folders"] += 1
            return None
        
        # 判断是否是叶子模块（没有子文件夹，只有代码文件）
        is_leaf = len(subfolders) == 0 and len(direct_files) >= self.min_files_for_module
        
        if is_leaf:
            # 叶子模块：使用 LLM 分析
            return self._analyze_leaf_module(
                repo_path=repo_path,
                repo_name=repo_name,
                folder_path=folder_path,
                files=direct_files,
                depth=depth,
                parent_path=parent_path,
            )
        else:
            # 容器模块：先递归分析子文件夹
            children = []
            for subfolder in subfolders:
                child_module = self._analyze_folder(
                    repo_path=repo_path,
                    repo_name=repo_name,
                    folder_path=subfolder,
                    folder_structure=folder_structure,
                    file_list=file_list,
                    depth=depth + 1,
                    parent_path=folder_path,
                )
                if child_module:
                    children.append(child_module)
            
            # 如果没有有效的子模块且没有直接文件，跳过
            if not children and not direct_files:
                self._stats["skipped_folders"] += 1
                return None
            
            # 分析容器模块
            return self._analyze_container_module(
                repo_path=repo_path,
                repo_name=repo_name,
                folder_path=folder_path,
                direct_files=direct_files,
                children=children,
                depth=depth,
                parent_path=parent_path,
            )
    
    def _analyze_leaf_module(
        self,
        repo_path: Path,
        repo_name: str,
        folder_path: str,
        files: List[str],
        depth: int,
        parent_path: str,
    ) -> FolderModule:
        """分析叶子模块（全是代码文件的文件夹）"""
        logger.info(f"Analyzing leaf module: {folder_path or '(root)'} ({len(files)} files)")
        
        # 准备文件列表显示
        file_list_str = "\n".join(f"- {f}" for f in files[:30])
        if len(files) > 30:
            file_list_str += f"\n... 还有 {len(files) - 30} 个文件"
        
        # 初始化工具集
        toolkit = FolderAnalyzerToolkit(
            repo_path=repo_path,
            folder_path=folder_path,
            available_files=files,
            max_file_content_length=self.max_file_content_length,
        )
        
        # 构建初始消息
        initial_message = FOLDER_LEAF_MODULE_INITIAL_MESSAGE.format(
            folder_path=folder_path or "(仓库根目录)",
            file_list=file_list_str,
            repo_name=repo_name,
            parent_path=parent_path or "(无)",
        )
        
        # 运行 agent
        conversation_name = f"leaf_{folder_path.replace('/', '_')}" if folder_path else f"leaf_root"
        result = self._run_agent(
            system_prompt=FOLDER_LEAF_MODULE_SYSTEM_PROMPT,
            initial_message=initial_message,
            toolkit=toolkit,
            tools=toolkit.get_leaf_module_tools(),
            conversation_name=conversation_name,
        )
        
        self._stats["leaf_modules"] += 1
        self._stats["total_modules_created"] += 1
        
        # 构建模块
        module = FolderModule(
            name=result.get("name", folder_path.split("/")[-1] if folder_path else repo_name),
            folder_path=folder_path,
            description=result.get("description", ""),
            is_leaf=True,
            files=files,
            children=[],
            key_functions=result.get("key_functions", []),
            key_classes=result.get("key_classes", []),
            external_dependencies=result.get("external_dependencies", []),
            depth=depth,
            full_module_path=parent_path + "/" + result.get("name", "") if parent_path else result.get("name", ""),
        )
        
        return module
    
    def _analyze_container_module(
        self,
        repo_path: Path,
        repo_name: str,
        folder_path: str,
        direct_files: List[str],
        children: List[FolderModule],
        depth: int,
        parent_path: str,
    ) -> FolderModule:
        """分析容器模块（包含子文件夹的文件夹）"""
        logger.info(f"Analyzing container module: {folder_path or '(root)'} "
                   f"({len(children)} submodules, {len(direct_files)} direct files)")
        
        # 准备子模块摘要
        submodule_summaries = []
        for child in children:
            summary = f"### {child.name}\n"
            summary += f"- 路径: `{child.folder_path}`\n"
            summary += f"- 类型: {'叶子模块' if child.is_leaf else '容器模块'}\n"
            summary += f"- 描述: {child.description}\n"
            if child.key_functions:
                summary += f"- 关键函数: {', '.join(child.key_functions[:5])}\n"
            if child.key_classes:
                summary += f"- 关键类: {', '.join(child.key_classes[:5])}\n"
            submodule_summaries.append(summary)
        
        submodule_summaries_str = "\n".join(submodule_summaries) if submodule_summaries else "(无子模块)"
        
        # 准备直接文件列表
        direct_files_str = "\n".join(f"- {f}" for f in direct_files) if direct_files else "(无)"
        
        # 初始化工具集
        toolkit = FolderAnalyzerToolkit(
            repo_path=repo_path,
            folder_path=folder_path,
            available_files=direct_files,
            max_file_content_length=self.max_file_content_length,
        )
        
        # 构建初始消息
        initial_message = FOLDER_CONTAINER_MODULE_INITIAL_MESSAGE.format(
            folder_path=folder_path or "(仓库根目录)",
            submodule_summaries=submodule_summaries_str,
            direct_files=direct_files_str,
            repo_name=repo_name,
            parent_path=parent_path or "(无)",
        )
        
        # 运行 agent
        conversation_name = f"container_{folder_path.replace('/', '_')}" if folder_path else f"container_root"
        result = self._run_agent(
            system_prompt=FOLDER_CONTAINER_MODULE_SYSTEM_PROMPT,
            initial_message=initial_message,
            toolkit=toolkit,
            tools=toolkit.get_container_module_tools(),
            conversation_name=conversation_name,
        )
        
        self._stats["container_modules"] += 1
        self._stats["total_modules_created"] += 1
        
        # 合并子模块的依赖
        all_dependencies = set(result.get("external_dependencies", []))
        for child in children:
            all_dependencies.update(child.external_dependencies)
        
        # 构建模块
        module = FolderModule(
            name=result.get("name", folder_path.split("/")[-1] if folder_path else repo_name),
            folder_path=folder_path,
            description=result.get("description", ""),
            is_leaf=False,
            files=direct_files,
            children=children,
            key_functions=result.get("key_functions", []),
            key_classes=result.get("key_classes", []),
            external_dependencies=list(all_dependencies),
            depth=depth,
            full_module_path=parent_path + "/" + result.get("name", "") if parent_path else result.get("name", ""),
        )
        
        return module
    
    def _run_agent(
        self,
        system_prompt: str,
        initial_message: str,
        toolkit: FolderAnalyzerToolkit,
        tools: List[Dict[str, Any]],
        conversation_name: str = None,
    ) -> Dict[str, Any]:
        """
        运行 LLM agent 进行分析（在单个 turn 内完成，但允许多次 LLM 调用）
        
        Args:
            system_prompt: 系统提示
            initial_message: 初始消息
            toolkit: 工具执行器
            tools: 可用工具列表
            conversation_name: 对话名称，用于标识不同的对话
            
        Returns:
            分析结果字典
        """
        # 准备 path_parts 用于保存 conversation
        path_parts = None
        if self._storage_manager and self._repo_name:
            path_parts = (self._repo_name, self._version) if self._version else (self._repo_name,)
        
        # 使用共享的 run_agent_analysis 函数
        is_complete, result, llm_calls, messages = run_agent_analysis(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            initial_message=initial_message,
            tools=tools,
            toolkit=toolkit,
            max_iterations=self.max_agent_iterations,
            update_stats_callback=lambda: self._stats.update({"llm_calls": self._stats["llm_calls"] + 1}),
            storage_manager=self._storage_manager,
            conversation_name=conversation_name,
            path_parts=path_parts,
        )
        
        if is_complete:
            return result
        else:
            # 返回默认值
            logger.warning(f"Agent did not produce valid result after {llm_calls} LLM calls, using defaults")
            return {
                "name": "未知模块",
                "description": "分析未完成",
                "key_functions": [],
                "key_classes": [],
                "external_dependencies": [],
            }
    
    def get_stats(self) -> Dict[str, int]:
        """获取分析统计信息, NOT USED"""
        return self._stats.copy()
