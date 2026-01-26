"""Hybrid module analyzer combining Agent- and folder-based approaches.

Workflow:
1. Run the agent-based method to obtain coarse-grained modules.
2. For each coarse-grained module, find the common parent folder of its files/folders.
3. For each common parent folder, apply the folder-based method for fine-grained analysis.
4. Save fine-grained results into separate files.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from llm import BaseLLMClient
from utils.logger import get_logger
from profiler.profile_storage import ProfileStorageManager
from profiler.software.models import FolderModule, ModuleTree

from .agent import ModuleAnalyzer
from .folder import FolderModuleAnalyzer, _build_folder_structure

logger = get_logger(__name__)

def _filter_files_by_folder(all_files: List[str], folder_prefix: str) -> List[str]:
    """
    Filter all files under a given folder.
    
    Args:
        all_files: All files in the repository.
        folder_prefix: Folder prefix.
        
    Returns:
        All files under that folder.
    """
    if not folder_prefix:
        # Repo root: return all files
        return all_files
    
    folder_prefix = folder_prefix.replace("\\", "/").rstrip("/") + "/"
    return [f for f in all_files if f.replace("\\", "/").startswith(folder_prefix)]


class HybridModuleAnalyzer:
    """
    Hybrid module analyzer.
    
    Combines Agent-based (coarse-grained) and folder-based (fine-grained) analysis:
    1. Use the Agent to get a coarse module partition of the repo.
    2. For each module, run folder-based analysis for deeper structure.
    """
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        max_agent_iterations: int = 100,
        max_folder_iterations: int = 10,
        max_file_content_length: int = 8000,
        excluded_folders: List[str] = None,
        code_extensions: List[str] = None,
        skip_empty_folders: bool = True,
        min_files_for_module: int = 1,
    ):
        """
        Initialize the hybrid analyzer.
        
        Args:
            llm_client: LLM client.
            max_agent_iterations: Max iterations for coarse-grained analysis.
            max_folder_iterations: Max iterations per module for fine-grained analysis.
            max_file_content_length: Max length when reading file contents.
            excluded_folders: Folders to exclude.
            code_extensions: Code file extensions.
            skip_empty_folders: Whether to skip empty folders.
            min_files_for_module: Minimum number of files to be considered a module.
        """
        self.llm_client = llm_client
        self.max_agent_iterations = max_agent_iterations
        self.max_folder_iterations = max_folder_iterations
        self.max_file_content_length = max_file_content_length
        self.excluded_folders = excluded_folders
        self.code_extensions = code_extensions
        self.skip_empty_folders = skip_empty_folders
        self.min_files_for_module = min_files_for_module
        
        # Initialize sub-analyzers
        self.agent_analyzer = ModuleAnalyzer(
            llm_client=llm_client,
            max_iterations=max_agent_iterations,
        )
        
        self.folder_analyzer = FolderModuleAnalyzer(
            llm_client=llm_client,
            excluded_folders=excluded_folders,
            code_extensions=code_extensions,
            max_agent_iterations=max_folder_iterations,
            max_file_content_length=max_file_content_length,
            skip_empty_folders=skip_empty_folders,
            min_files_for_module=min_files_for_module,
        )
        
        # Context
        self._storage_manager: Optional[ProfileStorageManager] = None
        self._repo_name: Optional[str] = None
        self._version: Optional[str] = None
        
        # Stats
        self._stats = {
            "coarse_modules_count": 0,
            "fine_modules_count": 0,
            "agent_llm_calls": 0,
            "folder_llm_calls": 0,
        }
    
    def analyze(
        self,
        repo_info: Dict[str, Any],
        repo_path: Path,
        storage_manager: Optional[ProfileStorageManager] = None,
        repo_name: str = None,
        version: str = None,
    ) -> Dict[str, Any]:
        """
        Run hybrid module analysis.
        
        Args:
            repo_info: Repository info (includes files, readme_content, languages, dependencies, etc.).
            repo_path: Repository path.
            storage_manager: Storage manager.
            repo_name: Repository name.
            version: Version string.
            
        Returns:
            {
                "modules": [...],  # Coarse-grained module list (same format as agent output)
                "llm_calls": int,  # Total LLM call count
                "fine_grained_results": {  # Fine-grained module results
                    "module_name": ModuleTree,
                    ...
                }
            }
        """
        repo_path = Path(repo_path)
        repo_name = repo_name or repo_path.name
        
        # Save context
        self._storage_manager = storage_manager
        self._repo_name = repo_name
        self._version = version
        
        logger.info(f"Starting hybrid module analysis for: {repo_name}")
        
        path_parts = (repo_name, version) if version else (repo_name,)
        
        # ==== Step 1: Coarse-grained analysis (Agent method) ====
        logger.info("Step 1: Coarse-grained analysis (Agent method)...")
        
        # Try to load coarse-grained results from a checkpoint
        coarse_result = None
        if storage_manager:
            coarse_result = storage_manager.load_checkpoint("coarse_modules", *path_parts)
        
        if coarse_result:
            logger.info("Loaded coarse modules from checkpoint")
        else:
            
            coarse_result = self.agent_analyzer.analyze(
                repo_info=repo_info,
                repo_path=repo_path,
                storage_manager=storage_manager,
                repo_name=repo_name,
                version=version,
            )
            
            # Save coarse-grained results
            if storage_manager:
                storage_manager.save_checkpoint("coarse_modules", coarse_result, *path_parts)
        
        coarse_modules = coarse_result.get("modules", [])
        self._stats["coarse_modules_count"] = len(coarse_modules)
        self._stats["agent_llm_calls"] = coarse_result.get("llm_calls", 0)
        
        logger.info(f"Identified {len(coarse_modules)} coarse-grained modules")
        
        # ==== Step 2: Fine-grained analysis (Folder-based method) ====
        logger.info("Step 2: Fine-grained analysis (Folder-based method)...")
        
        all_files = repo_info.get("files", [])
        fine_grained_results = {}
        total_folder_llm_calls = 0
        
        for i, module in enumerate(coarse_modules):
            module_name = module.get("name", f"Module_{i}")
            module_paths = module.get("paths", [])  # 这些可能是文件或文件夹路径
            
            logger.info(f"Analyzing module {i+1}/{len(coarse_modules)}: {module_name}")
            logger.info(f"  Module paths: {len(module_paths)}")
            
            # 直接使用 coarse module 列出的 paths，不再寻找 common parent
            # 将这些 paths 作为要分析的文件夹列表
            module_folders = []
            for path in module_paths:
                path = path.replace("\\", "/").rstrip("/")
                # 判断是文件还是文件夹
                last_part = path.rsplit("/", 1)[1] if "/" in path else path
                # 如果包含扩展名，视为文件，取其父文件夹
                if "." in last_part and not last_part.startswith("."):
                    parent = path.rsplit("/", 1)[0] if "/" in path else ""
                    if parent and parent not in module_folders:
                        module_folders.append(parent)
                else:
                    # 视为文件夹
                    if path not in module_folders:
                        module_folders.append(path)
            
            if not module_folders:
                logger.warning(f"  No valid folders found for module: {module_name}")
                continue
            
            logger.info(f"  Analyzing {len(module_folders)} folders")
            
            # 对每个文件夹进行 folder-based 分析
            module_tree = None
            
            # 如果只有一个文件夹，直接分析
            if len(module_folders) == 1:
                folder_path = module_folders[0]
                
                # Try to load from checkpoint
                fine_checkpoint_name = f"fine_module_{i}_{module_name.replace(' ', '_').replace('/', '_')}"
                fine_result = None
                if storage_manager:
                    fine_result = storage_manager.load_checkpoint(fine_checkpoint_name, *path_parts)
                
                if fine_result:
                    logger.info(f"  Loaded fine-grained result from checkpoint")
                    module_tree = ModuleTree.from_dict(fine_result)
                else:
                    # Filter files under this folder
                    folder_files = _filter_files_by_folder(all_files, folder_path)
                    logger.info(f"  Files in folder: {len(folder_files)}")
                    
                    if folder_files:
                        # Analyze this folder
                        module_tree = self._analyze_module_folder(
                            repo_path=repo_path,
                            repo_name=repo_name,
                            module_name=module_name,
                            folder_path=folder_path,
                            file_list=folder_files,
                            version=version,
                        )
                        
                        # Save checkpoint
                        if storage_manager and module_tree:
                            storage_manager.save_checkpoint(
                                fine_checkpoint_name,
                                module_tree.to_dict(),
                                *path_parts
                            )
            else:
                # 多个文件夹：创建一个两级结构，根节点包含多个子模块
                logger.info(f"  Creating two-level structure with {len(module_folders)} sub-modules")
                
                fine_checkpoint_name = f"fine_module_{i}_{module_name.replace(' ', '_').replace('/', '_')}"
                fine_result = None
                if storage_manager:
                    fine_result = storage_manager.load_checkpoint(fine_checkpoint_name, *path_parts)
                
                if fine_result:
                    logger.info(f"  Loaded fine-grained result from checkpoint")
                    module_tree = ModuleTree.from_dict(fine_result)
                else:
                    # 为每个文件夹创建子模块
                    children_modules = []
                    for folder_path in module_folders:
                        folder_files = _filter_files_by_folder(all_files, folder_path)
                        if folder_files:
                            sub_tree = self._analyze_module_folder(
                                repo_path=repo_path,
                                repo_name=repo_name,
                                module_name=f"{module_name}/{folder_path.split('/')[-1]}",
                                folder_path=folder_path,
                                file_list=folder_files,
                                version=version,
                            )
                            if sub_tree and sub_tree.root:
                                children_modules.append(sub_tree.root)
                    
                    if children_modules:
                        # 创建根模块
                        root_module = FolderModule(
                            name=module_name,
                            folder_path="",
                            description=f"Container module for {module_name}",
                            is_leaf=False,
                            children=children_modules,
                            depth=0,
                            full_module_path=module_name,
                        )
                        
                        # 计算统计信息
                        total_modules = sum(1 for _ in root_module.iter_all_modules())
                        total_leaf_modules = sum(1 for m in root_module.iter_all_modules() if m.is_leaf)
                        max_depth = max((m.depth for m in root_module.iter_all_modules()), default=0)
                        
                        module_tree = ModuleTree(
                            root=root_module,
                            repo_name=f"{repo_name}/{module_name}",
                            repo_path=str(repo_path),
                            analysis_timestamp=datetime.now().isoformat(),
                            total_modules=total_modules,
                            total_leaf_modules=total_leaf_modules,
                            max_depth=max_depth,
                            excluded_folders=self.folder_analyzer.excluded_folders,
                            code_extensions=self.folder_analyzer.code_extensions,
                        )
                        
                        # Save checkpoint
                        if storage_manager and module_tree:
                            storage_manager.save_checkpoint(
                                fine_checkpoint_name,
                                module_tree.to_dict(),
                                *path_parts
                            )
            
            if module_tree:
                fine_grained_results[module_name] = module_tree
                total_folder_llm_calls += self.folder_analyzer._stats.get("llm_calls", 0)
        
        self._stats["fine_modules_count"] = sum(
            tree.total_modules for tree in fine_grained_results.values()
        )
        self._stats["folder_llm_calls"] = total_folder_llm_calls
        
        # ==== Step 3: Save fine-grained results ====
        if storage_manager:
            self._save_fine_grained_results(fine_grained_results, path_parts)
        
        # Log stats
        total_llm_calls = self._stats["agent_llm_calls"] + self._stats["folder_llm_calls"]
        logger.info(f"Hybrid analysis complete!")
        logger.info(f"  Coarse modules: {self._stats['coarse_modules_count']}")
        logger.info(f"  Fine modules: {self._stats['fine_modules_count']}")
        logger.info(f"  Total LLM calls: {total_llm_calls}")
        
        return {
            "modules": coarse_modules,
            "llm_calls": total_llm_calls,
            "fine_grained_results": fine_grained_results,
        }
    
    def _analyze_module_folder(
        self,
        repo_path: Path,
        repo_name: str,
        module_name: str,
        folder_path: str,
        file_list: List[str],
        version: str = None,
    ) -> Optional[ModuleTree]:
        """
        Analyze a single module folder using the folder-based method.
        
        Args:
            repo_path: Repository path.
            repo_name: Repository name.
            module_name: Module name.
            folder_path: Folder path to analyze.
            file_list: List of files under this folder.
            version: Version string.
            
        Returns:
            A ModuleTree, or None.
        """
        # Reset folder analyzer stats
        self.folder_analyzer._stats = {
            "total_folders_scanned": 0,
            "total_modules_created": 0,
            "leaf_modules": 0,
            "container_modules": 0,
            "skipped_folders": 0,
            "llm_calls": 0,
        }
        
        # Set storage context for the folder analyzer
        self.folder_analyzer._storage_manager = self._storage_manager
        self.folder_analyzer._repo_name = repo_name
        self.folder_analyzer._version = version
        
        # Build folder structure
        folder_structure = _build_folder_structure(file_list)
        
        logger.debug(f"Folder structure for {module_name}: {len(folder_structure)} folders")
        
        # Analyze starting from the specified folder
        root_module = self.folder_analyzer._analyze_folder(
            repo_path=repo_path,
            repo_name=f"{repo_name}/{module_name}",
            folder_path=folder_path,
            folder_structure=folder_structure,
            file_list=file_list,
            depth=0,
            parent_path="",
        )
        
        if not root_module:
            logger.warning(f"No module tree generated for: {module_name}")
            return None
        
        # Compute stats
        total_modules = 0
        leaf_modules = 0
        max_depth = 0
        
        for module in root_module.iter_all_modules():
            total_modules += 1
            if module.is_leaf:
                leaf_modules += 1
            max_depth = max(max_depth, module.depth)
        
        # Build ModuleTree
        module_tree = ModuleTree(
            root=root_module,
            repo_name=f"{repo_name}/{module_name}",
            repo_path=str(repo_path),
            analysis_timestamp=datetime.now().isoformat(),
            total_modules=total_modules,
            total_leaf_modules=leaf_modules,
            max_depth=max_depth,
            excluded_folders=self.folder_analyzer.excluded_folders,
            code_extensions=self.folder_analyzer.code_extensions,
        )
        
        return module_tree
    
    def _save_fine_grained_results(
        self,
        fine_grained_results: Dict[str, ModuleTree],
        path_parts: tuple,
    ) -> None:
        """
        Save fine-grained analysis results to a separate file.
        
        Args:
            fine_grained_results: Fine-grained results dict {module_name: ModuleTree}.
            path_parts: Path components.
        """
        if not self._storage_manager:
            return
        
        # Save fine-grained results per module
        fine_grained_dict = {}
        for module_name, module_tree in fine_grained_results.items():
            fine_grained_dict[module_name] = module_tree.to_dict()
        
        # Save summary file
        result_data = {
            "analysis_timestamp": datetime.now().isoformat(),
            "coarse_module_count": len(fine_grained_results),
            "total_fine_modules": sum(tree.total_modules for tree in fine_grained_results.values()),
            "modules": fine_grained_dict,
        }
        
        self._storage_manager.save_final_result(
            "fine_grained_modules.json",
            json.dumps(result_data, ensure_ascii=False, indent=2),
            *path_parts
        )
        
        logger.info(f"Saved fine-grained results to fine_grained_modules.json")
    
    def get_stats(self) -> Dict[str, int]:
        """Get analysis statistics."""
        return self._stats.copy()
