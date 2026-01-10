"""深度分析模块 - 基于 RepoAnalyzer"""

from pathlib import Path
from typing import Dict, Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class DeepAnalyzer:
    """使用 RepoAnalyzer 进行深度静态分析"""
    
    def __init__(
        self,
        language: str = "python",
        max_slice_depth: int = 3,
        max_slice_files: int = 10,
        rebuild_cache: bool = False
    ):
        self.language = language
        self.max_slice_depth = max_slice_depth
        self.max_slice_files = max_slice_files
        self.rebuild_cache = rebuild_cache
        self.repo_analyzer = None
    
    def analyze(
        self, 
        repo_path: Path, 
        cache_dir: Optional[Path] = None
    ) -> Optional[Dict[str, Any]]:
        """
        执行深度分析
        
        Args:
            repo_path: 仓库路径
            cache_dir: 缓存目录
            
        Returns:
            深度分析结果字典，包含:
            - call_graph_edges: 调用图边
            - functions: 函数列表
            - dependencies: 依赖信息
            - entry_points: 入口点列表
            失败返回 None
        """
        logger.info("Running deep static analysis with RepoAnalyzer...")
        logger.info(f"RepoAnalyzer config: language={self.language}, "
                   f"max_slice_depth={self.max_slice_depth}, "
                   f"max_slice_files={self.max_slice_files}, "
                   f"rebuild_cache={self.rebuild_cache}")
        
        try:
            from utils.repo_analyzer import RepoAnalyzer
            
            self.repo_analyzer = RepoAnalyzer(
                repo_path=str(repo_path),
                language=self.language,
                cache_dir=str(cache_dir) if cache_dir else None,
                max_slice_depth=self.max_slice_depth,
                max_slice_files=self.max_slice_files,
                rebuild_cache=self.rebuild_cache
            )
            
            result = self._extract_analysis_info()
            logger.info(f"Deep analysis completed successfully")
            return result
            
        except ImportError as e:
            logger.warning(f"RepoAnalyzer not available: {e}, skipping deep analysis")
            return None
        except Exception as e:
            logger.warning(f"Deep analysis failed: {e}, continuing without deep analysis")
            logger.debug(f"Error details:", exc_info=True)
            return None
    
    def _extract_analysis_info(self) -> Dict[str, Any]:
        """从 RepoAnalyzer 提取深度分析信息"""
        if not self.repo_analyzer:
            return {}
        
        info = {
            'call_graph_edges': [],
            'functions': [],
            'dependencies': [],
            'entry_points': []
        }
        
        # 提取调用图
        try:
            call_graph = self.repo_analyzer.call_graph
            if call_graph:
                info['call_graph_edges'] = [
                    {
                        'caller': edge.caller_name,
                        'caller_file': edge.caller_file,
                        'caller_line': edge.caller_line,
                        'callee': edge.callee_name,
                        'callee_file': edge.callee_file,
                        'callee_line': edge.callee_line,
                        'call_site_line': edge.call_site_line
                    }
                    for edge in call_graph
                ]
                logger.info(f"Extracted {len(info['call_graph_edges'])} call graph edges")
        except Exception as e:
            logger.warning(f"Failed to extract call graph: {e}")
        
        # 提取函数信息
        try:
            functions = self.repo_analyzer.functions
            if functions:
                info['functions'] = [
                    {
                        'name': func.name,
                        'file': func.file,
                        'start_line': func.start_line,
                        'end_line': func.end_line,
                        'parameters': func.parameters,
                        'is_entry_point': func.is_entry_point
                    }
                    for func in list(functions.values())
                ]
                logger.info(f"Extracted {len(info['functions'])} functions")
        except Exception as e:
            logger.warning(f"Failed to extract functions: {e}")
        
        # 提取依赖信息
        try:
            dependencies = self.repo_analyzer.dependencies
            if dependencies:
                info['dependencies'] = [
                    {
                        'name': dep.name,
                        'version': dep.version,
                        'is_builtin': dep.is_builtin,
                        'is_third_party': dep.is_third_party,
                        'import_count': len(dep.import_locations)
                    }
                    for dep in list(dependencies.values())
                ]
                logger.info(f"Extracted {len(info['dependencies'])} dependencies")
        except Exception as e:
            logger.warning(f"Failed to extract dependencies: {e}")
        
        # 提取入口点
        try:
            entry_points = self.repo_analyzer.entry_points
            if entry_points:
                info['entry_points'] = [
                    {
                        'name': ep.name,
                        'file': ep.file,
                        'line': ep.start_line
                    }
                    for ep in entry_points
                ]
                logger.info(f"Extracted {len(info['entry_points'])} entry points")
        except Exception as e:
            logger.warning(f"Failed to extract entry points: {e}")
        
        return info
