"""
Software Profile Generator (Refactored)

轻量级协调器 - 将各个分析步骤委托给专门的模块。
"""

import yaml
import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from llm import BaseLLMClient, create_llm_client, LLMConfig
from config import _path_config
from profiler.profile_storage import ProfileStorageManager
from utils.git_utils import get_git_commit, checkout_commit
from utils.logger import get_logger

from .models import SoftwareProfile, ModuleInfo, DataFlowPattern
from .repo_collector import RepoInfoCollector
from .basic_info_analyzer import BasicInfoAnalyzer
from .module_analyzer import ModuleAnalyzer, SkillModuleAnalyzer

from .file_summarizer import FileSummarizer
from .repo_analyzer import RepoAnalyzer

logger = get_logger(__name__)


class SoftwareProfiler:
    """软件画像生成器 - 协调各个分析组件"""
    
    _detection_rules = None
    _rules_lock = threading.Lock()
    _C_API_ALIASES = {
        "open": {"fopen"},
        "read": {"fread"},
        "write": {"fwrite"},
        "close": {"fclose"},
        "socket": {"recv", "send", "accept", "connect"},
    }
    
    @classmethod
    def _load_detection_rules(cls, rules_path: Path = None, output_dir: Path = None) -> Dict[str, Any]:
        """加载检测规则配置文件"""
        _empty_rule = {'data_sources': {}, 'data_formats': {}, 'processing_operations': {}}
        with cls._rules_lock:
            if cls._detection_rules is not None:
                return cls._detection_rules
            
            if rules_path is None:
                rules_path = _path_config['repo_root'] / "config" / "software_profile_rule.yaml"
                if output_dir and Path(output_dir).exists():
                    save_config_path = Path(output_dir) / "software_profile_rule.yaml"
                    if save_config_path.exists():
                        logger.info(f"Loading saved config from: {save_config_path}")
                        rules_path = save_config_path
            try:
                if rules_path.exists():
                    with open(rules_path, 'r', encoding='utf-8') as f:
                        cls._detection_rules = yaml.safe_load(f)
                    logger.info(f"Loaded detection rules from {rules_path}")
                else:
                    logger.warning(f"Detection rules file not found: {rules_path}")
                    cls._detection_rules = _empty_rule
            except Exception as e:
                logger.error(f"Failed to load detection rules: {e}")
                cls._detection_rules = _empty_rule
            return cls._detection_rules
    
    def _save_config_to_output_dir(self):
        """将当前配置保存到输出目录"""
        if not self.output_dir:
            return
        
        try:
            config_save_path = self.output_dir / "software_profile_rule.yaml"
            # 直接保存完整的配置，确保所有内容都被保存
            with open(config_save_path, 'w', encoding='utf-8') as f:
                yaml.dump(self._detection_rules, f, allow_unicode=True, default_flow_style=False)
            
            logger.info(f"Saved configuration to: {config_save_path}")
        except Exception as e:
            logger.warning(f"Failed to save config: {e}")
    
    def __init__(
        self,
        llm_client: BaseLLMClient = None,
        output_dir: str = None,
        rules_path: Path = None,
        file_extensions: List[str] = None,
        exclude_dirs: List[str] = None
    ):
        """初始化软件画像生成器"""
        self.llm_client = llm_client

        # 设置输出目录和存储管理器
        self.output_dir = Path(output_dir) if output_dir else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.storage_manager = ProfileStorageManager(str(self.output_dir), profile_type="software")
        else:
            self.storage_manager = None
        
        # 加载配置
        all_config = self._load_detection_rules(rules_path, output_dir=self.output_dir)
        self.detection_rules = {
            'data_sources': all_config.get('data_sources', {}),
            'data_formats': all_config.get('data_formats', {}),
            'processing_operations': all_config.get('processing_operations', {}),
        }
        
        # 分析器配置
        analyzer_config = all_config.get('analyzer_config', {})
        self.file_extensions = file_extensions or analyzer_config.get('file_extensions', [
            ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".rs"
        ])
        self.exclude_dirs = exclude_dirs or analyzer_config.get('exclude_dirs', [
            "__pycache__", "node_modules", ".git", ".venv", "venv", "env",
            "build", "dist", ".eggs", "*.egg-info"
        ])
        
        # 文件摘要配置

        self.file_summary_llm_config = analyzer_config.get('file_summary_llm', {})
        self.file_summary_llm_client = None
        self.enable_llm_file_summary = self.file_summary_llm_config.get('enabled', False)

        if self.enable_llm_file_summary:
            try:
                llm_config = LLMConfig(
                    provider=self.file_summary_llm_config.get('provider', 'deepseek'),
                    model=self.file_summary_llm_config.get('model', ''),
                    temperature=self.file_summary_llm_config.get('temperature', 0.7),
                    max_tokens=self.file_summary_llm_config.get('max_tokens', 131072),
                )
                self.file_summary_llm_client = create_llm_client(llm_config)
                logger.info(f"Initialized file summary LLM: {llm_config.provider}/{llm_config.model or 'default'}")
            except Exception as e:
                logger.warning(f"Failed to initialize file summary LLM: {e}")
                self.file_summary_llm_client = None
        
        # RepoAnalyzer配置
        self.repo_analyzer_config = all_config.get('repo_analyzer_config', {})

        # 模块分析器配置
        self.module_analyzer_config = all_config.get('module_analyzer_config', {})
        
        # 仓库文件配置
        repo_files_config = all_config.get('repo_files', {})
        self.readme_files = repo_files_config.get('readme_files', [
            "README.md", "README.rst", "README.txt", "README"
        ])
        self.dependency_files = repo_files_config.get('dependency_files', [
            "pyproject.toml", "setup.py", "setup.cfg", "package.json"
        ])
        
        # 初始化分析器组件
        self._init_analyzers()
    
    def _init_analyzers(self):
        """初始化各个分析器组件"""
        # 仓库信息收集器
        self.repo_collector = RepoInfoCollector(
            file_extensions=self.file_extensions,
            exclude_dirs=self.exclude_dirs,
            readme_files=self.readme_files,
            dependency_files=self.dependency_files
        )
        
        # 基本信息分析器
        self.basic_info_analyzer = BasicInfoAnalyzer(
            llm_client=self.llm_client,
        )
        
        # 模块分析器 - 根据配置选择类型: 'skill' 或 'agent'
        analyzer_type = self.module_analyzer_config.get('analyzer_type', 'skill')
        
        # 初始化分析器引用为 None
        self.module_analyzer = None
        
        if analyzer_type == 'skill':
            logger.info("Using skill-based module analyzer (AI infra taxonomy)")
            self.module_analyzer = SkillModuleAnalyzer(
                llm_client=self.llm_client,
                excluded_folders=self.module_analyzer_config.get('excluded_folders') or None,
                code_extensions=self.module_analyzer_config.get('code_extensions') or None,
                max_key_functions=self.module_analyzer_config.get('skill_max_key_functions', 12),
            )
        else:  # 'agent' or default
            logger.info("Using agent-based module analyzer")
            max_agent_iterations = self.module_analyzer_config.get('max_agent_iterations', 100)
            self.module_analyzer = ModuleAnalyzer(
                llm_client=self.llm_client,
                max_iterations=max_agent_iterations
            )
        
        # 文件摘要器
        summary_llm = self.file_summary_llm_client or self.llm_client
        self.file_summarizer = FileSummarizer(llm_client=summary_llm)

    
    def generate_profile(
        self,
        repo_path: str,
        force_full_analysis: bool = False,
        target_version: str = None
    ) -> SoftwareProfile:
        """生成完整的软件画像"""
        repo_path = Path(repo_path)
        repo_name = repo_path.name
        
        logger.info(f"Starting profile generation for: {repo_name}")
        self._save_config_to_output_dir()
        
        # 获取版本信息
        original_version = get_git_commit(str(repo_path))
        changed_commit = False
        if target_version:
            logger.info(f"Target version: {target_version[:8]}...")
            if original_version != target_version:
                logger.info(f"Checking out to target version...")
                if not checkout_commit(str(repo_path), target_version):
                    raise RuntimeError(f"Failed to checkout to: {target_version}")
                changed_commit = True
        try:
            version = target_version if target_version else original_version
            
            if version:
                logger.info(f"Git commit hash: {version[:8]}...")
            else:
                logger.warning("Could not get git commit hash, using 'unknown'")
                version = "unknown"
            
            # 加载或创建 profile_info
            profile_info = self.storage_manager.load_profile_info(repo_name) if self.storage_manager else None
            is_first_run = (profile_info is None)
            
            if is_first_run:
                logger.info("First run detected, performing full analysis")
                profile_info = {
                    "repo_name": repo_name,
                    "base_commit": version,
                    "first_analysis_date": datetime.now().isoformat(),
                    "llm_config": {
                        "model": self.llm_client.config.model if self.llm_client else "none",
                        "temperature": self.llm_client.config.temperature if self.llm_client else 0.0,
                    } if self.llm_client else {},
                    "analysis_history": [{
                        "version": version,
                        "date": datetime.now().isoformat(),
                        "type": "full_analysis"
                    }]
                }
                if self.storage_manager:
                    self.storage_manager.save_profile_info(profile_info, repo_name)
            else:
                base_commit = profile_info.get("base_commit")
                logger.info(f"Found existing profile. Base commit: {base_commit[:8] if base_commit else 'N/A'}...")
            
            # 检查是否已有完成的画像
            if self.storage_manager and not force_full_analysis:
                path_parts = (repo_name, version) if version else (repo_name,)
                existing_profile_json = self.storage_manager.load_final_result("software_profile.json", *path_parts)
                if existing_profile_json:
                    logger.info(f"Found completed profile, loading from cache...")
                    existing_profile = json.loads(existing_profile_json)
                    return SoftwareProfile.from_dict(existing_profile)
            
            logger.info("Performing full analysis...")
            profile = self._generate_profile_full(repo_path, repo_name, version)
            
            # 更新分析历史
            if not is_first_run:
                if "analysis_history" not in profile_info:
                    profile_info["analysis_history"] = []
                profile_info["analysis_history"].append({
                    "version": version,
                    "date": datetime.now().isoformat(),
                    "type": "full_analysis"
                })
                if self.storage_manager:
                    self.storage_manager.save_profile_info(profile_info, repo_name)
            
            logger.info(f"Profile generation completed for: {repo_name}")
            return profile
        finally:
            if changed_commit and original_version:
                restored = checkout_commit(str(repo_path), original_version)
                if restored:
                    logger.info(f"Restored repository to original version: {original_version[:8]}...")
                else:
                    logger.error(f"Failed to restore repository to original version: {original_version[:8]}...")
    
    def _generate_profile_full(self, repo_path: Path, repo_name: str, version: str) -> SoftwareProfile:
        """执行完整的profile分析"""
        path_parts = (repo_name, version) if version else (repo_name,)
        
        # Step 1: 收集仓库信息
        logger.info("Step 1/4: Collecting repo info...")
        repo_info = None
        if self.storage_manager:
            repo_info = self.storage_manager.load_checkpoint("repo_info", *path_parts)
        
        if repo_info:
            logger.info("Loaded repo_info from checkpoint")
        else:
            repo_info = self.repo_collector.collect(repo_path)
            repo_info['commit_hash'] = version
            
            # 文件摘要
            if self.enable_llm_file_summary:
                logger.info("Generating file summaries with LLM...")
                file_summaries = self.file_summarizer.summarize_files(
                    repo_path,
                    repo_info['files'],
                    storage_manager=self.storage_manager,
                    repo_name=repo_name,
                    version=version,
                )
                repo_info['file_summaries'] = file_summaries
            else:
                repo_info['file_summaries'] = {}
            
            # CodeQL分析
            
            logger.info("Performing deep static analysis...")
            cache_dir = self.output_dir / repo_name / ".cache" / "repo_analyzer" if self.output_dir else None
                
            self.repo_analyzer = RepoAnalyzer(
                repo_path=str(repo_path),
                languages=self.repo_analyzer_config.get('languages'),
                cache_dir=str(cache_dir) if cache_dir else None,
                max_slice_depth=self.repo_analyzer_config.get('max_slice_depth'),
                max_slice_files=self.repo_analyzer_config.get('max_slice_files'),
                rebuild_cache=self.repo_analyzer_config.get('rebuild_cache')
            )

            repo_info['repo_analysis'] = self.repo_analyzer.get_info()
            
            if self.storage_manager:
                self.storage_manager.save_checkpoint("repo_info", repo_info, *path_parts)
        
        # Step 2: 分析基本信息
        logger.info("Step 2/4: Analyzing basic info...")
        basic_info = self.storage_manager.load_checkpoint("basic_info", *path_parts) if self.storage_manager else None
        if basic_info:
            logger.info("Loaded basic_info from checkpoint")
        else:
            basic_info = self.basic_info_analyzer.analyze(
                repo_path, repo_info, repo_name, version, storage_manager=self.storage_manager
            )
            if self.storage_manager:
                self.storage_manager.save_checkpoint("basic_info", basic_info, *path_parts)
        
        # Step 3: 分析模块
        logger.info("Step 3/4: Analyzing modules...")
        modules_result = self.storage_manager.load_checkpoint("modules", *path_parts) if self.storage_manager else None
        
        if modules_result and modules_result.get('modules'):
            logger.info("Loaded modules from checkpoint")
        else:
            if modules_result and not modules_result.get('modules'):
                logger.warning("Loaded modules checkpoint is empty, re-analyzing...")
            # 使用当前配置的模块分析器（skill 或 agent）
            modules_result = self.module_analyzer.analyze(
                repo_info, 
                repo_path,
                storage_manager=self.storage_manager,
                repo_name=repo_name,
                version=version
            )
            
            if self.storage_manager:
                self.storage_manager.save_checkpoint("modules", modules_result, *path_parts)
            
        # Step 4: 构建软件画像
        logger.info("Step 4/4: Building software profile...")
        profile = SoftwareProfile(
            name=repo_name,
            version=version,
            description=basic_info.get("description", ""),
            target_application=basic_info.get("target_application", []),
            target_user=basic_info.get("target_user", []),
            repo_info=repo_info,
            modules=modules_result.get('modules', []) if modules_result else [],
        )
        
        # 如果有 CodeQL 静态分析结果，增强profile
        if repo_info.get('repo_analysis'):
            logger.info("Enhancing profile with repo analysis...")

            
            base_modules = modules_result.get('modules', []) if modules_result else []
            logger.debug(f"[DEBUG] Base modules: {len(base_modules)}, first type: {type(base_modules[0]).__name__ if base_modules else 'N/A'}")
            modules = self._enhance_modules_with_repo_analysis(
                base_modules,
                repo_info['repo_analysis'],
                repo_files=repo_info.get('files', []),
            )
            logger.debug(f"[DEBUG] Enhanced modules: {len(modules)}, first type: {type(modules[0]).__name__ if modules else 'N/A'}")
            if modules:
                logger.debug(f"[DEBUG] First module enhanced data - external_deps: {len(modules[0].external_dependencies)}, called_by: {len(modules[0].called_by_modules)}, calls: {len(modules[0].calls_modules)}")
            profile.modules = modules
            logger.debug(f"[DEBUG] Profile.modules after assignment: {len(profile.modules)}, type: {type(profile.modules[0]).__name__ if profile.modules else 'N/A'}")
            
            # 提取数据流模式
            data_flow_patterns = self._extract_data_flow_patterns(modules, repo_info['repo_analysis'])
            profile.data_flow_patterns = data_flow_patterns
            
            project_features = self._extract_project_level_features(modules, repo_info['repo_analysis'])
            profile.common_data_sources = project_features.get('common_data_sources', [])
            profile.common_data_formats = project_features.get('common_data_formats', [])
            profile.third_party_libraries = project_features.get('third_party_libraries', [])
            profile.builtin_libraries = project_features.get('builtin_libraries', [])
            profile.dependency_usage_count = project_features.get('dependency_usage_count', {})
            profile.total_functions = project_features.get('total_functions', 0)
        
        # 保存最终画像
        if self.storage_manager:
            logger.debug(f"[DEBUG] Before saving (_generate_profile_full) - profile.modules: {len(profile.modules)}, type: {type(profile.modules[0]).__name__ if profile.modules else 'N/A'}")
            if profile.modules and hasattr(profile.modules[0], 'external_dependencies'):
                logger.debug(f"[DEBUG] First module before save - external_deps: {len(profile.modules[0].external_dependencies)}, called_by: {len(profile.modules[0].called_by_modules)}")
            self.storage_manager.save_final_result("software_profile.json", profile.to_json(), *path_parts)
        
        return profile
    

    def _enhance_modules_with_repo_analysis(
        self,
        base_modules: List[Dict],
        repo_analysis: Dict,
        repo_files: Optional[List[str]] = None,
    ) -> List[ModuleInfo]:
        """用 CodeQL 静态分析数据增强模块信息"""
        modules = []
        
        # 构建文件到函数列表的映射（一个文件可能包含多个函数）
        functions_by_file: Dict[str, List[Dict]] = {}
        for func in repo_analysis.get('functions', []):
            file_path = func.get('file', '')
            if file_path:
                if file_path not in functions_by_file:
                    functions_by_file[file_path] = []
                functions_by_file[file_path].append(func)
        
        call_graph_edges = repo_analysis.get('call_graph_edges', [])
        dependencies = repo_analysis.get('dependencies', [])
        normalized_repo_files: List[str] = []
        for raw_file in (repo_files or []):
            if not isinstance(raw_file, str):
                continue
            file_path = raw_file.replace('\\', '/').strip()
            if file_path:
                normalized_repo_files.append(file_path)
        all_files = sorted(set(functions_by_file.keys()) | set(normalized_repo_files))
        all_files_set = set(all_files)
        
        # 构建模块名到文件的映射
        module_name_to_files = {}
        for module in base_modules:
            module_paths = module.get('files', [])
            module_files = []
            module_file_set = set()
            for raw_path in module_paths:
                if not isinstance(raw_path, str):
                    continue

                path = raw_path.replace('\\', '/').strip().rstrip('/')
                if not path:
                    # LLM output may contain empty path entries; ignore them.
                    continue

                # Prefer exact file matching so extensionless files (e.g. Makefile) are handled correctly.
                if path in all_files_set:
                    if path not in module_file_set:
                        module_files.append(path)
                        module_file_set.add(path)
                    continue

                folder_prefix = path + '/'
                for file_path in all_files:
                    if file_path.startswith(folder_prefix) and file_path not in module_file_set:
                        module_files.append(file_path)
                        module_file_set.add(file_path)
            module_name_to_files[module.get('name', '')] = module_files
        
        # 构建文件到模块的映射
        file_to_module = {}
        for module_name, files in module_name_to_files.items():
            for file in files:
                file_to_module[file] = module_name

        # 按文件索引调用边，避免在模块循环中重复全量扫描 call_graph_edges。
        edges_by_file: Dict[str, List[Dict]] = {}
        for edge in call_graph_edges:
            caller_file = edge.get('caller_file', '')
            callee_file = edge.get('callee_file', '')
            if caller_file:
                edges_by_file.setdefault(caller_file, []).append(edge)
            if callee_file and callee_file != caller_file:
                edges_by_file.setdefault(callee_file, []).append(edge)
        
        # 构建依赖关系图（外部依赖）
        dependencies_by_file = {}
        for dep in dependencies:
            dep_name = dep.get('name', '')
            is_third_party = dep.get('is_third_party', False)
            is_builtin = dep.get('is_builtin', False)
            import_files = dep.get('import_files', [])
            
            if is_third_party or is_builtin:
                # 如果有import_files信息，使用精确匹配
                if import_files:
                    for file in import_files:
                        if file not in dependencies_by_file:
                            dependencies_by_file[file] = []
                        if dep_name not in dependencies_by_file[file]:
                            dependencies_by_file[file].append(dep_name)
                else:
                    # 如果没有import_files信息，假设所有文件都可能使用（保持向后兼容）
                    for file in all_files:
                        if file not in dependencies_by_file:
                            dependencies_by_file[file] = []
                        if dep_name not in dependencies_by_file[file]:
                            dependencies_by_file[file].append(dep_name)
        
        for module in base_modules:
            module_name = module.get('name', '')
            module_files = module_name_to_files.get(module_name, [])
            module_file_set = set(module_files)
            
            # 提取模块级别的函数和调用图
            module_functions = []
            module_call_graph = []
            
            for file_path in module_file_set:
                # 直接添加该文件中的所有函数
                if file_path in functions_by_file:
                    module_functions.extend(functions_by_file[file_path])

            seen_module_edges = set()
            for file_path in module_file_set:
                for edge in edges_by_file.get(file_path, []):
                    edge_key = (
                        edge.get('caller', ''),
                        edge.get('caller_file', ''),
                        edge.get('caller_line', 0),
                        edge.get('callee', ''),
                        edge.get('callee_file', ''),
                        edge.get('callee_line', 0),
                        edge.get('call_site_line', 0),
                    )
                    if edge_key in seen_module_edges:
                        continue
                    seen_module_edges.add(edge_key)
                    module_call_graph.append(edge)
            
            # 函数名 + 该模块函数调用的 API 名称（例如 C/C++ stdlib）共同参与模式检测
            pattern_candidates = list(module_functions)
            outgoing_callee_names = set()
            for edge in module_call_graph:
                if edge.get('caller_file', '') not in module_file_set:
                    continue
                callee_name = edge.get('callee', '')
                if callee_name and callee_name != '<module>':
                    outgoing_callee_names.add(callee_name)

            for callee_name in sorted(outgoing_callee_names):
                pattern_candidates.append({'name': callee_name})

            # 检测数据流模式
            data_sources = self._detect_patterns(pattern_candidates, 'data_sources')
            data_formats = self._detect_patterns(pattern_candidates, 'data_formats')
            processing_operations = self._detect_patterns(pattern_candidates, 'processing_operations')
            
            # 提取外部依赖
            external_dependencies = set()
            for file in module_files:
                if file in dependencies_by_file:
                    external_dependencies.update(dependencies_by_file[file])
            
            # 计算模块间的调用关系
            called_by_modules = set()
            calls_modules = set()
            
            for edge in call_graph_edges:
                caller_file = edge.get('caller_file', '')
                callee_file = edge.get('callee_file', '')
                
                # 如果当前模块的文件被调用
                if callee_file in module_file_set and caller_file in file_to_module:
                    caller_module = file_to_module[caller_file]
                    if caller_module != module_name:
                        called_by_modules.add(caller_module)
                
                # 如果当前模块调用了其他模块
                if caller_file in module_file_set and callee_file in file_to_module:
                    callee_module = file_to_module[callee_file]
                    if callee_module != module_name:
                        calls_modules.add(callee_module)

            # 统一 internal_dependencies 与 calls_modules 的来源，避免路径映射不一致。
            base_internal_dependencies = module.get('dependencies', [])
            if not isinstance(base_internal_dependencies, list):
                base_internal_dependencies = []
            internal_dependencies = set(calls_modules)
            for dep_name in base_internal_dependencies:
                if not isinstance(dep_name, str):
                    continue
                normalized_dep_name = dep_name.strip()
                if not normalized_dep_name or normalized_dep_name == module_name:
                    continue
                if normalized_dep_name in module_name_to_files:
                    internal_dependencies.add(normalized_dep_name)
            
            enhanced_module = ModuleInfo(
                name=module_name,
                category=module.get('category', ''),
                description=module.get('description', ''),
                files=module_files,
                key_functions=module.get('key_functions', []),
                data_sources=data_sources,
                data_formats=data_formats,
                processing_operations=processing_operations,
                external_dependencies=sorted(list(external_dependencies)),
                internal_dependencies=sorted(list(internal_dependencies)),
                called_by_modules=sorted(list(called_by_modules)),
                calls_modules=sorted(list(calls_modules))
            )
            modules.append(enhanced_module)
        
        return modules
    
    def _detect_patterns(self, functions: List[Dict], pattern_type: str) -> List[str]:
        """检测特定类型的模式"""
        patterns = set()
        rules = self.detection_rules.get(pattern_type, {})
        
        # 基于规则的检测
        for func in functions:
            func_name = func.get('name', '')
            if not func_name:
                continue
            for pattern_name, pattern_config in rules.items():
                keywords = self._extract_rule_keywords(pattern_config)
                if any(self._matches_keyword(func_name, keyword) for keyword in keywords):
                    patterns.add(pattern_name)
        
        return sorted(patterns)

    @staticmethod
    def _extract_rule_keywords(pattern_config: Any) -> List[str]:
        """统一提取规则关键词（兼容 list 和 {keywords: [...]} 两种格式）。"""
        if isinstance(pattern_config, list):
            return [kw for kw in pattern_config if isinstance(kw, str)]
        if isinstance(pattern_config, dict):
            return [kw for kw in pattern_config.get('keywords', []) if isinstance(kw, str)]
        return []

    @staticmethod
    def _normalize_keyword(keyword: str) -> str:
        """标准化规则关键词，兼容 open( / Path( / .json / requests. 这类写法。"""
        normalized = keyword.strip().lower()
        while normalized.endswith("("):
            normalized = normalized[:-1].strip()
        while normalized.endswith(")"):
            normalized = normalized[:-1].strip()
        normalized = normalized.strip(".")
        return normalized

    @staticmethod
    def _split_identifier_tokens(text: str) -> List[str]:
        """按分隔符与驼峰切分标识符。"""
        if not text:
            return []

        chunks = re.split(r"[^0-9A-Za-z]+", text)
        tokens = []
        for chunk in chunks:
            if not chunk:
                continue
            matches = re.findall(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+", chunk)
            if matches:
                tokens.extend(match.lower() for match in matches if match)
            else:
                tokens.append(chunk.lower())
        return tokens

    @staticmethod
    def _contains_token_sequence(tokens: List[str], keyword_tokens: List[str]) -> bool:
        """检查 keyword_tokens 是否以连续子序列出现在 tokens 中。"""
        if not tokens or not keyword_tokens or len(keyword_tokens) > len(tokens):
            return False

        window = len(keyword_tokens)
        for idx in range(len(tokens) - window + 1):
            if tokens[idx:idx + window] == keyword_tokens:
                return True
        return False

    def _matches_keyword(self, candidate_name: str, keyword: str) -> bool:
        """规则关键词与函数/API 名的匹配，优先词级匹配，避免子串误报。"""
        if not candidate_name or not keyword:
            return False

        normalized_keyword = self._normalize_keyword(keyword)
        if not normalized_keyword:
            return False

        candidate = candidate_name.strip()
        if not candidate:
            return False

        candidate_lower = candidate.lower()
        if candidate_lower == normalized_keyword:
            return True

        candidate_tokens = self._split_identifier_tokens(candidate)
        keyword_tokens = self._split_identifier_tokens(normalized_keyword)
        if keyword_tokens and self._contains_token_sequence(candidate_tokens, keyword_tokens):
            return True

        if len(keyword_tokens) == 1:
            alias_candidates = self._C_API_ALIASES.get(keyword_tokens[0], set())
            if alias_candidates and any(alias in candidate_tokens for alias in alias_candidates):
                return True

        # 复杂符号关键词（如 "json.load"）回退到字面包含匹配
        if any(sep in normalized_keyword for sep in (".", "::", "/", "\\")):
            return normalized_keyword in candidate_lower

        # 单词关键词使用边界匹配，避免 map->bitmap、read->thread 误报
        if len(keyword_tokens) == 1:
            escaped = re.escape(keyword_tokens[0])
            return bool(re.search(rf"(^|[^a-z0-9]){escaped}([^a-z0-9]|$)", candidate_lower))

        return False

    @staticmethod
    def _build_function_ref(file_path: str, func_name: str, line: Any = 0) -> str:
        """Build a stable function reference used in data-flow pattern extraction."""
        if not file_path or not func_name:
            return ""
        try:
            line_num = int(line or 0)
        except (TypeError, ValueError):
            line_num = 0
        if line_num > 0:
            return f"{file_path}::{func_name}@{line_num}"
        return f"{file_path}::{func_name}"
    
    def _extract_data_flow_patterns(
        self,
        modules: List[ModuleInfo],
        repo_analysis: Dict
    ) -> List[DataFlowPattern]:
        """extract data flow patterns from modules and repo analysis"""
        patterns = []
        
        # 构建文件到函数列表的映射（一个文件可能包含多个函数）
        functions_by_file: Dict[str, List[Dict]] = {}
        for func in repo_analysis.get('functions', []):
            file_path = func.get('file', '')
            if file_path:
                if file_path not in functions_by_file:
                    functions_by_file[file_path] = []
                functions_by_file[file_path].append(func)
        
        call_graph_edges = repo_analysis.get('call_graph_edges', [])
        
        # 构建模块级别的数据流模式
        for module in modules:
            if not module.data_sources or not module.data_formats:
                continue
            
            # module.files 已经在 _enhance_modules_with_repo_analysis 中展开过了
            # 查找源API和汇API
            source_apis = []
            sink_apis = []
            intermediate_ops = []
            file_paths = module.files

            called_apis_by_function = {}
            for edge in call_graph_edges:
                caller_file = edge.get('caller_file', '')
                if caller_file not in file_paths:
                    continue
                callee_name = edge.get('callee', '')
                if not callee_name or callee_name == '<module>':
                    continue
                caller_key = edge.get('caller_id') or self._build_function_ref(
                    caller_file,
                    edge.get('caller', ''),
                    edge.get('caller_line', 0),
                )
                if not caller_key:
                    continue
                if caller_key not in called_apis_by_function:
                    called_apis_by_function[caller_key] = set()
                called_apis_by_function[caller_key].add(callee_name)
            
            # 从模块的函数中提取相关API
            module_functions = {}  # {function_ref: func_info}
            for file_path in module.files:
                if file_path in functions_by_file:
                    for func in functions_by_file[file_path]:
                        func_name = func.get('name', '')
                        func_key = (
                            func.get('function_id')
                            or self._build_function_ref(file_path, func_name, func.get('start_line', 0))
                        )
                        if not func_key:
                            continue
                        module_functions[func_key] = func
                        candidate_names = [func_name]
                        candidate_names.extend(sorted(called_apis_by_function.get(func_key, set())))
                        
                        # 根据数据源识别源API
                        for data_source in module.data_sources:
                            source_rules = self.detection_rules.get('data_sources', {}).get(data_source, {})
                            keywords = self._extract_rule_keywords(source_rules)
                            if any(
                                self._matches_keyword(candidate_name, keyword)
                                for candidate_name in candidate_names
                                for keyword in keywords
                            ):
                                if func_key not in source_apis:
                                    source_apis.append(func_key)
                        
                        # 根据数据格式识别汇API
                        for data_format in module.data_formats:
                            format_rules = self.detection_rules.get('data_formats', {}).get(data_format, {})
                            keywords = self._extract_rule_keywords(format_rules)
                            if any(
                                self._matches_keyword(candidate_name, keyword)
                                for candidate_name in candidate_names
                                for keyword in keywords
                            ):
                                if func_key not in sink_apis:
                                    sink_apis.append(func_key)
                        
                        # 识别中间处理操作
                        for proc_op in module.processing_operations:
                            proc_rules = self.detection_rules.get('processing_operations', {}).get(proc_op, {})
                            keywords = self._extract_rule_keywords(proc_rules)
                            if any(
                                self._matches_keyword(candidate_name, keyword)
                                for candidate_name in candidate_names
                                for keyword in keywords
                            ):
                                if func_key not in intermediate_ops:
                                    intermediate_ops.append(func_key)
            
            # 利用调用图边来追踪数据流路径
            # 找出源API到汇API之间的中间调用
            for edge in call_graph_edges:
                caller_file = edge.get('caller_file', '')
                caller_func = edge.get('caller', '')  # 字段名是 'caller' 而非 'caller_function'
                callee_file = edge.get('callee_file', '')
                callee_func = edge.get('callee', '')  # 字段名是 'callee' 而非 'callee_function'
                
                caller_key = edge.get('caller_id') or self._build_function_ref(
                    caller_file,
                    caller_func,
                    edge.get('caller_line', 0),
                )
                callee_key = edge.get('callee_id') or self._build_function_ref(
                    callee_file,
                    callee_func,
                    edge.get('callee_line', 0),
                )
                
                # 如果调用者或被调用者在模块内
                if caller_key in module_functions or callee_key in module_functions:
                    # 如果这条边连接了源API和其他函数，将其他函数加入中间操作
                    if caller_key in source_apis and callee_key in module_functions:
                        if callee_key not in source_apis and callee_key not in sink_apis and callee_key not in intermediate_ops:
                            intermediate_ops.append(callee_key)
                    
                    # 如果这条边连接了某个函数和汇API，将该函数加入中间操作
                    if callee_key in sink_apis and caller_key in module_functions:
                        if caller_key not in source_apis and caller_key not in sink_apis and caller_key not in intermediate_ops:
                            intermediate_ops.append(caller_key)
            
            # 构建数据流模式
            if source_apis or sink_apis:
                # 根据数据源和格式生成模式类型
                sources_str = "_".join(sorted(module.data_sources)[:2])
                formats_str = "_".join(sorted(module.data_formats)[:2])
                pattern_type = f"{sources_str}_to_{formats_str}" if sources_str and formats_str else "unknown"
                
                pattern = DataFlowPattern(
                    pattern_type=pattern_type,
                    source_apis=source_apis[:5],  # 限制数量
                    sink_apis=sink_apis[:5],
                    intermediate_operations=list(set(intermediate_ops))[:10],  # 增加中间操作数量
                    file_paths=file_paths
                )
                patterns.append(pattern)
        
        # 去重相似的模式
        unique_patterns = []
        seen_pattern_types = set()
        for pattern in patterns:
            if pattern.pattern_type not in seen_pattern_types:
                unique_patterns.append(pattern)
                seen_pattern_types.add(pattern.pattern_type)
        
        logger.info(f"Extracted {len(unique_patterns)} unique data flow patterns")
        return unique_patterns
    
    def _extract_project_level_features(
        self,
        modules: List[ModuleInfo],
        repo_analysis: Dict
    ) -> Dict[str, Any]:
        """从模块中提取项目级特征"""
        all_data_sources = []
        all_data_formats = []
        all_processing_ops = []
        
        for module in modules:
            all_data_sources.extend(module.data_sources)
            all_data_formats.extend(module.data_formats)
            all_processing_ops.extend(module.processing_operations)
        
        # 去重并统计
        common_data_sources = list(set(all_data_sources))
        common_data_formats = list(set(all_data_formats))
        
        # 依赖统计
        dependencies = repo_analysis.get('dependencies', [])
        third_party_libraries = []
        builtin_libraries = []
        
        if isinstance(dependencies, list):
            for dep in dependencies:
                if dep.get('is_third_party'):
                    third_party_libraries.append(dep.get('name', ''))
                elif dep.get('is_builtin'):
                    builtin_libraries.append(dep.get('name', ''))
        
        # 统计函数
        total_functions = len(repo_analysis.get('functions', []))
        
        # 依赖使用次数
        dependency_usage_count = {}
        if isinstance(dependencies, list):
            for dep in dependencies:
                dep_name = dep.get('name', '')
                if dep_name:
                    dependency_usage_count[dep_name] = dep.get('import_count', 1)
        
        return {
            'common_data_sources': common_data_sources,
            'common_data_formats': common_data_formats,
            'third_party_libraries': third_party_libraries,
            'builtin_libraries': builtin_libraries,
            'dependency_usage_count': dependency_usage_count,
            'total_functions': total_functions,
        }
