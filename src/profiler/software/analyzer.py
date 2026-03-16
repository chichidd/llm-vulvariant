"""
Software Profile Generator (Refactored)

轻量级协调器 - 将各个分析步骤委托给专门的模块。
"""

import yaml
import json
import re
import threading
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm import BaseLLMClient, aggregate_llm_usage_since, capture_llm_usage_snapshot
from config import _path_config
from profiler.profile_storage import ProfileStorageManager
from utils.number_utils import to_int
from utils.git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from utils.logger import get_logger
from utils.claude_cli import coerce_aggregated_usage_summary, merge_aggregated_usage_summaries

from .models import (
    DEFAULT_FILE_EXTENSIONS,
    DataFlowPattern,
    ModuleInfo,
    SoftwareProfile,
    normalize_file_extensions,
)
from .repo_collector import RepoInfoCollector
from .basic_info_analyzer import BasicInfoAnalyzer
from .module_analyzer import ModuleAnalyzer, SkillModuleAnalyzer
from .repo_analyzer import RepoAnalyzer

logger = get_logger(__name__)


class SoftwareProfiler:
    """软件画像生成器 - 协调各个分析组件"""
    
    _detection_rules_cache: Dict[tuple[Path, str], Dict[str, Any]] = {}
    _rules_lock = threading.Lock()
    _C_API_ALIASES = {
        "open": {"fopen"},
        "read": {"fread"},
        "write": {"fwrite"},
        "close": {"fclose"},
        "socket": {"recv", "send", "accept", "connect"},
    }

    def _coerce_llm_usage_summary(
        self,
        usage: Optional[Dict[str, Any]],
        *,
        llm_calls: int = 0,
        default_source: Optional[str] = None,
        default_provider: Optional[str] = None,
        default_requested_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        summary = coerce_aggregated_usage_summary(usage)
        expected_calls = max(0, to_int(llm_calls))
        recorded_calls = to_int(summary.get("calls_total"))
        if expected_calls <= recorded_calls:
            if recorded_calls == 0:
                summary = dict(summary)
                if default_source:
                    summary["source"] = default_source
                if default_provider:
                    summary["provider"] = default_provider
                if default_requested_model and not summary.get("requested_model"):
                    summary["requested_model"] = default_requested_model
            return summary

        summary = dict(summary)
        missing_calls = expected_calls - recorded_calls
        summary["calls_total"] = expected_calls
        summary["calls_missing_selected_model_usage"] = to_int(
            summary.get("calls_missing_selected_model_usage")
        ) + missing_calls
        summary["calls_missing_usage"] = to_int(summary.get("calls_missing_usage")) + missing_calls

        requested_model = summary.get("requested_model") or default_requested_model
        provider = summary.get("provider") or default_provider
        if requested_model:
            summary["requested_model"] = requested_model
            if not summary.get("selected_model"):
                summary["selected_model"] = requested_model
            selected_models = sorted(
                {str(model) for model in (summary.get("selected_models") or []) if model} | {requested_model}
            )
            summary["selected_models"] = selected_models
        if provider:
            summary["provider"] = provider
        if default_source:
            summary["source"] = default_source
        elif not summary.get("source"):
            summary["source"] = "llm_client" if provider else "llm_usage"
        return summary

    def _normalize_agent_module_usage_summary(
        self,
        usage: Optional[Dict[str, Any]],
        *,
        llm_calls: int = 0,
    ) -> Dict[str, Any]:
        llm_config = getattr(getattr(self, "llm_client", None), "config", None)
        summary = self._coerce_llm_usage_summary(
            usage,
            llm_calls=llm_calls,
            default_source="llm_client",
            default_provider=getattr(llm_config, "provider", None) if llm_config is not None else None,
            default_requested_model=getattr(llm_config, "model", None) if llm_config is not None else None,
        )
        summary = dict(summary)
        summary["source"] = "llm_client"
        if llm_config is not None and not summary.get("provider"):
            summary["provider"] = getattr(llm_config, "provider", None)
        return summary

    def _load_prior_agent_module_usage_summary(
        self,
        *,
        path_parts: tuple,
        previous_modules_checkpoint: Optional[Dict[str, Any]],
    ) -> tuple[Dict[str, Any], int]:
        conversation_data = None
        if self.storage_manager and hasattr(self.storage_manager, "load_conversation"):
            conversation_data = self.storage_manager.load_conversation(
                "module_analysis",
                *path_parts,
                file_identifier="module_analysis",
            )

        conversation_calls = 0
        if isinstance(conversation_data, dict) and conversation_data.get("conversation_name") == "module_analysis":
            conversation_calls = max(0, to_int(conversation_data.get("llm_calls", 0)))
            if conversation_data.get("llm_usage"):
                return (
                    self._normalize_agent_module_usage_summary(
                        conversation_data.get("llm_usage"),
                        llm_calls=conversation_calls,
                    ),
                    conversation_calls,
                )

        checkpoint_calls = max(
            0,
            to_int((previous_modules_checkpoint or {}).get("llm_calls", 0)),
        )
        if isinstance(previous_modules_checkpoint, dict) and (
            previous_modules_checkpoint.get("llm_usage") or checkpoint_calls > 0
        ):
            return (
                self._normalize_agent_module_usage_summary(
                    previous_modules_checkpoint.get("llm_usage"),
                    llm_calls=checkpoint_calls,
                ),
                checkpoint_calls,
            )

        if conversation_calls > 0:
            return (
                self._normalize_agent_module_usage_summary(
                    None,
                    llm_calls=conversation_calls,
                ),
                conversation_calls,
            )

        return self._normalize_agent_module_usage_summary(None, llm_calls=0), 0

    def _merge_agent_module_usage_summary(
        self,
        current_usage: Optional[Dict[str, Any]],
        *,
        total_llm_calls: int,
        previous_usage_summary: Optional[Dict[str, Any]] = None,
        previous_llm_calls: int = 0,
    ) -> Dict[str, Any]:
        total_calls = max(0, to_int(total_llm_calls))
        prior_calls = max(0, to_int(previous_llm_calls))
        current_calls = max(total_calls - prior_calls, 0)
        current_summary = self._normalize_agent_module_usage_summary(
            current_usage,
            llm_calls=current_calls,
        )

        if prior_calls <= 0 or not isinstance(previous_usage_summary, dict):
            return self._normalize_agent_module_usage_summary(current_summary, llm_calls=total_calls)

        if to_int(current_summary.get("calls_total")) > current_calls:
            return self._normalize_agent_module_usage_summary(current_summary, llm_calls=total_calls)

        merged_summary = merge_aggregated_usage_summaries(
            [previous_usage_summary, current_summary]
        )
        return self._normalize_agent_module_usage_summary(merged_summary, llm_calls=total_calls)

    @staticmethod
    def _is_basic_info_complete(basic_info: Optional[Dict[str, Any]]) -> bool:
        if not isinstance(basic_info, dict):
            return False
        return (
            isinstance(basic_info.get("description"), str)
            and isinstance(basic_info.get("target_application"), list)
            and isinstance(basic_info.get("target_user"), list)
        )
    
    @classmethod
    def _load_detection_rules(cls, rules_path: Path = None, output_dir: Path = None) -> Dict[str, Any]:
        """加载检测规则配置文件"""
        _empty_rule = {'data_sources': {}, 'data_formats': {}, 'processing_operations': {}}
        resolved_rules_path = rules_path
        if resolved_rules_path is None:
            resolved_rules_path = _path_config['repo_root'] / "config" / "software_profile_rule.yaml"
            if output_dir and Path(output_dir).exists():
                save_config_path = Path(output_dir) / "software_profile_rule.yaml"
                if save_config_path.exists():
                    logger.info(f"Loading saved config from: {save_config_path}")
                    resolved_rules_path = save_config_path
        resolved_rules_path = Path(resolved_rules_path).expanduser()
        resolved_cache_path = resolved_rules_path.resolve()

        try:
            raw_rules_text = (
                resolved_rules_path.read_text(encoding='utf-8')
                if resolved_rules_path.exists()
                else ""
            )
        except Exception as e:
            logger.error(f"Failed to read detection rules: {e}")
            raw_rules_text = ""
        cache_key = (
            resolved_cache_path,
            hashlib.sha1(raw_rules_text.encode('utf-8')).hexdigest(),
        )

        with cls._rules_lock:
            if cache_key in cls._detection_rules_cache:
                return cls._detection_rules_cache[cache_key]
            try:
                if raw_rules_text:
                    loaded_rules = yaml.safe_load(raw_rules_text)
                    if not isinstance(loaded_rules, dict):
                        loaded_rules = _empty_rule
                    logger.info(f"Loaded detection rules from {resolved_rules_path}")
                else:
                    logger.warning(f"Detection rules file not found: {resolved_rules_path}")
                    loaded_rules = _empty_rule
            except Exception as e:
                logger.error(f"Failed to load detection rules: {e}")
                loaded_rules = _empty_rule
            cls._detection_rules_cache[cache_key] = loaded_rules
            return loaded_rules
    
    def _save_config_to_output_dir(self):
        """将当前配置保存到输出目录"""
        if not self.output_dir:
            return
        
        try:
            config_save_path = self.output_dir / "software_profile_rule.yaml"
            # 直接保存完整的配置，确保所有内容都被保存
            config_save_path.write_text(
                yaml.dump(self._detection_rules, allow_unicode=True, default_flow_style=False),
                encoding='utf-8',
            )
            
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
        self._detection_rules = all_config
        self.detection_rules = {
            'data_sources': all_config.get('data_sources', {}),
            'data_formats': all_config.get('data_formats', {}),
            'processing_operations': all_config.get('processing_operations', {}),
        }
        
        # 分析器配置
        analyzer_config = all_config.get('analyzer_config', {})
        configured_file_extensions = normalize_file_extensions(analyzer_config.get('file_extensions'))
        if file_extensions is not None:
            self.file_extensions = normalize_file_extensions(file_extensions)
        elif 'file_extensions' in analyzer_config:
            self.file_extensions = configured_file_extensions
        else:
            self.file_extensions = list(DEFAULT_FILE_EXTENSIONS)
        self.exclude_dirs = exclude_dirs or analyzer_config.get('exclude_dirs', [
            "__pycache__", "node_modules", ".git", ".venv", "venv", "env",
            "build", "dist", ".eggs", "*.egg-info"
        ])
        
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
        
    def generate_profile(
        self,
        repo_path: str,
        force_regenerate: bool = False,
        target_version: str = None
    ) -> SoftwareProfile:
        """生成完整的软件画像"""
        repo_path = Path(repo_path)
        repo_name = repo_path.name
        
        logger.info(f"Starting profile generation for: {repo_name}")
        self._save_config_to_output_dir()

        if target_version and has_uncommitted_changes(str(repo_path)):
            raise RuntimeError(
                f"Repository {repo_name} has local changes; please clean/stash before profiling {target_version[:8]}"
            )
        
        # 获取版本信息
        original_version = get_git_commit(str(repo_path))
        original_restore_target = get_git_restore_target(str(repo_path))
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

            path_parts = (repo_name, version) if version else (repo_name,)
            if self.storage_manager and not force_regenerate:
                existing_profile_json = self.storage_manager.load_final_result("software_profile.json", *path_parts)
                if existing_profile_json:
                    logger.info("Found completed profile, loading from cache...")
                    return SoftwareProfile.from_dict(json.loads(existing_profile_json))

            logger.info("Performing full analysis...")
            profile = self._generate_profile_full(
                repo_path,
                repo_name,
                version,
                force_regenerate=force_regenerate,
            )

            logger.info(f"Profile generation completed for: {repo_name}")
            return profile
        finally:
            if changed_commit and original_restore_target:
                restored = restore_git_position(str(repo_path), original_restore_target)
                if restored:
                    logger.info(f"Restored repository to original position: {original_restore_target}")
                else:
                    logger.error(f"Failed to restore repository to original position: {original_restore_target}")
    
    def _generate_profile_full(
        self,
        repo_path: Path,
        repo_name: str,
        version: str,
        force_regenerate: bool = False,
    ) -> SoftwareProfile:
        """执行完整的profile分析"""
        path_parts = (repo_name, version) if version else (repo_name,)
        
        # Step 1: 收集仓库信息
        logger.info("Step 1/4: Collecting repo info...")
        repo_info = None
        if self.storage_manager and not force_regenerate:
            repo_info = self.storage_manager.load_checkpoint("repo_info", *path_parts)
        
        if repo_info:
            logger.info("Loaded repo_info from checkpoint")
        else:
            repo_info = self.repo_collector.collect(repo_path)
            repo_info['commit_hash'] = version

            logger.info("Performing deep static analysis...")
            cache_dir = self.output_dir / repo_name / ".cache" / "repo_analyzer" if self.output_dir else None

            self.repo_analyzer = RepoAnalyzer(
                repo_path=str(repo_path),
                languages=self.repo_analyzer_config.get('languages'),
                cache_dir=str(cache_dir) if cache_dir else None,
                rebuild_cache=force_regenerate or self.repo_analyzer_config.get('rebuild_cache', False)
            )

            repo_info['repo_analysis'] = self.repo_analyzer.get_info()
            if self.storage_manager:
                self.storage_manager.save_checkpoint("repo_info", repo_info, *path_parts)
        
        # Step 2: 分析基本信息
        logger.info("Step 2/4: Analyzing basic info...")
        basic_info = self.storage_manager.load_checkpoint("basic_info", *path_parts) if self.storage_manager and not force_regenerate else None
        if self._is_basic_info_complete(basic_info):
            logger.info("Loaded basic_info from checkpoint")
        else:
            if basic_info is not None:
                logger.warning("Loaded basic_info checkpoint is incomplete, re-analyzing...")
            basic_info = self.basic_info_analyzer.analyze(
                repo_path, repo_info, repo_name, version, storage_manager=self.storage_manager
            )
            if self.storage_manager and self._is_basic_info_complete(basic_info):
                self.storage_manager.save_checkpoint("basic_info", basic_info, *path_parts)
        basic_info = basic_info or {}
        
        # Step 3: 分析模块
        logger.info("Step 3/4: Analyzing modules...")
        modules_result = self.storage_manager.load_checkpoint("modules", *path_parts) if self.storage_manager and not force_regenerate else None
        previous_modules_checkpoint = (
            modules_result
            if isinstance(self.module_analyzer, ModuleAnalyzer)
            and isinstance(modules_result, dict)
            and not modules_result.get('modules')
            else None
        )
        
        if modules_result and modules_result.get('modules'):
            logger.info("Loaded modules from checkpoint")
        else:
            if modules_result and not modules_result.get('modules'):
                logger.warning("Loaded modules checkpoint is empty, re-analyzing...")
            module_analyze_kwargs = {
                "repo_info": repo_info,
                "repo_path": repo_path,
                "storage_manager": self.storage_manager,
                "repo_name": repo_name,
                "version": version,
            }
            if isinstance(self.module_analyzer, ModuleAnalyzer):
                module_analyze_kwargs["resume_from_conversation"] = not force_regenerate
            elif isinstance(self.module_analyzer, SkillModuleAnalyzer):
                module_analyze_kwargs["force_regenerate"] = force_regenerate
            llm_client = getattr(self, "llm_client", None)
            prior_module_usage_summary, prior_module_llm_calls = (
                self._load_prior_agent_module_usage_summary(
                    path_parts=path_parts,
                    previous_modules_checkpoint=previous_modules_checkpoint,
                )
                if isinstance(self.module_analyzer, ModuleAnalyzer)
                else (self._coerce_llm_usage_summary(None, llm_calls=0), 0)
            )
            module_usage_snapshot = (
                capture_llm_usage_snapshot(llm_client)
                if isinstance(self.module_analyzer, ModuleAnalyzer)
                else None
            )
            modules_result = self.module_analyzer.analyze(**module_analyze_kwargs)
            if isinstance(self.module_analyzer, ModuleAnalyzer) and isinstance(modules_result, dict):
                current_module_usage = modules_result.get("llm_usage")
                if not current_module_usage:
                    current_module_usage = aggregate_llm_usage_since(
                        llm_client,
                        module_usage_snapshot,
                    )
                modules_result["llm_usage"] = self._merge_agent_module_usage_summary(
                    current_module_usage,
                    total_llm_calls=modules_result.get("llm_calls", 0),
                    previous_usage_summary=prior_module_usage_summary,
                    previous_llm_calls=prior_module_llm_calls,
                )
            
            if self.storage_manager:
                self.storage_manager.save_checkpoint("modules", modules_result, *path_parts)
            
        # Step 4: 构建软件画像
        logger.info("Step 4/4: Building software profile...")
        llm_config = getattr(getattr(self, "llm_client", None), "config", None)
        basic_info_usage_summary = self._coerce_llm_usage_summary(
            basic_info.get("llm_usage"),
            llm_calls=basic_info.get("llm_calls", 0),
            default_source="llm_client",
            default_provider=getattr(llm_config, "provider", None) if llm_config is not None else None,
            default_requested_model=getattr(llm_config, "model", None) if llm_config is not None else None,
        )
        module_usage_source = "llm_client" if isinstance(self.module_analyzer, ModuleAnalyzer) else "claude_cli"
        module_usage_provider = (
            getattr(llm_config, "provider", None)
            if isinstance(self.module_analyzer, ModuleAnalyzer) and llm_config is not None
            else None
        )
        module_usage_requested_model = (
            getattr(llm_config, "model", None)
            if isinstance(self.module_analyzer, ModuleAnalyzer) and llm_config is not None
            else None
        )
        modules_usage_summary = self._coerce_llm_usage_summary(
            modules_result.get("llm_usage") if modules_result else None,
            llm_calls=(modules_result or {}).get("llm_calls", 0),
            default_source=module_usage_source,
            default_provider=module_usage_provider,
            default_requested_model=module_usage_requested_model,
        )
        llm_usage_summary = merge_aggregated_usage_summaries(
            [basic_info_usage_summary, modules_usage_summary]
        )
        llm_usage_summary["source"] = "llm_usage"
        profile = SoftwareProfile(
            name=repo_name,
            version=version,
            description=basic_info.get("description", ""),
            target_application=basic_info.get("target_application", []),
            target_user=basic_info.get("target_user", []),
            repo_info=repo_info,
            modules=modules_result.get('modules', []) if modules_result else [],
            metadata={
                "llm_calls": int(basic_info.get("llm_calls", 0)) + int(
                    (modules_result or {}).get("llm_calls", 0)
                ),
                "llm_usage_by_stage": {
                    "basic_info": basic_info_usage_summary,
                    "module_analysis": modules_usage_summary,
                },
                "llm_usage_summary": llm_usage_summary,
                "module_analysis_record_path": (modules_result or {}).get("claude_cli_record_path"),
            },
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
        if llm_usage_summary.get("sessions_total", llm_usage_summary.get("calls_total", 0)) > 0:
            logger.info(
                "LLM usage summary: sessions=%s turns=%s input_tokens=%s output_tokens=%s cache_read_input_tokens=%s cost_usd=%.6f",
                llm_usage_summary.get("sessions_total", llm_usage_summary.get("calls_total", 0)),
                llm_usage_summary.get("turns_total", 0),
                llm_usage_summary.get("input_tokens", 0),
                llm_usage_summary.get("output_tokens", 0),
                llm_usage_summary.get("cache_read_input_tokens", 0),
                llm_usage_summary.get("cost_usd", 0.0),
            )
        
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

                matched_path = False

                # Prefer exact file matching so extensionless files (e.g. Makefile) are handled correctly.
                if path in all_files_set:
                    if path not in module_file_set:
                        module_files.append(path)
                        module_file_set.add(path)
                    matched_path = True
                    continue

                folder_prefix = path + '/'
                for file_path in all_files:
                    if file_path.startswith(folder_prefix) and file_path not in module_file_set:
                        module_files.append(file_path)
                        module_file_set.add(file_path)
                        matched_path = True

                if not matched_path and path not in module_file_set:
                    # Keep the original checkpoint/module-modeler paths when the
                    # current repo inventory cannot resolve them. This preserves
                    # the checkpoint module file superset instead of shrinking it
                    # during enhancement.
                    module_files.append(path)
                    module_file_set.add(path)
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
            preserved_dependencies = []
            seen_preserved_dependencies = set()
            internal_dependencies = set(calls_modules)
            for dep_name in base_internal_dependencies:
                if not isinstance(dep_name, str):
                    continue
                normalized_dep_name = dep_name.strip()
                if not normalized_dep_name:
                    continue
                if normalized_dep_name not in seen_preserved_dependencies:
                    preserved_dependencies.append(normalized_dep_name)
                    seen_preserved_dependencies.add(normalized_dep_name)
                if normalized_dep_name == module_name:
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
                dependencies=preserved_dependencies,
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
