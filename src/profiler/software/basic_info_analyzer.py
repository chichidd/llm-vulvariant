"""基本信息分析器 - 分析应用名称、目标场景等"""

from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from llm import BaseLLMClient
from utils.logger import get_logger
from utils.llm_utils import parse_llm_json, extract_message_content
from profiler.profile_storage import ProfileStorageManager
from .prompts import BASIC_INFO_PROMPT

logger = get_logger(__name__)


class BasicInfoAnalyzer:
    """分析软件的基本信息"""
    
    def __init__(self, llm_client: BaseLLMClient, detection_rules: Dict[str, Any] = None):
        self.llm_client = llm_client
        self.detection_rules = detection_rules or {}
    
    def analyze(
        self, 
        repo_path: Path, 
        repo_info: Dict,
        repo_name: str = None,
        version: str = None,
        storage_manager: Optional[ProfileStorageManager] = None
    ) -> Dict[str, Any]:
        """
        分析基本信息
        
        Returns:
            包含以下字段的字典:
            - description: 项目描述
            - target_application: 目标应用场景
            - target_user: 目标用户
        """
        logger.info("Analyzing basic info...")
        
        # 先尝试基于规则的分析
        rule_based_result = self._rule_based_analysis(repo_path, repo_info)
        
        # 格式化配置文件
        config_files_text = self._format_config_files(repo_info.get("config_files", []))
        
        # 构建 LLM prompt
        prompt = BASIC_INFO_PROMPT.format(
            repo_name=repo_name or repo_path.name,
            readme_content=repo_info.get("readme_content", ""),
            config_files_formatted=config_files_text,
            file_list="\n".join(repo_info.get("files", []))
        )
        
        try:
            response = self.llm_client.chat(
                messages=[{"role": "user", "content": prompt}],
            )

            content = extract_message_content(response)
            llm_result = parse_llm_json(content)

            if storage_manager:
                conversation_data = {
                    "step": "basic_info_analysis",
                    "timestamp": datetime.now().isoformat(),
                    "prompt": prompt,
                    "response": content,
                    "parsed_result": llm_result,
                }
                path_parts = (repo_name, version) if repo_name else (repo_path.name, version)
                storage_manager.save_conversation("basic_info", conversation_data, *path_parts)

            # 合并规则分析和 LLM 分析结果
            if llm_result:
                return {
                    "description": llm_result.get("description", ""),
                    "target_application": llm_result.get("target_application", 
                                                        rule_based_result.get("target_application", [])),
                    "target_user": llm_result.get("target_user", 
                                                 rule_based_result.get("target_user", []))
                }
        except Exception as e:
            logger.warning(f"LLM-based basic info analysis failed: {e}, using rule-based results")
        
        return rule_based_result
    
    def _format_config_files(self, config_files: list) -> str:
        """格式化配置文件内容"""
        result = []
        for config in config_files[:3]:  # 最多3个
            name = config.get("name", "unknown")
            content = config.get("content", "")
            result.append(f"[{name}]\n{content}")
        return "\n\n".join(result)
    
    def _rule_based_analysis(self, repo_path: Path, repo_info: Dict) -> Dict[str, Any]:
        """基于规则的基本分析"""
        result = {
            "description": "",
            "target_application": [],
            "target_user": []
        }
        
        readme = repo_info.get("readme_content", "").lower()
        
        # 检测应用场景
        app_scenarios = self.detection_rules.get("application_scenarios", {})
        for scenario, keywords in app_scenarios.items():
            if any(kw in readme for kw in keywords):
                result["target_application"].append(scenario)
        
        # 检测目标用户
        user_types = self.detection_rules.get("user_types", {})
        for user_type, keywords in user_types.items():
            if any(kw in readme for kw in keywords):
                result["target_user"].append(user_type)
        
        return result
