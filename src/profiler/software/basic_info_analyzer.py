"""Basic information analyzer (app name, target scenarios, etc.)."""

from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from llm import BaseLLMClient, safe_chat_call
from utils.logger import get_logger
from utils.llm_utils import parse_llm_json, extract_message_content
from profiler.profile_storage import ProfileStorageManager
from .prompts import BASIC_INFO_PROMPT, SOFTWARE_BASIC_INFO_SYSTEM_PROMPT

logger = get_logger(__name__)


class BasicInfoAnalyzer:
    """Analyze basic information about the software."""
    
    def __init__(self, llm_client: BaseLLMClient):
        self.llm_client = llm_client

    def analyze(
        self, 
        repo_path: Path, 
        repo_info: Dict,
        repo_name: str = None,
        version: str = None,
        storage_manager: Optional[ProfileStorageManager] = None
    ) -> Dict[str, Any]:
        """
        Analyze basic information.
        
        Returns:
            A dict containing the following fields:
            - description: Project description
            - target_application: Target application scenarios
            - target_user: Target users
        """
        logger.info("Analyzing basic info...")
        
        # Format configuration files
        config_files_text = self._format_config_files(repo_info.get("config_files", []))
        
        # Build the LLM prompt
        prompt = BASIC_INFO_PROMPT.format(
            repo_name=repo_name or repo_path.name,
            readme_content=repo_info.get("readme_content", ""),
            config_files_formatted=config_files_text,
            # file_list="\n".join(repo_info.get("files", []))
        )
        
        try:
            response = safe_chat_call(
                self.llm_client,
                messages=[
                    {"role": "system", "content": SOFTWARE_BASIC_INFO_SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
            )

            content = extract_message_content(response)
            llm_result = parse_llm_json(
                content,
                required_keys=["description", "target_application", "target_user"],
                expected_types={
                    "description": str,
                    "target_application": list,
                    "target_user": list,
                },
                llm_client=self.llm_client,
                max_repair_attempts=2,
                task_hint="software basic information extraction",
            )

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

            # Merge rule-based analysis and LLM-based analysis results
            if llm_result:
                return {
                    "description": llm_result.get("description", ""),
                    "target_application": llm_result.get("target_application", []),
                    "target_user": llm_result.get("target_user", [])
                }
        except Exception as e:
            logger.warning(f"LLM-based basic info analysis failed: {e}, using rule-based results")
        
        return {}
    
    def _format_config_files(self, config_files: list) -> str:
        """Format configuration file contents."""
        result = []
        for config in config_files[:3]:  # At most 3
            name = config.get("name", "unknown")
            content = config.get("content", "")
            result.append(f"[{name}]\n{content}")
        return "\n\n".join(result)
    
