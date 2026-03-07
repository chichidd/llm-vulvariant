"""Basic information analyzer (app name, target scenarios, etc.)."""

from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from llm import (
    BaseLLMClient,
    aggregate_llm_usage_since,
    capture_llm_usage_snapshot,
    safe_chat_call,
)
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
        llm_usage = {
            "source": "llm_client",
            "provider": getattr(getattr(self.llm_client, "config", None), "provider", None),
            "requested_model": getattr(getattr(self.llm_client, "config", None), "model", None),
            "selected_model": getattr(getattr(self.llm_client, "config", None), "model", None),
            "selected_model_found": getattr(getattr(self.llm_client, "config", None), "model", None) is not None,
            "selected_model_reason": "requested_model" if getattr(getattr(self.llm_client, "config", None), "model", None) else None,
            "available_models": [getattr(getattr(self.llm_client, "config", None), "model", None)] if getattr(getattr(self.llm_client, "config", None), "model", None) else [],
            "models_usage": {},
            "session_usage": None,
            "selected_model_usage": None,
            "top_level_usage": None,
            "response_id": None,
            "service_tier": None,
            "total_cost_usd": 0.0,
            "is_error": False,
            "subtype": None,
            "sessions_total": 0,
            "turns_total": 0,
            "calls_total": 0,
            "calls_with_session_usage": 0,
            "calls_with_selected_model_usage": 0,
            "calls_with_selected_model_usage_session_fallback": 0,
            "calls_with_top_level_usage_fallback": 0,
            "calls_missing_selected_model_usage": 0,
            "calls_missing_usage": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cost_usd": 0.0,
            "request_cost_usd": 0.0,
            "session_usage_summary": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
                "request_cost_usd": 0.0,
            },
            "selected_model_usage_summary": None,
        }
        usage_snapshot = capture_llm_usage_snapshot(self.llm_client)
        
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
            llm_usage = aggregate_llm_usage_since(self.llm_client, usage_snapshot)

            if storage_manager:
                conversation_data = {
                    "step": "basic_info_analysis",
                    "timestamp": datetime.now().isoformat(),
                    "prompt": prompt,
                    "response": content,
                    "parsed_result": llm_result,
                    "llm_usage": llm_usage,
                }
                path_parts = (repo_name, version) if repo_name else (repo_path.name, version)
                storage_manager.save_conversation("basic_info", conversation_data, *path_parts)

            # Merge rule-based analysis and LLM-based analysis results
            if llm_result:
                return {
                    "description": llm_result.get("description", ""),
                    "target_application": llm_result.get("target_application", []),
                    "target_user": llm_result.get("target_user", []),
                    "llm_usage": llm_usage,
                    "llm_calls": llm_usage.get("sessions_total", llm_usage.get("calls_total", 0)),
                }
        except Exception as e:
            logger.warning(f"LLM-based basic info analysis failed: {e}, using rule-based results")
            llm_usage = aggregate_llm_usage_since(self.llm_client, usage_snapshot)
        
        return {
            "llm_usage": llm_usage,
            "llm_calls": llm_usage.get("sessions_total", llm_usage.get("calls_total", 0)),
        }
    
    def _format_config_files(self, config_files: list) -> str:
        """Format configuration file contents."""
        result = []
        for config in config_files[:3]:  # At most 3
            name = config.get("name", "unknown")
            content = config.get("content", "")
            result.append(f"[{name}]\n{content}")
        return "\n\n".join(result)
    
