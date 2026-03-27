"""Basic information analyzer (app name, target scenarios, etc.)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from llm import (
    BaseLLMClient,
    aggregate_llm_usage_since,
    build_empty_llm_usage_summary,
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
        repo_info: Dict[str, Any],
        repo_name: Optional[str] = None,
        version: Optional[str] = None,
        storage_manager: Optional[ProfileStorageManager] = None,
    ) -> Dict[str, Any]:
        """Analyze repository-level software basic information.

        Args:
            repo_path: Local repository path.
            repo_info: Repository metadata collected before LLM analysis.
            repo_name: Optional repository name override.
            version: Optional commit or version identifier.
            storage_manager: Optional storage manager used to persist the prompt
                conversation.

        Returns:
            Parsed basic-info fields plus LLM usage metadata when analysis
            succeeds. On failure, returns usage metadata only.
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
        llm_usage = build_empty_llm_usage_summary(
            requested_model=getattr(getattr(self.llm_client, "config", None), "model", None),
            provider=getattr(getattr(self.llm_client, "config", None), "provider", None),
        )
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
                required_keys=[
                    "description",
                    "target_application",
                    "target_user",
                    "capabilities",
                    "interfaces",
                    "deployment_style",
                    "operator_inputs",
                    "external_surfaces",
                    "evidence_summary",
                    "confidence",
                    "open_questions",
                ],
                expected_types={
                    "description": str,
                    "target_application": list,
                    "target_user": list,
                    "capabilities": list,
                    "interfaces": list,
                    "deployment_style": list,
                    "operator_inputs": list,
                    "external_surfaces": list,
                    "evidence_summary": str,
                    "confidence": str,
                    "open_questions": list,
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
                    "capabilities": llm_result.get("capabilities", []),
                    "interfaces": llm_result.get("interfaces", []),
                    "deployment_style": llm_result.get("deployment_style", []),
                    "operator_inputs": llm_result.get("operator_inputs", []),
                    "external_surfaces": llm_result.get("external_surfaces", []),
                    "evidence_summary": llm_result.get("evidence_summary", ""),
                    "confidence": llm_result.get("confidence", ""),
                    "open_questions": llm_result.get("open_questions", []),
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

    def _format_config_files(self, config_files: list[Dict[str, Any]]) -> str:
        """Format configuration file contents.

        Args:
            config_files: Collected configuration file records.

        Returns:
            Up to three formatted config snippets for the prompt.
        """
        result = []
        for config in config_files[:3]:  # At most 3
            name = config.get("name", "unknown")
            content = config.get("content", "")
            result.append(f"[{name}]\n{content}")
        return "\n\n".join(result)
