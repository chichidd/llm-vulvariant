"""Agentic vulnerability finder core logic."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import _scanner_config
from llm import BaseLLMClient
from llm.tool_arguments import normalize_tool_arguments
from profiler.fingerprint import stable_data_hash
from scanner.similarity.embedding import embedding_model_artifact_signature
from utils.logger import get_logger
from utils.number_utils import to_int
from utils.llm_utils import extract_json_from_text
from scanner.agent.utils import (
    clear_reasoning_content,
    compress_iteration_conversation,
    estimate_serialized_tokens,
    make_serializable,
)

from .memory import AgentMemoryManager
from .priority import calculate_module_priorities, resolve_module_similarity_config
from .prompts import (
    build_initial_user_message,
    build_intermediate_user_message,
    build_system_prompt,
)
from .toolkit import AgenticToolkit

logger = get_logger(__name__)

_CONTEXT_LIMIT_ERROR_PATTERNS = (
    "maximum context length",
    "context length exceeded",
    "context window exceeded",
    "prompt is too long",
    "too many tokens",
    "input is too long",
)
_PREFLIGHT_CONTEXT_THRESHOLD = 0.8


class AgenticVulnFinder:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        repo_path: Path,
        software_profile,
        vulnerability_profile,
        max_iterations: int = 300,
        max_sub_turns: int = 64,
        stop_when_critical_complete: bool = False,
        critical_stop_mode: str = "max",
        critical_stop_max_priority: int = 2,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        verbose: bool = True,
        output_dir: Optional[Path] = None,
        languages: Optional[List[str]] = None,
        codeql_database_names: Optional[Dict[str, str]] = None,
        shared_public_memory_manager: Optional[Any] = None,
        shared_public_memory_scope: Optional[Dict[str, Any]] = None,
        module_similarity_config: Optional[Dict[str, Any]] = None,
    ):
        self.llm_client = llm_client
        self.repo_path = repo_path
        self.software_profile = software_profile
        self.vulnerability_profile = vulnerability_profile
        self.max_iterations = max_iterations
        self.max_sub_turns = max(1, int(max_sub_turns))
        self.stop_when_critical_complete = stop_when_critical_complete
        normalized_stop_mode = (critical_stop_mode or "max").lower()
        if normalized_stop_mode not in {"min", "max"}:
            logger.warning(
                f"Invalid critical_stop_mode={critical_stop_mode!r}; fallback to 'max'"
            )
            normalized_stop_mode = "max"
        self.critical_stop_mode = normalized_stop_mode
        if critical_stop_max_priority not in {1, 2}:
            logger.warning(
                "Invalid critical_stop_max_priority=%r; fallback to 2",
                critical_stop_max_priority,
            )
        self.critical_stop_max_priority = 1 if critical_stop_max_priority == 1 else 2
        llm_config = getattr(self.llm_client, "config", None)
        default_temperature = getattr(llm_config, "temperature", 0.0) if llm_config is not None else 0.0
        self.temperature = default_temperature if temperature is None else temperature
        default_max_tokens = to_int(getattr(llm_config, "max_tokens", 0)) if llm_config is not None else 0
        self.max_tokens = default_max_tokens if max_tokens is None else max_tokens
        self.verbose = verbose
        self.output_dir = output_dir
        self.scan_languages = list(languages or [])
        self.codeql_database_names = dict(codeql_database_names or {})
        self.shared_public_memory_scope = dict(shared_public_memory_scope or {})
        self.module_similarity_config = resolve_module_similarity_config(module_similarity_config)
        self.toolkit = AgenticToolkit(
            repo_path,
            shared_public_memory_manager=shared_public_memory_manager,
            languages=languages,
            codeql_database_names=codeql_database_names,
        )
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, Any]] = []
        
        # Initialize memory manager
        self.memory: Optional[AgentMemoryManager] = None
        self.module_priorities: Dict[str, int] = {}
        self.file_to_module: Dict[str, str] = {}
        self._init_memory()
    
    def _init_memory(self):
        """Initialize memory manager with priority information."""
        try:
            self.module_priorities, self.file_to_module = calculate_module_priorities(
                self.software_profile,
                self.vulnerability_profile,
                module_similarity_config=self.module_similarity_config,
            )
        except TypeError as exc:
            if "unexpected keyword argument 'module_similarity_config'" not in str(exc):
                raise
            self.module_priorities, self.file_to_module = calculate_module_priorities(
                self.software_profile,
                self.vulnerability_profile,
            )
        self.toolkit.set_software_profile(self.software_profile)
        if not self.output_dir:
            return

        # Initialize memory
        self.memory = AgentMemoryManager(self.output_dir, self.llm_client)
        
        # Get CVE ID
        cve_id = getattr(self.vulnerability_profile, 'cve_id', '') or ''
        if hasattr(self.vulnerability_profile, 'to_dict'):
            cve_id = self.vulnerability_profile.to_dict().get('cve_id', cve_id)
        
        # Get repo info
        repo_name = self.repo_path.name
        target_commit = ""
        if hasattr(self.software_profile, 'version'):
            target_commit = self.software_profile.version or ""
        elif isinstance(self.software_profile, dict):
            basic = self.software_profile.get('basic_info', {})
            target_commit = basic.get('version', '')
        
        resumed = self.memory.initialize(
            target_repo=repo_name,
            target_commit=target_commit,
            cve_id=cve_id,
            module_priorities=self.module_priorities,
            file_to_module=self.file_to_module,
            critical_stop_max_priority=self.critical_stop_max_priority,
            scan_signature=self._build_scan_signature(),
        )
        
        # Connect memory to toolkit for status checking
        self.toolkit.set_memory_manager(self.memory)
        
        if resumed:
            logger.info(f"Resumed scan with {len(self.memory.get_pending_files())} pending files")

    def _build_scan_signature(self) -> Dict[str, Any]:
        """Build the scan-shaping signature used for resume compatibility checks."""
        llm_config = getattr(self.llm_client, "config", None)
        languages = self.scan_languages
        if not languages and hasattr(self.toolkit, "_languages"):
            toolkit_languages = getattr(self.toolkit, "_languages", [])
            if isinstance(toolkit_languages, list):
                languages = toolkit_languages
        codeql_database_names = self.codeql_database_names
        if not codeql_database_names and hasattr(self.toolkit, "_codeql_database_names"):
            toolkit_codeql_database_names = getattr(self.toolkit, "_codeql_database_names", {})
            if isinstance(toolkit_codeql_database_names, dict):
                codeql_database_names = toolkit_codeql_database_names
        normalized_codeql_database_names = {}
        for language, db_name in codeql_database_names.items():
            language_key = str(language).strip().lower()
            db_name_value = str(db_name).strip()
            if language_key and db_name_value:
                normalized_codeql_database_names[language_key] = db_name_value

        cli_root = Path(__file__).resolve().parents[2] / "cli"
        agent_root = Path(__file__).resolve().parent
        project_root = cli_root.parent
        similarity_root = project_root / "scanner" / "similarity"
        source_files = {
            "scanner/agent/finder.py": agent_root / "finder.py",
            "scanner/agent/memory.py": agent_root / "memory.py",
            "scanner/agent/priority.py": agent_root / "priority.py",
            "scanner/agent/prompts.py": agent_root / "prompts.py",
            "scanner/agent/shared_memory.py": agent_root / "shared_memory.py",
            "scanner/agent/toolkit.py": agent_root / "toolkit.py",
            "scanner/agent/toolkit_fs.py": agent_root / "toolkit_fs.py",
            "scanner/agent/toolkit_codeql.py": agent_root / "toolkit_codeql.py",
            "scanner/agent/utils.py": agent_root / "utils.py",
            "cli/agent_scanner.py": cli_root / "agent_scanner.py",
            "scanner/similarity/retriever.py": similarity_root / "retriever.py",
            "scanner/similarity/embedding.py": similarity_root / "embedding.py",
            "config.py": project_root / "config.py",
            "utils/codeql_native.py": project_root / "utils" / "codeql_native.py",
        }
        return {
            "llm": {
                "provider": getattr(llm_config, "provider", ""),
                "model": getattr(llm_config, "model", ""),
                "base_url": getattr(llm_config, "base_url", ""),
                "temperature": getattr(llm_config, "temperature", None),
                "top_p": getattr(llm_config, "top_p", None),
                "max_tokens": getattr(llm_config, "max_tokens", None),
                "enable_thinking": getattr(llm_config, "enable_thinking", None),
            },
            "scan_config": {
                "max_iterations": int(self.max_iterations),
                "stop_when_critical_complete": bool(self.stop_when_critical_complete),
                "critical_stop_mode": self.critical_stop_mode,
                "critical_stop_max_priority": self.critical_stop_max_priority,
                "scan_languages": sorted({
                    str(lang).strip().lower()
                    for lang in languages
                    if str(lang).strip()
                }),
                "codeql_database_names": normalized_codeql_database_names,
                "shared_public_memory": {
                    "enabled": bool(self.shared_public_memory_scope.get("enabled", False)),
                    "root_hash": str(self.shared_public_memory_scope.get("root_hash", "")).strip(),
                    "scope_key": str(self.shared_public_memory_scope.get("scope_key", "")).strip(),
                    "state_hash": str(self.shared_public_memory_scope.get("state_hash", "")).strip(),
                },
                "module_similarity": {
                    "threshold": float(self.module_similarity_config.get("threshold", 0.8)),
                    "model_name": str(self.module_similarity_config.get("model_name", "")).strip(),
                    "device": str(self.module_similarity_config.get("device", "cpu")).strip(),
                    **embedding_model_artifact_signature(
                        str(self.module_similarity_config.get("model_name", "")).strip() or None
                    ),
                },
            },
            "source_hashes": {
                label: stable_data_hash(path.read_text(encoding="utf-8"))
                for label, path in source_files.items()
                if path.exists()
            },
        }

    def _critical_scope_label(self) -> str:
        """Return the human-readable label for the configured critical scope."""
        return "priority-1" if self.critical_stop_max_priority == 1 else "priority-1/2"

    def _is_critical_complete(self) -> bool:
        """Query critical-scope completion with compatibility for older memory doubles."""
        if not self.memory:
            return True
        check_fn = getattr(self.memory, "is_critical_complete", None)
        if not callable(check_fn):
            return True
        try:
            return bool(check_fn(max_priority=self.critical_stop_max_priority))
        except TypeError:
            return bool(check_fn())

    def _clear_reasoning_content(self) -> List[Dict[str, Any]]:
        return clear_reasoning_content(self.conversation_history)

    def _commit_messages(self, messages: List[Dict[str, Any]]) -> None:
        self.conversation_history += messages[len(self.conversation_history):]

    def _mark_current_turn_start(self) -> None:
        self._current_turn_start_index = len(self.conversation_history)

    def _estimate_request_input_tokens(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        return estimate_serialized_tokens(
            {
                "messages": messages,
                "tools": tools or [],
            }
        )

    def _get_last_request_input_tokens(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_input_tokens()))

    def _get_last_request_output_tokens(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_output_tokens()))

    def _get_last_request_context_limit(self) -> int:
        return max(0, to_int(self.llm_client.get_last_request_context_limit()))

    def _get_effective_context_limit(self) -> int:
        context_limit = self._get_last_request_context_limit()
        if context_limit > 0:
            return context_limit
        llm_config = getattr(self.llm_client, "config", None)
        if llm_config is not None:
            context_limit = to_int(getattr(llm_config, "context_limit", 0))
            if context_limit > 0:
                return context_limit
        return max(0, to_int(getattr(self.llm_client, "context_limit", 0)))

    def _needs_preflight_compaction(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        planned_output_tokens: int = 0,
        context_limit: int = 0,
    ) -> bool:
        if context_limit <= 0 or planned_output_tokens <= 0:
            return False
        estimated_input_tokens = self._estimate_request_input_tokens(messages, tools)
        return estimated_input_tokens + planned_output_tokens > int(_PREFLIGHT_CONTEXT_THRESHOLD * context_limit)

    def _compact_previous_history_locally(self) -> bool:
        if len(self.conversation_history) <= 2:
            return False
        latest_message = self.conversation_history[-1] if self.conversation_history else None
        has_current_user = isinstance(latest_message, dict) and latest_message.get("role") == "user"
        history_end = len(self.conversation_history) - 1 if has_current_user else len(self.conversation_history)
        prior_messages = self.conversation_history[1:history_end]
        if not prior_messages:
            return False

        assistant_summary_count = sum(
            1
            for message in prior_messages
            if isinstance(message, dict) and message.get("role") == "assistant"
        )
        compacted_summary = (
            "Previous scan context was compacted locally before this query. "
            "Use the current progress snapshot and memory-backed tools as the source of truth."
        )
        if assistant_summary_count > 0:
            compacted_summary += f" Prior assistant summaries compacted: {assistant_summary_count}."
        else:
            compacted_summary += f" Prior messages compacted: {len(prior_messages)}."

        new_history = [self.conversation_history[0], {"role": "assistant", "content": compacted_summary}]
        if has_current_user:
            new_history.append(latest_message)
        self.conversation_history = new_history
        return True

    def _compact_current_user_message(self, iteration: int) -> bool:
        if not self.conversation_history:
            return False
        latest_message = self.conversation_history[-1]
        if not isinstance(latest_message, dict) or latest_message.get("role") != "user":
            return False
        compact_message = self._get_user_message(iteration, compact=True)
        if compact_message == latest_message.get("content", ""):
            return False
        self.conversation_history[-1] = {"role": "user", "content": compact_message}
        return True

    def _prepare_preflight_messages(
        self,
        iteration: int,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        context_limit = self._get_effective_context_limit()
        planned_output_tokens = max(0, to_int(self.max_tokens))
        if not self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            return messages, False

        if self.verbose:
            logger.info(
                "Preflight compaction triggered before query: estimated_input_tokens=%s planned_output_tokens=%s context_limit=%s",
                self._estimate_request_input_tokens(messages, tools),
                planned_output_tokens,
                context_limit,
            )

        original_history_len = len(self.conversation_history)
        current_turn_additions = messages[original_history_len:]

        compacted_history = self._compact_previous_history_locally()
        if compacted_history:
            messages = self._clear_reasoning_content() + current_turn_additions
            self._mark_current_turn_start()

        if self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            compacted_user = self._compact_current_user_message(iteration)
            if compacted_user:
                messages = self._clear_reasoning_content() + current_turn_additions
                self._mark_current_turn_start()

        if self._needs_preflight_compaction(
            messages,
            tools,
            planned_output_tokens=planned_output_tokens,
            context_limit=context_limit,
        ):
            logger.warning(
                "Skipping LLM query because the preflight request budget remains above %.0f%% of the context limit "
                "after local compaction",
                _PREFLIGHT_CONTEXT_THRESHOLD * 100,
            )
            return messages, True

        return messages, False

    def _is_near_context_limit(
        self,
        input_tokens: int,
        context_limit: int,
        reserved_output_tokens: int = 0,
    ) -> bool:
        if input_tokens <= 0 or context_limit <= 0:
            return False

        reserved_output_tokens = max(0, reserved_output_tokens)
        projected_total = input_tokens + min(reserved_output_tokens, context_limit)
        threshold = int(0.8 * context_limit)
        return projected_total >= threshold or projected_total >= context_limit

    @staticmethod
    def _is_context_limit_error(exc: Exception) -> bool:
        message = str(exc).lower()
        return any(pattern in message for pattern in _CONTEXT_LIMIT_ERROR_PATTERNS)

    @staticmethod
    def _parse_tool_arguments(
        raw_arguments: Any,
        parameter_schema: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Normalize one tool-call argument payload into a JSON object."""
        return normalize_tool_arguments(
            raw_arguments,
            parameters_schema=parameter_schema,
            provider=provider,
        )

    def _run_turn(self, iteration: int) -> int:
        sub_turn = 1
        messages = self._clear_reasoning_content()
        self._mark_current_turn_start()
        while True:
            tools = self.toolkit.get_available_tools()
            tool_parameter_schemas = {
                tool_definition.get("function", {}).get("name"): tool_definition.get("function", {}).get("parameters")
                for tool_definition in tools
                if isinstance(tool_definition, dict) and isinstance(tool_definition.get("function"), dict)
            }
            llm_provider = getattr(getattr(self.llm_client, "config", None), "provider", None)
            messages, skip_query = self._prepare_preflight_messages(iteration, messages, tools)
            if skip_query:
                self._commit_messages(messages)
                return sub_turn
            try:
                message = self.llm_client.chat(
                    messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            except Exception as exc:  # pylint: disable=broad-except
                if self._is_context_limit_error(exc):
                    logger.warning(
                        "LLM request hit the context limit; ending the current turn and rolling conversation forward"
                    )
                else:
                    logger.error(f"LLM call failed: {exc}")
                self._commit_messages(messages)
                return sub_turn
            reasoning_content = getattr(message, "reasoning_content", None)
            content = getattr(message, "content", None)
            tool_calls = getattr(message, "tool_calls", None)
            if content is None and tool_calls is None:
                logger.error("LLM returned no content and no tool calls.")
                self._commit_messages(messages)
                return sub_turn
            messages.append(message)
            request_input_tokens = self._get_last_request_input_tokens()
            request_output_tokens = self._get_last_request_output_tokens()
            request_context_limit = self._get_last_request_context_limit()

            if self.verbose:
                logger.info(
                    f"[Iteration {iteration + 1}.{sub_turn}]\n"
                    f"- API input_tokens: {request_input_tokens}\n"
                    f"- API output_tokens: {request_output_tokens}\n"
                    f"- API context_limit: {request_context_limit}\n"
                    f"- {reasoning_content=}\n"
                    f"- {content=}\n"
                )
                if tool_calls:
                    logger.info(f"- {tool_calls[0].function.name=}\n- {tool_calls[0].function.arguments=}\n")

            if not tool_calls:
                if self._is_completion_signal(content):
                    logger.debug("LLM signaled completion.")
                self._commit_messages(messages)
                return sub_turn
            if hasattr(self.vulnerability_profile, "to_dict"):
                vulnerability_dict = self.vulnerability_profile.to_dict()
            elif isinstance(self.vulnerability_profile, dict):
                vulnerability_dict = self.vulnerability_profile
            else:
                vulnerability_dict = {}

            for tool in tool_calls:
                tool_name = tool.function.name
                parameters, argument_error = self._parse_tool_arguments(
                    tool.function.arguments,
                    parameter_schema=tool_parameter_schemas.get(tool_name),
                    provider=llm_provider,
                )
                if argument_error:
                    logger.error(argument_error)
                    tool_result_content = f"Error: {argument_error}"
                    if len(tool_result_content) > 10000:
                        tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                    messages.append({"role": "tool", "tool_call_id": tool.id, "content": tool_result_content})
                    continue
                if self.verbose:
                    logger.debug(
                        f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:500]}..."
                    )
                result = self.toolkit.execute_tool(tool_name, parameters)
                if self.verbose:
                    logger.debug(f"  [TOOL RESULT] {result}...")
                
                if tool_name == "report_vulnerability" and result.success:
                    vuln_report = json.loads(result.content)
                    sink_features = vulnerability_dict.get("sink_features", {})
                    raw_known_type = ""
                    if isinstance(sink_features, dict):
                        raw_known_type = str(sink_features.get("type", "") or "")
                    normalized_known_type = raw_known_type.strip().lower().replace("-", "_").replace(" ", "_")
                    normalized_reported_type = str(
                        vuln_report.get("vulnerability_type", "") or ""
                    ).strip().lower().replace("-", "_").replace(" ", "_")
                    type_aliases = {
                        "cmd_injection": "command_injection",
                        "os_command_injection": "command_injection",
                        "unsafe_deserialization": "deserialization",
                        "directory_traversal": "path_traversal",
                        "server_side_request_forgery": "ssrf",
                    }
                    normalized_known_type = type_aliases.get(
                        normalized_known_type,
                        normalized_known_type,
                    )
                    normalized_reported_type = type_aliases.get(
                        normalized_reported_type,
                        normalized_reported_type,
                    )
                    if (
                        normalized_known_type
                        and normalized_reported_type
                        and normalized_reported_type != normalized_known_type
                    ):
                        tool_result_content = (
                            "Error: report_vulnerability must keep the same vulnerability type as "
                            f"the known vulnerability ({normalized_known_type}); got "
                            f"{vuln_report.get('vulnerability_type', 'unknown')}."
                        )
                        if len(tool_result_content) > 10000:
                            tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                        messages.append(
                            {"role": "tool", "tool_call_id": tool.id, "content": tool_result_content}
                        )
                        continue
                    # Check for duplicate before adding
                    is_duplicate = False
                    if self.memory:
                        is_duplicate = not self.memory.add_finding(vuln_report)
                    
                    if is_duplicate:
                        if self.verbose:
                            logger.info(
                                f"  [DUPLICATE] Skipping already reported: {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}"
                            )
                        # Modify result to indicate duplicate
                        tool_result_content = "Note: This vulnerability was already reported. Do not report duplicates."
                    else:
                        self.found_vulnerabilities.append(vuln_report)
                        if self.verbose:
                            logger.warning(
                                f"  [VULN FOUND] {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}"
                            )
                        tool_result_content = result.content
                else:
                    tool_result_content = result.content if result.success else f"Error: {result.error}"
                    
                if len(tool_result_content) > 10000:
                    tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                messages.append({"role": "tool", "tool_call_id": tool.id, "content": tool_result_content})

            if self._is_near_context_limit(
                request_input_tokens,
                request_context_limit,
                # Use actual output usage from the last request. Reserving the full configured
                # max_tokens budget here can prematurely end every turn for providers whose
                # max_tokens equals the context window.
                reserved_output_tokens=request_output_tokens,
            ):
                if self.verbose:
                    logger.info(
                        "Stopping current turn because the last successful request is already near the model context limit"
                    )
                self._commit_messages(messages)
                return sub_turn
            if sub_turn >= self.max_sub_turns:
                logger.warning(
                    "Stopping current turn after reaching max_sub_turns=%s",
                    self.max_sub_turns,
                )
                self._commit_messages(messages)
                return sub_turn
            sub_turn += 1

    def _is_completion_signal(self, content: Optional[str]) -> bool:
        """Check whether assistant response is an explicit completion signal."""
        if not content:
            return False
        normalized = content.lower()
        if "analysis complete" in normalized:
            return True
        parsed = extract_json_from_text(
            response_text=content,
            required_keys=["analysis_complete", "summary"],
            validator=lambda payload: isinstance(payload.get("analysis_complete"), bool),
            prefer_last=True,
        )
        return bool(parsed and parsed.get("analysis_complete"))

    def _extract_complementary_summary(self, summarized: Dict[str, Any]) -> str:
        """Extract only information complementary to _get_user_message.
        
        _get_user_message provides:
        - progress_info: scan progress statistics
        - findings: already reported vulnerabilities (file, type, confidence)
        - scanned_files: already scanned file paths
        
        This method extracts only:
        - reasoning: motivation, analysis logic, conclusions
        - shared_memory_hits: reusable shared-memory queries or observations
        - rejected_hypotheses: dead ends or false positives worth avoiding
        - next_best_queries: focused follow-up searches
        - evidence_gaps: missing proof blocking confirmation
        - files_completed_this_iteration: newly completed files
        - summary: one-sentence summary
        """
        content = summarized.get("content", summarized)
        if not isinstance(content, dict):
            # Fallback if content is not a dict
            return str(content)
        
        complementary_parts = []
        
        # 1. Summary - concise overview
        summary = content.get("summary", "")
        if summary:
            complementary_parts.append(f"**Summary**: {summary}")
        
        # 2. Reasoning - the analysis logic (not tracked elsewhere)
        reasoning = content.get("reasoning", {})
        if reasoning:
            reasoning_lines = []
            if reasoning.get("motivation"):
                reasoning_lines.append(f"- Motivation: {reasoning['motivation']}")
            if reasoning.get("analysis"):
                reasoning_lines.append(f"- Analysis: {reasoning['analysis']}")
            if reasoning.get("conclusions"):
                conclusions = reasoning["conclusions"]
                if isinstance(conclusions, list):
                    reasoning_lines.append("- Conclusions: " + "; ".join(conclusions))
                else:
                    reasoning_lines.append(f"- Conclusions: {conclusions}")
            if reasoning_lines:
                complementary_parts.append("**Reasoning**:\n" + "\n".join(reasoning_lines))

        rejected_hypotheses = content.get("rejected_hypotheses", [])
        if not rejected_hypotheses:
            for attempt in content.get("failed_attempts", [])[:5]:
                if isinstance(attempt, dict):
                    what = str(attempt.get("what", "")).strip()
                    why = str(attempt.get("why_failed", "")).strip()
                    if what and why:
                        rejected_hypotheses.append(f"{what}: {why}")
                    elif what:
                        rejected_hypotheses.append(what)
                elif isinstance(attempt, str) and attempt.strip():
                    rejected_hypotheses.append(attempt.strip())

        next_best_queries = content.get(
            "next_best_queries",
            content.get("next_step_insights", content.get("next_steps", [])),
        )
        list_sections = [
            ("Shared Memory Hits", content.get("shared_memory_hits", [])),
            ("Rejected Hypotheses", rejected_hypotheses),
            ("Next Best Queries", next_best_queries),
            ("Evidence Gaps", content.get("evidence_gaps", [])),
            (
                "Files Completed This Iteration",
                content.get("files_completed_this_iteration", []),
            ),
        ]
        for title, values in list_sections:
            if isinstance(values, list):
                lines = [
                    f"- {item}"
                    for item in values[:5]
                    if isinstance(item, str) and item.strip()
                ]
            elif isinstance(values, str) and values.strip():
                lines = [f"- {values.strip()}"]
            else:
                lines = []
            if lines:
                complementary_parts.append(f"**{title}**:\n" + "\n".join(lines))
        
        if not complementary_parts:
            return "Iteration completed. Check progress for details."
        
        return "\n\n".join(complementary_parts)

    def _get_user_message(self, iteration: int, compact: bool = False) -> str:
        shared_observation_count = max(
            0,
            to_int(self.shared_public_memory_scope.get("observation_count", 0)),
        )
        vulnerability_dict: Dict[str, Any]
        if hasattr(self.vulnerability_profile, "to_dict"):
            vulnerability_dict = self.vulnerability_profile.to_dict()
        elif isinstance(self.vulnerability_profile, dict):
            vulnerability_dict = self.vulnerability_profile
        else:
            vulnerability_dict = {}
        structured_guidance = {
            field_name: field_value
            for field_name, field_value in {
                "query_terms": vulnerability_dict.get("query_terms", []),
                "dangerous_apis": vulnerability_dict.get("dangerous_apis", []),
                "source_indicators": vulnerability_dict.get("source_indicators", []),
                "sink_indicators": vulnerability_dict.get("sink_indicators", []),
                "variant_hypotheses": vulnerability_dict.get("variant_hypotheses", []),
                "negative_constraints": vulnerability_dict.get("negative_constraints", []),
                "likely_false_positive_patterns": vulnerability_dict.get(
                    "likely_false_positive_patterns", []
                ),
                "scan_start_points": vulnerability_dict.get("scan_start_points", []),
                "open_questions": vulnerability_dict.get("open_questions", []),
                "assumptions": vulnerability_dict.get("assumptions", []),
            }.items()
            if field_value
        }
        guidance_prefix = ""
        if structured_guidance and iteration == 0:
            guidance_prefix = (
                "## Structured Vulnerability Guidance\n"
                "Use these concrete anchors when choosing shared-memory queries, modules, and search patterns.\n"
                f"{json.dumps(structured_guidance, indent=2, ensure_ascii=False)}\n\n"
            )
        if iteration == 0:
            return guidance_prefix + build_initial_user_message(
                self.software_profile,
                self.module_priorities,
                critical_stop_max_priority=self.critical_stop_max_priority,
                shared_observation_count=shared_observation_count,
            )
        # Include progress info and already-scanned context for subsequent iterations
        progress_info = ""
        scanned_files = []
        findings = []
        pending: List[str] = []
        
        if self.memory:
            pending = self.memory.get_pending_files(
                max_priority=self.critical_stop_max_priority
            )
            progress_info = self.memory.format_progress_info()
            if self.critical_stop_max_priority == 1 and pending:
                progress_info = (
                    "Critical scope: priority-1 modules only (directly affected or embedding-similar). "
                    "Do not spend turns on RELATED modules until all priority-1 files are complete.\n"
                    f"{progress_info}"
                )
            if pending:
                if compact:
                    progress_info += f" Pending: {len(pending)} files remain."
                    progress_info += "\nUse 'check_file_status' tool to inspect specific files as needed."
                else:
                    progress_info += f" Pending: {pending[:50]}"
                    progress_info += "\nUse 'check_file_status' tool to get the status of specific files."
            # Get already scanned files and findings to avoid duplicates
            scanned_files = self.memory.get_scanned_files()
            findings = self.memory.get_findings_summary()
        pending_module_priorities = {
            self.module_priorities.get(self.file_to_module.get(file_path, ""), 3)
            for file_path in pending
        }
        if pending_module_priorities:
            has_priority_one = 1 in pending_module_priorities
            has_related = 2 in pending_module_priorities
        elif self.memory:
            has_priority_one = False
            has_related = False
        else:
            has_priority_one = any(priority == 1 for priority in self.module_priorities.values())
            has_related = any(priority == 2 for priority in self.module_priorities.values())
        
        intermediate_kwargs = {
            "scanned_files": scanned_files,
            "findings": findings,
            "progress_info": progress_info,
            "critical_stop_max_priority": self.critical_stop_max_priority,
            "shared_observation_count": shared_observation_count,
            "has_priority_one": has_priority_one,
            "has_related": has_related,
        }
        if compact:
            intermediate_kwargs["compact"] = True

        return guidance_prefix + build_intermediate_user_message(
            **intermediate_kwargs,
        )

    def _finalize_iteration_progress(self, iteration: int) -> None:
        """Clear per-iteration read tracking without changing coverage state."""
        _ = iteration
        consume_tracked_files = getattr(self.toolkit, "consume_tracked_files", None)
        if not callable(consume_tracked_files):
            return
        consume_tracked_files()

    def run(self) -> Dict[str, Any]:
        if self.verbose:
            logger.info("Starting agentic vulnerability analysis with native tool calling...")
        shared_observation_count = max(
            0,
            to_int(self.shared_public_memory_scope.get("observation_count", 0)),
        )
        self.conversation_history = [
            {
                "role": "system",
                "content": build_system_prompt(
                    self.vulnerability_profile,
                    self.toolkit,
                    shared_observation_count=shared_observation_count,
                ),
            }
        ]
        iteration = 0  # iteration index

        while True:
            critical_complete = self._is_critical_complete()
            base_iteration_reached = iteration >= self.max_iterations
            if not self.stop_when_critical_complete:
                if base_iteration_reached:
                    break
            elif self.critical_stop_mode == "max":
                if base_iteration_reached and critical_complete:
                    if self.verbose:
                        logger.info(
                            "Reached stop condition: iterations >= baseline and %s scope complete",
                            self._critical_scope_label(),
                        )
                    break
            else:
                # min mode: stop when either baseline iteration cap is reached
                # or critical scope is complete
                if base_iteration_reached:
                    if self.verbose:
                        logger.warning(f"Reached maximum iterations ({self.max_iterations})")
                    break
                if critical_complete and iteration > 0:
                    if self.verbose:
                        logger.info(
                            "- %s scan scope is complete; stopping (critical-stop-mode=min)",
                            self._critical_scope_label(),
                        )
                    break

            if self.verbose:
                if self.stop_when_critical_complete and self.critical_stop_mode == "max":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}] "
                        f"(baseline={self.max_iterations}, "
                        f"stop when baseline reached AND {self._critical_scope_label()} complete)"
                    )
                elif self.stop_when_critical_complete and self.critical_stop_mode == "min":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}/{self.max_iterations}] "
                        f"(stop when baseline reached OR {self._critical_scope_label()} complete)"
                    )
                else:
                    logger.info(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            start_iteration_tracking = getattr(self.toolkit, "start_iteration_tracking", None)
            if callable(start_iteration_tracking):
                start_iteration_tracking()
            self.conversation_history.append(
                {"role": "user", "content": self._get_user_message(iteration)}
            )
            prev_conv_length = len(self.conversation_history)
            _ = self._run_turn(iteration)
            self._finalize_iteration_progress(iteration)
            turn_start_index = min(
                max(0, to_int(getattr(self, "_current_turn_start_index", prev_conv_length))),
                len(self.conversation_history),
            )
            response = ""
            # Only inspect assistant messages produced in the current turn.
            for message in reversed(self.conversation_history[turn_start_index:]):
                role = getattr(message, "role", None)
                if role is None and isinstance(message, dict):
                    role = message.get("role")
                if role != "assistant":
                    continue
                response = (
                    message.content
                    if hasattr(message, "content")
                    else message.get("content", "")
                )
                break
            completion_keywords = ["analysis complete"]  # currently only "analysis complete" as stop words
            should_stop = bool(
                response
                and (
                    any(keyword in response.lower() for keyword in completion_keywords)
                    or self._is_completion_signal(str(response))
                )
            )
            critical_complete = self._is_critical_complete()
            if should_stop and self.verbose:
                logger.info("- LLM indicates analysis is complete")
            if self.stop_when_critical_complete and critical_complete and self.verbose:
                logger.info("- %s scan scope is complete", self._critical_scope_label())

            if self.output_dir:
                conversations_dir = self.output_dir / "conversations"
                conversations_dir.mkdir(parents=True, exist_ok=True)
                iteration_file = conversations_dir / f"iteration_{iteration}.json"
                with open(iteration_file, "w", encoding="utf-8") as handle:
                    json.dump(make_serializable(self.conversation_history), handle, indent=2, ensure_ascii=False)
                iteration_history = self.conversation_history[turn_start_index:]
                summarized = compress_iteration_conversation(
                    self.llm_client, iteration, iteration_history, verbose=self.verbose
                )
                summary_file = conversations_dir / f"iteration_{iteration}_output_summary.json"
                with open(summary_file, "w", encoding="utf-8") as handle:
                    json.dump(summarized, handle, indent=2, ensure_ascii=False)
                self.conversation_history = self.conversation_history[:turn_start_index]

                # Keep history bounded even if compression returns a failure stub.
                assistant_summary = self._extract_complementary_summary(summarized)
                if assistant_summary:
                    self.conversation_history.append(
                        {"role": "assistant", "content": assistant_summary}
                    )
            
            iteration += 1
            if should_stop:
                if not self.stop_when_critical_complete:
                    break
                if critical_complete and self.critical_stop_mode == "min":
                    break
                if self.verbose:
                    logger.info(
                        "- Ignore 'analysis complete' because %s scope is still incomplete",
                        self._critical_scope_label(),
                    )
            if should_stop and self.stop_when_critical_complete and self.critical_stop_mode == "max" and self.verbose:
                logger.info(
                    "- Continue scanning until both conditions are met: "
                    f"iterations >= {self.max_iterations} and {self._critical_scope_label()} scope complete"
                )

        if (
            not self.stop_when_critical_complete
            and iteration >= self.max_iterations
            and self.verbose
        ):
            logger.warning(f"Reached maximum iterations ({self.max_iterations})")
        
        # Finalize memory
        self._finalize_memory()
        
        return {
            "vulnerabilities": self.found_vulnerabilities,
            "iterations": iteration,
            "conversation_length": len(self.conversation_history),
        }
    
    def _finalize_memory(self):
        """Generate summary and save final memory state."""
        if not self.memory:
            return

        # Generate LLM summary
        if self.llm_client:
            logger.info("Generating scan summary...")
            generate_summary_fn = getattr(self.memory, "generate_summary", None)
            if callable(generate_summary_fn):
                generate_summary_fn()

        # Save markdown report
        save_markdown_fn = getattr(self.memory, "save_markdown", None)
        if callable(save_markdown_fn):
            save_markdown_fn()
        
        # Log completion status
        progress = self.memory.get_progress()
        priority_1 = progress.get("priority_1", {})
        priority_2 = progress.get("priority_2", {})
        critical_scope_total = int(priority_1.get("total", 0))
        critical_scope_completed = int(priority_1.get("completed", 0))
        if self.critical_stop_max_priority >= 2:
            critical_scope_total += int(priority_2.get("total", 0))
            critical_scope_completed += int(priority_2.get("completed", 0))

        if self._is_critical_complete():
            logger.info("✅ All %s files have been scanned", self._critical_scope_label())
        else:
            logger.warning(
                "⚠️ Some %s files not scanned: %s/%s",
                self._critical_scope_label(),
                critical_scope_completed,
                critical_scope_total,
            )
        
        logger.info(
            f"Scan complete: {progress['completed']}/{progress['total_files']} files, "
            f"{progress['findings']} findings"
        )
