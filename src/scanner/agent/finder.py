"""Agentic vulnerability finder core logic."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm import BaseLLMClient
from utils.logger import get_logger
from utils.number_utils import to_int
from scanner.agent.utils import (
    clear_reasoning_content,
    compress_iteration_conversation,
    make_serializable,
)

from .memory import AgentMemoryManager
from .priority import calculate_module_priorities
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


class AgenticVulnFinder:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        repo_path: Path,
        software_profile,
        vulnerability_profile,
        max_iterations: int = 300,
        stop_when_critical_complete: bool = False,
        critical_stop_mode: str = "min",
        temperature: float = 1.0,
        max_tokens: int = 65536,
        verbose: bool = True,
        output_dir: Optional[Path] = None,
        languages: Optional[List[str]] = None,
        codeql_database_names: Optional[Dict[str, str]] = None,
    ):
        self.llm_client = llm_client
        self.repo_path = repo_path
        self.software_profile = software_profile
        self.vulnerability_profile = vulnerability_profile
        self.max_iterations = max_iterations
        self.stop_when_critical_complete = stop_when_critical_complete
        normalized_stop_mode = (critical_stop_mode or "min").lower()
        if normalized_stop_mode not in {"min", "max"}:
            logger.warning(
                f"Invalid critical_stop_mode={critical_stop_mode!r}; fallback to 'min'"
            )
            normalized_stop_mode = "min"
        self.critical_stop_mode = normalized_stop_mode
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.verbose = verbose
        self.output_dir = output_dir
        self.toolkit = AgenticToolkit(
            repo_path,
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
        if not self.output_dir:
            return
        
        # Calculate priorities
        self.module_priorities, self.file_to_module = calculate_module_priorities(
            self.software_profile,
            self.vulnerability_profile,
        )
        
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
        )
        
        # Connect memory to toolkit for status checking
        self.toolkit.set_memory_manager(self.memory)
        # Connect software profile to toolkit for call relationships
        self.toolkit.set_software_profile(self.software_profile)
        
        if resumed:
            logger.info(f"Resumed scan with {len(self.memory.get_pending_files())} pending files")

    def _clear_reasoning_content(self) -> List[Dict[str, Any]]:
        return clear_reasoning_content(self.conversation_history)

    def _commit_messages(self, messages: List[Dict[str, Any]]) -> None:
        self.conversation_history += messages[len(self.conversation_history):]

    def _get_last_request_input_tokens(self) -> int:
        getter = getattr(self.llm_client, "get_last_request_input_tokens", None)
        if callable(getter):
            return max(0, to_int(getter()))

        summary_getter = getattr(self.llm_client, "get_last_usage_summary", None)
        if not callable(summary_getter):
            return 0

        summary = summary_getter()
        selected_usage = summary.get("selected_model_usage") if isinstance(summary, dict) else None
        top_level_usage = summary.get("top_level_usage") if isinstance(summary, dict) else None
        return max(
            0,
            to_int(
                (selected_usage or {}).get("input_tokens")
                or (top_level_usage or {}).get("input_tokens")
            ),
        )

    def _get_last_request_output_tokens(self) -> int:
        getter = getattr(self.llm_client, "get_last_request_output_tokens", None)
        if callable(getter):
            return max(0, to_int(getter()))

        summary_getter = getattr(self.llm_client, "get_last_usage_summary", None)
        if not callable(summary_getter):
            return 0

        summary = summary_getter()
        selected_usage = summary.get("selected_model_usage") if isinstance(summary, dict) else None
        top_level_usage = summary.get("top_level_usage") if isinstance(summary, dict) else None
        return max(
            0,
            to_int(
                (selected_usage or {}).get("output_tokens")
                or (top_level_usage or {}).get("output_tokens")
            ),
        )

    def _get_last_request_context_limit(self) -> int:
        getter = getattr(self.llm_client, "get_last_request_context_limit", None)
        if callable(getter):
            return max(0, to_int(getter()))
        return max(0, to_int(getattr(self.llm_client, "context_limit", 0)))

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

    def _run_turn(self, iteration: int) -> int:
        sub_turn = 1
        messages = self._clear_reasoning_content()
        while True:
            tools = self.toolkit.get_available_tools()
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
                continue
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
                if tool_calls is not None:
                    logger.info(f"- {tool_calls[0].function.name=}\n- {tool_calls[0].function.arguments=}\n")

            if tool_calls is None:
                self._commit_messages(messages)
                return sub_turn
            
            for tool in tool_calls:
                tool_name = tool.function.name
                try:
                    parameters = json.loads(tool.function.arguments)
                except json.JSONDecodeError:
                    parameters = {}
                    logger.error("Failed to parse tool arguments")
                if self.verbose:
                    logger.debug(
                        f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:500]}..."
                    )
                result = self.toolkit.execute_tool(tool_name, parameters)
                if self.verbose:
                    logger.debug(f"  [TOOL RESULT] {result}...")
                
                if tool_name == "report_vulnerability" and result.success:
                    vuln_report = json.loads(result.content)
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
                        tool_result_content = f"Note: This vulnerability was already reported. Do not report duplicates."
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
                reserved_output_tokens=max(0, to_int(self.max_tokens)),
            ):
                if self.verbose:
                    logger.info(
                        "Stopping current turn because the last successful request is already near the model context limit"
                    )
                self._commit_messages(messages)
                return sub_turn
            sub_turn += 1

    def _extract_complementary_summary(self, summarized: Dict[str, Any]) -> str:
        """Extract only information complementary to _get_user_message.
        
        _get_user_message provides:
        - progress_info: scan progress statistics
        - findings: already reported vulnerabilities (file, type, confidence)
        - scanned_files: already scanned file paths
        
        This method extracts only:
        - reasoning: motivation, analysis logic, conclusions
        - failed_attempts: what was tried and why it failed
        - next_step_insights: hypotheses and strategies to validate
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
        
        # 3. Failed attempts - important context not tracked elsewhere
        failed = content.get("failed_attempts", [])
        if failed:
            failed_lines = []
            for attempt in failed[:5]:  # Limit to avoid too much context
                if isinstance(attempt, dict):
                    what = attempt.get("what", "")
                    why = attempt.get("why_failed", "")
                    if what:
                        failed_lines.append(f"- {what}: {why}")
                elif isinstance(attempt, str):
                    failed_lines.append(f"- {attempt}")
            if failed_lines:
                complementary_parts.append("**Failed Attempts**:\n" + "\n".join(failed_lines))
        
        # 4. Next step insights - hypotheses and strategies
        next_insights = content.get("next_step_insights", content.get("next_steps", []))
        if next_insights:
            if isinstance(next_insights, list):
                insights_str = "\n".join(f"- {item}" for item in next_insights[:5])
            else:
                insights_str = f"- {next_insights}"
            complementary_parts.append(f"**Next Steps**:\n{insights_str}")
        
        if not complementary_parts:
            return "Iteration completed. Check progress for details."
        
        return "\n\n".join(complementary_parts)

    def _get_user_message(self, iteration: int) -> str:
        if iteration == 0:
            return build_initial_user_message(
                self.software_profile,
                self.module_priorities,
                # self.file_to_module,
            )
        # Include progress info and already-scanned context for subsequent iterations
        progress_info = ""
        scanned_files = []
        findings = []
        
        if self.memory:
            progress = self.memory.get_progress()
            pending = self.memory.get_pending_files(max_priority=2)
            progress_info = (
                f"{progress['completed']}/{progress['total_files']} files scanned, "
                f"{progress['findings']} findings. "
                f"Priority-1: {progress['priority_1']['completed']}/{progress['priority_1']['total']}, "
                f"Priority-2: {progress['priority_2']['completed']}/{progress['priority_2']['total']}."
            )
            if pending:
                progress_info += f" Pending: {pending[:50]}"
                progress_info += "\nUse 'check_file_status' tool to get the status of specific files."
            # Get already scanned files and findings to avoid duplicates
            scanned_files = self.memory.get_scanned_files()
            findings = self.memory.get_findings_summary()
        
        return build_intermediate_user_message(
            scanned_files=scanned_files,
            findings=findings,
            progress_info=progress_info,
        )

    def run(self) -> Dict[str, Any]:
        if self.verbose:
            logger.info("Starting agentic vulnerability analysis with native tool calling...")
        self.conversation_history = [
            {"role": "system", "content": build_system_prompt(self.vulnerability_profile, self.toolkit)}
        ]
        iteration = 0  # iteration index

        while True:
            critical_complete = self.memory.is_critical_complete() if self.memory else True
            base_iteration_reached = iteration >= self.max_iterations
            if not self.stop_when_critical_complete:
                if base_iteration_reached:
                    break
            elif self.critical_stop_mode == "max":
                if base_iteration_reached and critical_complete:
                    if self.verbose:
                        logger.info(
                            "Reached stop condition: iterations >= baseline and priority-1 scope complete"
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
                        logger.info("- Priority-1 scan scope is complete; stopping (critical-stop-mode=min)")
                    break

            if self.verbose:
                if self.stop_when_critical_complete and self.critical_stop_mode == "max":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}] "
                        f"(baseline={self.max_iterations}, "
                        "stop when baseline reached AND priority-1 complete)"
                    )
                elif self.stop_when_critical_complete and self.critical_stop_mode == "min":
                    logger.info(
                        f"\n[ITERATION {iteration + 1}/{self.max_iterations}] "
                        "(stop when baseline reached OR priority-1 complete)"
                    )
                else:
                    logger.info(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            self.conversation_history.append(
                {"role": "user", "content": self._get_user_message(iteration)}
            )
            prev_conv_length = len(self.conversation_history)
            _ = self._run_turn(iteration)
            response = self.conversation_history[-1].content if hasattr(self.conversation_history[-1], "content") else self.conversation_history[-1].get("content")
            completion_keywords = ["analysis complete"]  # currently only "analysis complete" as stop words
            should_stop = bool(
                response and any(keyword in response.lower() for keyword in completion_keywords)
            )
            critical_complete = self.memory.is_critical_complete() if self.memory else True
            if should_stop and self.verbose:
                logger.info("- LLM indicates analysis is complete")
            if self.stop_when_critical_complete and critical_complete and self.verbose:
                logger.info("- Priority-1 scan scope is complete")

            if self.output_dir:
                conversations_dir = self.output_dir / "conversations"
                conversations_dir.mkdir(parents=True, exist_ok=True)
                iteration_file = conversations_dir / f"iteration_{iteration}.json"
                with open(iteration_file, "w", encoding="utf-8") as handle:
                    json.dump(make_serializable(self.conversation_history), handle, indent=2, ensure_ascii=False)
                iteration_history = self.conversation_history[prev_conv_length:]
                summarized = compress_iteration_conversation(
                    self.llm_client, iteration, iteration_history, verbose=self.verbose
                )
                summary_file = conversations_dir / f"iteration_{iteration}_output_summary.json"
                with open(summary_file, "w", encoding="utf-8") as handle:
                    json.dump(summarized, handle, indent=2, ensure_ascii=False)
                self.conversation_history = self.conversation_history[:prev_conv_length]
                
                # Extract only complementary information (not duplicated in _get_user_message)
                assistant_summary = self._extract_complementary_summary(summarized)
                self.conversation_history.append(
                    {"role": "assistant", "content": assistant_summary}
                )
            
            iteration += 1
            if should_stop and (not self.stop_when_critical_complete or self.critical_stop_mode == "min"):
                break
            if should_stop and self.stop_when_critical_complete and self.critical_stop_mode == "max" and self.verbose:
                logger.info(
                    "- Continue scanning until both conditions are met: "
                    f"iterations >= {self.max_iterations} and priority-1 scope complete"
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
            self.memory.generate_summary()
        
        # Save markdown report
        self.memory.save_markdown()
        
        # Log completion status
        progress = self.memory.get_progress()
        if self.memory.is_critical_complete():
            logger.info("✅ All priority-1 (affected) files have been scanned")
        else:
            logger.warning(
                f"⚠️ Some priority-1 files not scanned: "
                f"{progress['priority_1']['completed']}/{progress['priority_1']['total']}"
            )
        
        logger.info(
            f"Scan complete: {progress['completed']}/{progress['total_files']} files, "
            f"{progress['findings']} findings"
        )
