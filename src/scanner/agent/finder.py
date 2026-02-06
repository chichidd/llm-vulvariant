"""Agentic vulnerability finder core logic."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from llm import BaseLLMClient
from utils.logger import get_logger
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


class AgenticVulnFinder:
    def __init__(
        self,
        llm_client: BaseLLMClient,
        repo_path: Path,
        software_profile,
        vulnerability_profile,
        max_iterations: int = 300,
        temperature: float = 1.0,
        max_tokens: int = 65536,
        verbose: bool = True,
        output_dir: Optional[Path] = None,
        codeql_database_name: Optional[str] = None,
    ):
        self.llm_client = llm_client
        self.repo_path = repo_path
        self.software_profile = software_profile
        self.vulnerability_profile = vulnerability_profile
        self.max_iterations = max_iterations
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.verbose = verbose
        self.output_dir = output_dir
        self.toolkit = AgenticToolkit(repo_path, codeql_database_name=codeql_database_name)
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

    def _run_turn(self, iteration: int) -> int:
        sub_turn = 1
        messages = self._clear_reasoning_content()
        while True:
            try:
                message = self.llm_client.chat(
                    messages,
                    tools=self.toolkit.get_available_tools(),
                    tool_choice="auto",
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(f"LLM call failed: {exc}")
                break
            reasoning_content = getattr(message, "reasoning_content", None)
            content = getattr(message, "content", None)
            tool_calls = getattr(message, "tool_calls", None)
            if content is None and tool_calls is None:
                logger.error("LLM returned no content and no tool calls.")
                continue
            messages.append(message)
            messages_token_len = self.llm_client.token_compute.apply_chat_template_len(messages) 

            if self.verbose:
                
                logger.info(
                    f"[Iteration {iteration + 1}.{sub_turn}]\n- Tokens: {messages_token_len}\n- {reasoning_content=}\n- {content=}\n")
                if tool_calls is not None:
                    logger.info(f"- {tool_calls[0].function.name=}\n- {tool_calls[0].function.arguments=}\n")
                
            # the token limitation handling
            if tool_calls is None or (messages_token_len > int(0.9 * (self.llm_client.context_limit - self.llm_client.config.max_tokens))):
                self.conversation_history += messages[len(self.conversation_history) :]
                return sub_turn

            # temperary safeguard against infinite loops
            if messages_token_len > 65536:
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
            sub_turn += 1
        return sub_turn

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
        iteration = 0 # essentailly is the repetition
        
        
        while True:
            if self.verbose:
                logger.info(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            self.conversation_history.append(
                {"role": "user", "content": self._get_user_message(iteration)}
            )
            prev_conv_length = len(self.conversation_history)
            _ = self._run_turn(iteration)
            response = self.conversation_history[-1].content if hasattr(self.conversation_history[-1], "content") else self.conversation_history[-1].get("content")
            completion_keywords = ["analysis complete"] # currently only "analysis complete" as stop words
            if response and any(keyword in response.lower() for keyword in completion_keywords):
                if self.verbose:
                    logger.info("- LLM indicates analysis is complete")
                    # break
                # some logic to add about how to finalize the conversation

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
            if iteration >= self.max_iterations:
                if self.verbose:
                    logger.warning(f"Reached maximum iterations ({self.max_iterations})")
                break
        
        # Finalize memory
        self._finalize_memory()
        
        return {
            "vulnerabilities": self.found_vulnerabilities,
            "iterations": iteration + 1,
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
