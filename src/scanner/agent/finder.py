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
        self.toolkit = AgenticToolkit(repo_path)
        self.found_vulnerabilities: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, Any]] = []

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
            if self.verbose:
                logger.info(
                    f"[Iteration {iteration + 1}.{sub_turn}]\n{reasoning_content=}\n{content=}\n{tool_calls=}"
                )
            if tool_calls is None:
                self.conversation_history += messages[len(self.conversation_history) :]
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
                    self.found_vulnerabilities.append(vuln_report)
                    if self.verbose:
                        logger.warning(
                            f"  [VULN FOUND] {vuln_report.get('file_path', 'unknown')} - {vuln_report.get('vulnerability_type', 'unknown')}"
                        )
                tool_result_content = result.content if result.success else f"Error: {result.error}"
                if len(tool_result_content) > 10000:
                    tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                messages.append({"role": "tool", "tool_call_id": tool.id, "content": tool_result_content})
            sub_turn += 1
        return sub_turn

    def _get_user_message(self, iteration: int) -> str:
        if iteration == 0:
            return build_initial_user_message(self.software_profile)
        return build_intermediate_user_message()

    def run(self) -> Dict[str, Any]:
        if self.verbose:
            logger.info("Starting agentic vulnerability analysis with native tool calling...")
        self.conversation_history = [
            {"role": "system", "content": build_system_prompt(self.vulnerability_profile, self.toolkit)}
        ]
        iteration = 0
        while True:
            if self.verbose:
                logger.info(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            self.conversation_history.append(
                {"role": "user", "content": self._get_user_message(iteration)}
            )
            prev_conv_length = len(self.conversation_history)
            _ = self._run_turn(iteration)
            response = self.conversation_history[-1].content if hasattr(self.conversation_history[-1], "content") else self.conversation_history[-1].get("content")
            completion_keywords = ["analysis complete", "no findings", "no more", "finished", "cannot find"]
            if response and any(keyword in response.lower() for keyword in completion_keywords):
                if self.verbose:
                    logger.info("LLM indicates analysis is complete")
                break

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
                self.conversation_history.append(
                    {"role": "assistant", "content": json.dumps(summarized, ensure_ascii=False, indent=2)}
                )
            iteration += 1
            if iteration >= self.max_iterations:
                if self.verbose:
                    logger.warning(f"Reached maximum iterations ({self.max_iterations})")
                break
        return {
            "vulnerabilities": self.found_vulnerabilities,
            "iterations": iteration + 1,
            "conversation_length": len(self.conversation_history),
        }
