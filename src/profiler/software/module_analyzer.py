"""模块分析器 - 使用 LLM 智能体方式分析模块结构

使用原生工具调用（tool calling）模式，遵循 src/scanner/agent 的结构。
"""

import copy
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from llm import BaseLLMClient
from utils.logger import get_logger
from utils.tree_utils import build_directory_structure_tree
from utils.agent_conversation import compress_iteration_conversation, make_serializable, clear_reasoning_content
from .toolkit import ModuleAnalyzerToolkit
from .prompts import (
    MODULE_ANALYSIS_SYSTEM_PROMPT,
    MODULE_ANALYSIS_INITIAL_MESSAGE,
)

logger = get_logger(__name__)


MODULE_ANALYSIS_COMPRESSION_PROMPT = """你是模块结构分析的对话压缩助手。请压缩assistant在本轮模块分析中的对话记录，保留能够支撑后续分析的关键信息。

请输出JSON，字段含义如下（保持中文键名）：
{
    "iteration_number": <迭代编号>,
    "summary": "<一句话概括本轮做了什么>",
    "actions": [
        {"type": "list_folder" | "read_file" | "其他", "target": "路径", "result": "获取到的要点/状态"}
    ],
    "findings": ["关键发现或对模块的判断"],
    "open_questions": ["仍需确认的点"],
    "next_steps": ["下一步要查看的目录/文件或分析方向"],
    "evidence": ["引用的文件/段落/函数等，尽量具体"],
    "errors": ["遇到的错误或缺失的信息"],
    "modules_hypothesis": ["当前推测的模块候选及理由"]
}

注意：
- 精简但不要丢失action获取到的关键信息，尤其是list_folder的目录列表、read_file的核心内容。
- 如果没有相关项，用空数组。
- 只返回JSON，不要额外说明。
"""


class ModuleAnalyzer:
    """使用 LLM 智能体方式分析仓库模块结构"""
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        max_iterations: int = 100
    ):
        self.llm_client = llm_client
        self.max_iterations = max_iterations
        self.conversation_history: List[Dict[str, Any]] = []
        self.toolkit: Optional[ModuleAnalyzerToolkit] = None
    
    
    def analyze(
        self,
        repo_info: Dict,
        repo_path: Path = None
    ) -> Dict[str, Any]:
        """
        分析模块结构
        
        Returns:
            {
                "modules": [...],
                "iterations": int
            }
        """
        file_list = repo_info.get("files", [])
        
        # Initialize toolkit
        self.toolkit = ModuleAnalyzerToolkit(repo_path, file_list)
        
        dir_structure = build_directory_structure_tree(file_list, max_depth=2)
        logger.info("Starting module analysis with native tool calling...")
        
        # Initialize conversation
        self.conversation_history = self._initialize_conversation(repo_info, dir_structure)
        
        final_result = None
        for iteration in range(self.max_iterations):
            logger.info(f"Module analysis iteration {iteration + 1}/{self.max_iterations}")
            prev_length = len(self.conversation_history)
            
            try:
                # Run one turn of the agent
                is_complete, result = self._run_turn(iteration)
                
                if is_complete:
                    final_result = {
                        "modules": result.get("modules", []),
                        "iterations": iteration + 1
                    }
                    logger.info(f"Module analysis completed in {iteration + 1} iterations")
                    break
                
            except Exception as e:
                logger.warning(f"Error during module analysis iteration {iteration + 1}: {e}")
                # Add a user message to handle the error and continue
                self.conversation_history.append({
                    "role": "user",
                    "content": f"处理响应时出错: {str(e)}。请继续分析。"
                })

            # Compress the iteration if there were new messages
            if len(self.conversation_history) > prev_length:
                self.conversation_history = self._compress_iteration(
                    self.conversation_history, 
                    prev_length, 
                    iteration
                )
        
        if final_result is None:
            logger.warning("Module analysis did not converge, returning empty result")
            final_result = {
                "modules": [],
                "iterations": self.max_iterations
            }
        
        return final_result
    
    def _initialize_conversation(self, repo_info: Dict, dir_structure: str) -> List[Dict]:
        """初始化对话"""
        initial_message = MODULE_ANALYSIS_INITIAL_MESSAGE.format(
            dir_structure=dir_structure,
            file_count=len(repo_info.get("files", [])),
            readme_content=repo_info.get('readme_content', '')[:2000],
            languages=', '.join(repo_info.get('languages', [])),
            dependencies=', '.join(repo_info.get('dependencies', [])[:20])
        )
        
        return [
            {"role": "system", "content": MODULE_ANALYSIS_SYSTEM_PROMPT},
            {"role": "user", "content": initial_message}
        ]

    def _run_turn(self, iteration: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Run a single turn of the agent conversation.
        
        Returns:
            (is_complete, result): A tuple where is_complete indicates if analysis
            is finished, and result contains the modules if complete.
        """
        messages = clear_reasoning_content(self.conversation_history)
        
        while True:
            try:
                message = self.llm_client.chat(
                    messages,
                    tools=self.toolkit.get_available_tools(),
                    tool_choice="auto",
                )
            except Exception as exc:
                logger.error(f"LLM call failed: {exc}")
                raise
            
            content = getattr(message, "content", None)
            tool_calls = getattr(message, "tool_calls", None)
            
            if content is None and tool_calls is None:
                logger.error("LLM returned no content and no tool calls.")
                continue
            
            # Add assistant message to history
            messages.append(message)
            
            logger.debug(f"[Iteration {iteration + 1}] content={content[:200] if content else None}... tool_calls={tool_calls}")
            
            # If no tool calls, update conversation history and return
            if tool_calls is None:
                self.conversation_history = messages
                return False, {}
            
            # Process tool calls
            for tool in tool_calls:
                tool_name = tool.function.name
                try:
                    parameters = json.loads(tool.function.arguments)
                except json.JSONDecodeError:
                    parameters = {}
                    logger.error("Failed to parse tool arguments")
                
                logger.debug(f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:500]}...")
                
                result = self.toolkit.execute_tool(tool_name, parameters)
                
                logger.debug(f"  [TOOL RESULT] {result.content[:200] if result.content else result.error}...")
                
                # Check if this is the finalize tool
                if tool_name == "finalize" and result.success:
                    # Parse the modules from the result
                    try:
                        finalize_result = json.loads(result.content)
                        # Update conversation history before returning
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool.id,
                            "content": result.content
                        })
                        self.conversation_history = messages
                        return True, finalize_result
                    except json.JSONDecodeError:
                        logger.error("Failed to parse finalize result")
                
                # Add tool result to messages
                tool_result_content = result.content if result.success else f"Error: {result.error}"
                if len(tool_result_content) > 10000:
                    tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
                
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool.id,
                    "content": tool_result_content
                })
            
            # After processing all tool calls, continue the loop to get next response
            # This allows multiple tool calls in a single turn

    def _compress_iteration(
        self,
        conversation_history: List[Dict[str, Any]],
        prev_length: int,
        iteration: int
    ) -> List[Dict[str, Any]]:
        """Compress the latest iteration to keep context size manageable.
        
        This function ensures proper message alternation by adding a user message
        after the compressed assistant summary to avoid consecutive assistant messages.
        """
        iteration_history = conversation_history[prev_length:]
        if not iteration_history:
            return conversation_history

        summarized = compress_iteration_conversation(
            self.llm_client,
            iteration,
            iteration_history,
            verbose=False,
            compression_prompt=MODULE_ANALYSIS_COMPRESSION_PROMPT,
        )

        truncated_history = conversation_history[:prev_length]
        
        # Ensure we don't have consecutive assistant messages
        # Check the last message in truncated_history
        last_role = None
        if truncated_history:
            last_msg = truncated_history[-1]
            if hasattr(last_msg, "role"):
                last_role = last_msg.role
            elif isinstance(last_msg, dict):
                last_role = last_msg.get("role")
        
        # If the last message was an assistant message, we need to add a user message first
        if last_role == "assistant":
            truncated_history.append({
                "role": "user",
                "content": "请继续分析。以下是上一轮的分析总结："
            })
        
        # Add the compressed summary as assistant message
        truncated_history.append({
            "role": "assistant",
            "content": json.dumps(make_serializable(summarized), ensure_ascii=False, indent=2)
        })
        
        # Add a user prompt to continue the analysis
        truncated_history.append({
            "role": "user",
            "content": "请继续你的分析，或者如果你已经收集了足够的信息，调用 finalize 工具返回最终结果。"
        })
        
        return truncated_history