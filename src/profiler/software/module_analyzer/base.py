"""Module analyzer base utilities - shared agent execution logic."""

import json
from typing import Any, Dict, List, Tuple, Optional

from llm import BaseLLMClient
from utils.logger import get_logger

logger = get_logger(__name__)


def run_agent_analysis(
    llm_client: BaseLLMClient,
    system_prompt: str,
    initial_message: str,
    tools: List[Dict[str, Any]],
    toolkit: Any,  # FolderAnalyzerToolkit or ModuleAnalyzerToolkit
    max_iterations: int,
    update_stats_callback: Optional[callable] = None,
    storage_manager: Optional[Any] = None,
    conversation_name: str = None,
    path_parts: tuple = None,
) -> Tuple[bool, Dict[str, Any], int, List[Dict[str, Any]]]:
    """
    Shared helper to run an LLM agent analysis.

    Runs within a single turn, but may perform multiple LLM calls.

    Args:
        llm_client: LLM client.
        system_prompt: System prompt.
        initial_message: Initial user message.
        tools: List of available tools.
        toolkit: Tool executor (must implement execute_tool).
        max_iterations: Maximum number of LLM calls.
        update_stats_callback: Callback to update stats.
        storage_manager: Storage manager for persisting the conversation.
        conversation_name: Conversation name to distinguish different runs.
        path_parts: Path components used to determine the storage location.
    
    Returns:
        (is_complete, result, llm_calls, messages): 
            - is_complete: Whether the analysis completed successfully.
            - result: Result dict.
            - llm_calls: Number of LLM calls.
            - messages: Full conversation history.
    """
    # Try to resume from a checkpointed conversation (loaded from module_analysis)
    messages = None
    start_iteration = 0
    
    if storage_manager and conversation_name and path_parts:
        # Load the corresponding conversation from the module_analysis directory
        saved_conv = storage_manager.load_conversation("module_analysis", *path_parts)
        if saved_conv and saved_conv.get('conversation_name') == conversation_name:
            logger.info(f"Resuming from saved conversation: {conversation_name}")
            messages = saved_conv.get('messages', [])
            start_iteration = saved_conv.get('llm_calls', 0)
            logger.info(f"Resuming from iteration {start_iteration}/{max_iterations}")
    
    # If no checkpoint is available, initialize a new conversation
    if messages is None:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message},
        ]
    
    # Process within a single turn, allowing up to max_iterations LLM calls
    for llm_call_idx in range(start_iteration, max_iterations):
        llm_call_count = llm_call_idx + 1
        
        # Update stats
        if update_stats_callback:
            update_stats_callback()
        
        try:
            response = llm_client.chat(
                messages=messages,
                tools=tools,
                tool_choice="auto",
            )
        except Exception as e:
            logger.error(f"LLM call failed (attempt {llm_call_count}/{max_iterations}): {e}")
            return False, {}, llm_call_count, messages
        
        content = getattr(response, "content", None)
        tool_calls = getattr(response, "tool_calls", None)
        
        if content is None and tool_calls is None:
            logger.warning(f"LLM returned no content and no tool calls (call {llm_call_count})")
            continue
        
        messages.append(response)
        
        logger.debug(f"[LLM call {llm_call_count}] content={content[:200] if content else None}... tool_calls={tool_calls}")
        
        if tool_calls is None:
            # No tool calls: try parsing the result from the content
            if content:
                try:
                    result = json.loads(content)
                    logger.info(f"Analysis completed with {llm_call_count} LLM calls (from content)")
                    # Save the final conversation
                    if storage_manager and conversation_name and path_parts:
                        _save_conversation_final(storage_manager, conversation_name, messages, llm_call_count, result, path_parts)
                    return True, result, llm_call_count, messages
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse JSON from content: {e}")
            logger.debug(f"No tool calls in response, analysis may be incomplete (call {llm_call_count})")
            return False, {}, llm_call_count, messages
        
        # Handle tool calls
        has_finalize = False
        for tool in tool_calls:
            tool_name = tool.function.name
            try:
                parameters = json.loads(tool.function.arguments)
            except json.JSONDecodeError:
                parameters = {}
                logger.error("Failed to parse tool arguments")
            
            logger.debug(f"  [TOOL] {tool_name}: {json.dumps(parameters, ensure_ascii=False)[:500]}...")
            
            result = toolkit.execute_tool(tool_name, parameters)
            
            logger.debug(f"  [TOOL RESULT] {result.content[:200] if result.content else result.error}...")
            
            # If tool is finalize, return the result
            if tool_name == "finalize" and result.success:
                try:
                    finalize_result = json.loads(result.content)
                    
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool.id,
                        "content": result.content
                    })
                    logger.info(f"Analysis completed with {llm_call_count} LLM calls")
                    # Save the final conversation
                    if storage_manager and conversation_name and path_parts:
                        _save_conversation_final(storage_manager, conversation_name, messages, llm_call_count, finalize_result, path_parts)
                    return True, finalize_result, llm_call_count, messages
                except json.JSONDecodeError:
                    logger.error("Failed to parse finalize result")
                has_finalize = True
            
            # Add tool result
            tool_result_content = result.content if result.success else f"Error: {result.error}"
            if len(tool_result_content) > 10000:
                tool_result_content = tool_result_content[:10000] + "\n... [truncated]"
            
            messages.append({
                "role": "tool",
                "tool_call_id": tool.id,
                "content": tool_result_content,
            })
        
        # finalize was called but parsing failed; stop
        if has_finalize:
            return False, {}, llm_call_count, messages
    
    # No valid result produced
    logger.warning(f"Agent did not produce valid result after {max_iterations} LLM calls")
    # Save final (failed) state
    if storage_manager and conversation_name and path_parts:
        _save_conversation_final(storage_manager, conversation_name, messages, max_iterations, {}, path_parts, success=False)
    return False, {}, max_iterations, messages


def _save_conversation_final(
    storage_manager,
    conversation_name: str,
    messages: List[Dict[str, Any]],
    llm_calls: int,
    result: Dict[str, Any],
    path_parts: tuple,
    success: bool = True
) -> None:
    """Persist the final conversation (saved under the module_analysis directory)."""
    try:
        from utils.agent_conversation import make_serializable
        from datetime import datetime
        conversation_data = {
            "conversation_name": conversation_name,
            "timestamp": datetime.now().isoformat(),
            "llm_calls": llm_calls,
            "status": "completed" if success else "failed",
            "messages": make_serializable(messages),
            "result": result,
        }
        # Save to the module_analysis directory; use conversation_name as file_identifier
        storage_manager.save_conversation(
            "module_analysis", 
            conversation_data, 
            *path_parts,
            file_identifier=conversation_name
        )
        status_text = "completed" if success else "failed"
        logger.info(f"Saved {status_text} conversation: {conversation_name} (calls: {llm_calls})")
    except Exception as e:
        logger.warning(f"Failed to save final conversation: {e}")
