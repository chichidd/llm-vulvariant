"""Module analyzer - analyze repository module structure via an LLM agent.

Uses a native tool-calling pattern and follows the structure of src/scanner/agent.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from llm import BaseLLMClient
from utils.logger import get_logger
from utils.tree_utils import build_directory_structure_tree
from profiler.software.module_analyzer.toolkit import ModuleAnalyzerToolkit
from profiler.software.module_analyzer.base import run_agent_analysis
from profiler.software.prompts import (
    MODULE_ANALYSIS_SYSTEM_PROMPT,
    MODULE_ANALYSIS_INITIAL_MESSAGE,
)

logger = get_logger(__name__)


class ModuleAnalyzer:
    """Analyze repository module structure using an LLM agent."""
    
    def __init__(
        self,
        llm_client: BaseLLMClient,
        max_iterations: int = 100
    ):
        self.llm_client = llm_client
        self.max_iterations = max_iterations
        self.toolkit: Optional[ModuleAnalyzerToolkit] = None
        self.conversation_history: List[Dict[str, Any]] = []  # Conversation history
    
    
    def analyze(
        self,
        repo_info: Dict,
        repo_path: Path = None,
        storage_manager = None,
        repo_name: str = None,
        version: str = None
    ) -> Dict[str, Any]:
        """Analyze module structure.

        Runs within a single turn and allows up to ``max_iterations`` LLM calls.

        Args:
            repo_info: Repository metadata.
            repo_path: Repository path.
            storage_manager: Storage manager for persisting the conversation.
            repo_name: Repository name.
            version: Version identifier.

        Returns:
            A dict in the form:
            {
                "modules": [...],
                "llm_calls": int
            }
        """
        file_list = repo_info.get("files", [])
        
        # Initialize toolkit
        self.toolkit = ModuleAnalyzerToolkit(repo_path, file_list)
        
        dir_structure = build_directory_structure_tree(file_list, max_depth=2)
        logger.info("Starting module analysis with native tool calling...")
        
        # Initialize conversation
        initial_message = MODULE_ANALYSIS_INITIAL_MESSAGE.format(
            dir_structure=dir_structure,
            file_count=len(repo_info.get("files", [])),
            readme_content=repo_info.get('readme_content', '')[:10000],
            languages=', '.join(repo_info.get('languages', [])),
            dependencies=', '.join(repo_info.get('dependencies', [])[:100])
        )
        
        # Prepare path_parts for persisting the conversation
        path_parts = None
        if storage_manager and repo_name:
            path_parts = (repo_name, version) if version else (repo_name,)
        
        try:
            # Run the agent using shared function
            is_complete, result, llm_calls, messages = run_agent_analysis(
                llm_client=self.llm_client,
                system_prompt=MODULE_ANALYSIS_SYSTEM_PROMPT,
                initial_message=initial_message,
                tools=self.toolkit.get_available_tools(),
                toolkit=self.toolkit,
                max_iterations=self.max_iterations,
                storage_manager=storage_manager,
                conversation_name="module_analysis",
                path_parts=path_parts,
            )
            
            # Save conversation history
            self.conversation_history = messages
            logger.debug(f"Module analysis result: {result}")
            if is_complete:
                return {
                    "modules": result.get("modules", []),
                    "llm_calls": llm_calls
                }
            else:
                logger.warning(f"Module analysis did not complete after {llm_calls} LLM calls")
                return {
                    "modules": [],
                    "llm_calls": llm_calls
                }
                
        except Exception as e:
            logger.error(f"Error during module analysis: {e}")
            return {
                "modules": [],
                "llm_calls": 0
            }

