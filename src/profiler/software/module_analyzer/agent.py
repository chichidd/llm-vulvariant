"""Module analyzer - analyze repository module structure via an LLM agent.

Uses a native tool-calling pattern and follows the structure of src/scanner/agent.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from llm import BaseLLMClient
from config import _path_config
from utils.logger import get_logger
from utils.tree_utils import build_directory_structure_tree
from profiler.software.module_analyzer.toolkit import ModuleAnalyzerToolkit
from profiler.software.module_analyzer.base import run_agent_analysis
from profiler.software.prompts import (
    MODULE_ANALYSIS_SYSTEM_PROMPT,
    MODULE_ANALYSIS_INITIAL_MESSAGE,
)
from profiler.software.module_analyzer.taxonomy_loader import load_ai_infra_taxonomy

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
        version: str = None,
        resume_from_conversation: bool = True,
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
        
        # Load AI Infra taxonomy
        taxonomy = load_ai_infra_taxonomy(_path_config['skill_path'] / "ai-infra-module-modeler")
        taxonomy_str = self._format_taxonomy(taxonomy) if taxonomy else "Not available"
        
        dir_structure = build_directory_structure_tree(file_list, max_depth=2)
        logger.info("Starting module analysis with native tool calling and AI Infra taxonomy...")
        
        # Enhance system prompt with taxonomy
        system_prompt = MODULE_ANALYSIS_SYSTEM_PROMPT + "\n\n" + self._get_taxonomy_instruction(taxonomy_str)
        
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
                system_prompt=system_prompt,
                initial_message=initial_message,
                tools=self.toolkit.get_available_tools(),
                toolkit=self.toolkit,
                max_iterations=self.max_iterations,
                storage_manager=storage_manager,
                conversation_name="module_analysis",
                path_parts=path_parts,
                resume_from_saved=resume_from_conversation,
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
    
    def _format_taxonomy(self, taxonomy: Dict[str, Any]) -> str:
        """Format taxonomy dictionary into a readable string."""
        lines = []
        for coarse_key, fine_dict in taxonomy.items():
            lines.append(f"- {coarse_key}")
            if isinstance(fine_dict, dict):
                for fine_key in fine_dict.keys():
                    lines.append(f"  - {coarse_key}.{fine_key}")
        return "\n".join(lines)
    
    def _get_taxonomy_instruction(self, taxonomy_str: str) -> str:
        """Generate instruction text for using the taxonomy."""
        return f"""# AI Infrastructure Module Taxonomy

When identifying modules, classify each module according to the following AI Infrastructure taxonomy. Each module should be assigned a category from this taxonomy.

## Available Categories (coarse.fine format):
{taxonomy_str}

## Module Classification Requirements:
1. For each identified module, assign it to one of the taxonomy categories above
2. Use the format: coarse_category.fine_category (e.g., "data_knowledge.preprocess_tokenization")
3. If a module spans multiple categories, choose the primary/dominant one
4. When calling the `finalize` tool, ensure each module has a "category" field with the taxonomy classification
5. The category should be in the format: "coarse.fine" (e.g., "training_optimization.training_loop")

## Example Module Format:
```json
{{
  "name": "Data Preprocessing",
  "category": "data_knowledge.preprocess_tokenization",
  "files": ["src/data/preprocessing"],
  "key_functions": ["tokenize", "normalize"],
  "dependencies": ["transformers", "numpy"],
  "purpose": "Handles text tokenization and normalization for model input"
}}
```

IMPORTANT: Every module you identify MUST have a valid "category" field matching one of the taxonomy categories listed above."""
