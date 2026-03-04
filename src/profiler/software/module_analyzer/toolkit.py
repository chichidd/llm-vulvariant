"""Tools exposed to the module analyzer agent."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolResult:
    """Result of a tool execution."""
    success: bool
    content: str
    error: Optional[str] = None


class ModuleAnalyzerToolkit:
    """Toolkit providing file system operations for module analysis."""
    
    def __init__(self, repo_path: Path, file_list: List[str]):
        """
        Initialize the toolkit.
        
        Args:
            repo_path: Path to the repository root.
            file_list: List of file paths in the repository.
        """
        self.repo_path = repo_path
        self.file_list = file_list
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return the list of available tools for module analysis."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_folder",
                    "description": "List the direct children (files and subfolders) of the specified folder(s) to explore the repository structure.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "One or more folder paths relative to the repository root. Use an empty string or '.' to represent the root directory.",
                            },
                        },
                        "required": ["folder_paths"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the full content of one or more files to analyze code structure and functionality.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "One or more file paths relative to the repository root.",
                            },
                        },
                        "required": ["file_paths"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finalize",
                    "description": "Complete the module analysis and return the final results. Call this tool when you have gathered enough information to identify all functional modules.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "modules": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string", "description": "Module name."},
                                        "category": {"type": "string", "description": "Module category (e.g., web_interface, data_loading, core_algorithm, etc.)."},
                                        "description": {"type": "string", "description": "Module functionality description."},
                                        "files": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "List of file paths related to the module. Make sure they are complete.",
                                        },
                                        "key_functions": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "List of key functions or class names in the module.",
                                        },
                                        "dependencies": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "List of other modules that this module depends on.",
                                        },
                                    },
                                    "required": ["name", "category", "description", "files"],
                                },
                                "description": "List of identified modules.",
                            },
                        },
                        "required": ["modules"],
                    },
                },
            },
        ]
    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        """Execute a tool by name with the given parameters."""
        try:
            if tool_name == "list_folder":
                return self._list_folder(**parameters)
            if tool_name == "read_file":
                return self._read_file(**parameters)
            if tool_name == "finalize":
                return self._finalize(**parameters)
            return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))
    
    def _list_folder(self, folder_paths: List[str]) -> ToolResult:
        """List the contents of one or more folders."""
        folder_paths = [p for p in folder_paths if isinstance(p, str)]
        
        if not folder_paths:
            return ToolResult(
                success=False,
                content="",
                error="No folder paths provided. Please provide one or more folder relative paths in folder_paths."
            )
        
        output_chunks: List[str] = []
        
        for raw_folder in folder_paths:
            folder = raw_folder.strip().replace("\\", "/")
            if folder.startswith("./"):
                folder = folder[2:]
            folder = folder.rstrip("/")
            
            prefix = folder + "/" if folder else ""
            matching_files = [f for f in self.file_list if f.startswith(prefix)] if prefix else list(self.file_list)
            
            if not matching_files:
                output_chunks.append(f"No files found in folder '{raw_folder}'.")
                continue
            
            children = []
            for path in matching_files:
                rest = path[len(prefix):] if prefix else path
                first = rest.split("/", 1)[0]
                children.append(first)
            
            unique_children = sorted(set(children))
            subdirs = []
            files = []
            
            for name in unique_children:
                is_dir = any(path.startswith(f"{prefix}{name}/") for path in matching_files)
                if is_dir:
                    subdirs.append(name + "/")
                else:
                    files.append(name)
            
            lines = [f"## Folder: {folder or '.'}", f"Subdirectories ({len(subdirs)}):"]
            if subdirs:
                lines.extend([f"- {d}" for d in subdirs])
            else:
                lines.append("- (none)")
            
            lines.append(f"Files ({len(files)}):")
            if files:
                lines.extend([f"- {f}" for f in files])
            else:
                lines.append("- (none)")
            
            output_chunks.append("\n".join(lines))
        
        return ToolResult(success=True, content="\n\n".join(output_chunks))
    
    def _read_file(self, file_paths: List[str]) -> ToolResult:
        """Read the contents of one or more files."""
        file_paths = [p for p in file_paths if isinstance(p, str) and p.strip()]
        
        if not file_paths:
            return ToolResult(
                success=False,
                content="",
                error="No file paths provided. Please provide one or more file paths in file_paths."
            )
        
        files_content = []
        
        for file_path in file_paths:
            try:
                # Find matching file
                actual_path = file_path
                if file_path not in self.file_list:
                    matching = [f for f in self.file_list if file_path in f]
                    if matching:
                        actual_path = matching[0]
                    else:
                        files_content.append(f"No file found for '{file_path}'.")
                        continue
                
                # Read file content
                if self.repo_path:
                    absolute_path = self.repo_path / actual_path
                else:
                    absolute_path = Path(actual_path)
                
                content = absolute_path.read_text(encoding="utf-8", errors="ignore")
                if len(content) > 10000:
                    content = content[:10000] + "\n\n... [content truncated] ..."
                
                files_content.append(f"## Full file content: {actual_path}\n\n```\n{content}\n```")
            
            except Exception as e:
                files_content.append(f"Error reading file '{file_path}': {str(e)}")
        
        if not files_content:
            return ToolResult(success=False, content="", error="Failed to read any of the requested file contents.")
        
        return ToolResult(success=True, content="\n\n".join(files_content))
    
    def _finalize(self, modules: List[Dict[str, Any]]) -> ToolResult:
        """Finalize the analysis and return the modules."""
        return ToolResult(
            success=True,
            content=json.dumps({"modules": modules}, ensure_ascii=False, indent=2)
        )





class FolderAnalyzerToolkit:
    """
    Folder analyzer toolkit providing file operations for module analysis.

    Designed for folder-splitting-based module analysis, and provides tools for
    two analysis scenarios:
    1. Leaf-module analysis: read code files within the folder
    2. Container-module analysis: read script files directly under the folder
    """
    
    def __init__(
        self,
        repo_path: Path,
        folder_path: str,
        available_files: List[str],
        max_file_content_length: int = 8000
    ):
        """
        Initialize the toolkit.
        
        Args:
            repo_path: Path to the repository root.
            folder_path: Current folder being analyzed (relative path).
            available_files: List of files available in this folder.
            max_file_content_length: Maximum length of file content to return.
        """
        self.repo_path = repo_path
        self.folder_path = folder_path
        self.available_files = available_files
        self.max_file_content_length = max_file_content_length
    
    def get_leaf_module_tools(self) -> List[Dict[str, Any]]:
        """Get tools for leaf module analysis (all code files)."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the content of a code file in the folder to understand the module's functionality.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path to read (relative to the repository root).",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
            self._get_finalize_tool(),
        ]
    
    def get_container_module_tools(self) -> List[Dict[str, Any]]:
        """Get tools for container module analysis (has subfolders)."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the content of a script file in the current folder to understand the module's integration logic.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path to read (relative to the repository root).",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
            self._get_finalize_tool(),
        ]
    
    def _get_finalize_tool(self) -> Dict[str, Any]:
        """Get the finalize tool definition."""
        return {
            "type": "function",
            "function": {
                "name": "finalize",
                "description": "Complete the analysis and return the results. Call this tool when you have thoroughly understood the module's functionality.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Module name. Use clear, descriptive English name reflecting the core responsibility (do not force it to match any examples).",
                        },
                        "description": {
                            "type": "string",
                            "description": "Describing what the module does and how it fits into the project.",
                        },
                        "key_functions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Most important functions in the module (exact names as in code).",
                        },
                        "key_classes": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Most important classes in the module (exact names as in code).",
                        },
                        "external_dependencies": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Key third-party libraries.",
                        },
                    },
                    "required": ["name", "description"],
                },
            },
        }
    
    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        """Execute a tool by name with the given parameters."""
        try:
            if tool_name == "read_file":
                return self._read_file(parameters.get("file_path", ""))
            if tool_name == "finalize":
                return self._finalize(parameters)
            return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as exc:
            return ToolResult(success=False, content="", error=str(exc))
    
    def _read_file(self, file_path: str) -> ToolResult:
        """Read file content."""
        if not file_path:
            return ToolResult(
                success=False,
                content="",
                error="No file path provided. Please specify the file to read."
            )
        
        # Normalize path
        file_path = file_path.strip().replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        
        # Check if file is in available files
        if file_path not in self.available_files:
            # Try to find a matching file
            matching = [f for f in self.available_files if f.endswith(file_path) or file_path in f]
            if matching:
                file_path = matching[0]
            else:
                available_str = "\n".join(f"- {f}" for f in self.available_files[:100])
                if len(self.available_files) > 100:
                    available_str += f"\n...and {len(self.available_files) - 100} more files"
                return ToolResult(
                    success=False,
                    content="",
                    error=f"File '{file_path}' is not in the current folder. Available files:\n{available_str}"
                )
        
        try:
            absolute_path = self.repo_path / file_path
            content = absolute_path.read_text(encoding="utf-8", errors="ignore")
            
            if len(content) > self.max_file_content_length:
                content = content[:self.max_file_content_length] + "\n\n... [Content truncated] ..."
            
            return ToolResult(
                success=True,
                content=f"## File content: {file_path}\n\n```\n{content}\n```"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                content="",
                error=f"Error reading file: {str(e)}"
            )
    
    def _finalize(self, parameters: Dict[str, Any]) -> ToolResult:
        """Finalize the analysis and return the result."""
        result = {
            "name": parameters.get("name", "Unnamed Module"),
            "description": parameters.get("description", ""),
            "key_functions": parameters.get("key_functions", []),
            "key_classes": parameters.get("key_classes", []),
            "external_dependencies": parameters.get("external_dependencies", []),
        }
        return ToolResult(
            success=True,
            content=json.dumps(result, ensure_ascii=False, indent=2)
        )
