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
                actual_path, resolution_error = self._resolve_requested_file_path(file_path)
                if actual_path is None:
                    files_content.append(resolution_error or f"No file found for '{file_path}'.")
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

    def _resolve_requested_file_path(self, file_path: str) -> tuple[Optional[str], Optional[str]]:
        """Resolve one requested file path without silently picking ambiguous matches."""
        normalized_path = file_path.strip().replace("\\", "/")
        while normalized_path.startswith("./"):
            normalized_path = normalized_path[2:]

        if normalized_path in self.file_list:
            return normalized_path, None

        suffix_matches = [
            candidate
            for candidate in self.file_list
            if candidate.endswith(f"/{normalized_path}") or candidate == normalized_path
        ]
        if len(suffix_matches) == 1:
            return suffix_matches[0], None
        if len(suffix_matches) > 1:
            matches_preview = ", ".join(sorted(suffix_matches)[:5])
            return None, (
                f"Ambiguous file path '{file_path}'. "
                f"Please use an exact relative path. Matches: {matches_preview}"
            )

        return None, f"No file found for '{file_path}'."
    
    def _finalize(self, modules: List[Dict[str, Any]]) -> ToolResult:
        """Finalize the analysis and return the modules."""
        return ToolResult(
            success=True,
            content=json.dumps({"modules": modules}, ensure_ascii=False, indent=2)
        )
