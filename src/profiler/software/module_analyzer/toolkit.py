"""Tools exposed to the module analyzer agent."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

VALID_MODULE_CONFIDENCE_VALUES = ("high", "medium", "low")


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
                                        "responsibility": {
                                            "type": "string",
                                            "description": "One-sentence summary of the concern this module owns.",
                                        },
                                        "entry_points": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "Externally visible commands, APIs, routes, or startup hooks owned by the module.",
                                        },
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
                                        "interfaces": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "Interfaces the module exposes or relies on, such as CLI, HTTP API, worker, or library API.",
                                        },
                                        "depends_on": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "List of other modules that this module depends on.",
                                        },
                                        "dependencies": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "Compatibility copy of the module dependency list for downstream consumers that still read dependencies.",
                                        },
                                        "boundary_rationale": {
                                            "type": "string",
                                            "description": "Short justification for why these files belong to one logical module.",
                                        },
                                        "evidence_paths": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "description": "Repository-relative paths inspected as evidence for this module boundary.",
                                        },
                                        "confidence": {
                                            "type": "string",
                                            "enum": list(VALID_MODULE_CONFIDENCE_VALUES),
                                            "description": "Confidence level for this module summary: high, medium, or low.",
                                        },
                                    },
                                    "required": [
                                        "name",
                                        "category",
                                        "description",
                                        "responsibility",
                                        "entry_points",
                                        "files",
                                        "key_functions",
                                        "interfaces",
                                        "depends_on",
                                        "dependencies",
                                        "boundary_rationale",
                                        "evidence_paths",
                                        "confidence",
                                    ],
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
        if not isinstance(modules, list):
            return ToolResult(
                success=False,
                content="",
                error="modules must be a list of module objects.",
            )

        required_fields = (
            "name",
            "category",
            "description",
            "responsibility",
            "entry_points",
            "files",
            "key_functions",
            "interfaces",
            "depends_on",
            "dependencies",
            "boundary_rationale",
            "evidence_paths",
            "confidence",
        )
        list_fields = (
            "entry_points",
            "files",
            "key_functions",
            "interfaces",
            "depends_on",
            "dependencies",
            "evidence_paths",
        )
        string_fields = (
            "name",
            "category",
            "description",
            "responsibility",
            "boundary_rationale",
            "confidence",
        )
        normalized_modules: List[Dict[str, Any]] = []
        for index, module in enumerate(modules):
            if not isinstance(module, dict):
                return ToolResult(
                    success=False,
                    content="",
                    error=f"modules[{index}] must be an object.",
                )

            missing_fields = [field for field in required_fields if field not in module]
            if missing_fields:
                return ToolResult(
                    success=False,
                    content="",
                    error=f"modules[{index}] missing required fields: {', '.join(missing_fields)}",
                )

            normalized_module = dict(module)
            for field in string_fields:
                value = normalized_module.get(field)
                if not isinstance(value, str) or not value.strip():
                    return ToolResult(
                        success=False,
                        content="",
                        error=f"modules[{index}].{field} must be a non-empty string.",
                    )
                normalized_module[field] = value.strip()

            for field in list_fields:
                value = normalized_module.get(field)
                if not isinstance(value, list):
                    return ToolResult(
                        success=False,
                        content="",
                        error=f"modules[{index}].{field} must be a list of strings.",
                    )
                cleaned_values = []
                for item in value:
                    if not isinstance(item, str) or not item.strip():
                        return ToolResult(
                            success=False,
                            content="",
                            error=f"modules[{index}].{field} must contain only non-empty strings.",
                        )
                    cleaned_values.append(item.strip())
                normalized_module[field] = cleaned_values

            if normalized_module["confidence"] not in VALID_MODULE_CONFIDENCE_VALUES:
                return ToolResult(
                    success=False,
                    content="",
                    error=(
                        f"modules[{index}].confidence must be one of "
                        f"{', '.join(VALID_MODULE_CONFIDENCE_VALUES)}."
                    ),
                )

            if normalized_module["depends_on"] != normalized_module["dependencies"]:
                return ToolResult(
                    success=False,
                    content="",
                    error=(
                        f"modules[{index}].depends_on must match modules[{index}].dependencies "
                        "to preserve the legacy contract."
                    ),
                )

            normalized_modules.append(normalized_module)

        return ToolResult(
            success=True,
            content=json.dumps({"modules": normalized_modules}, ensure_ascii=False, indent=2)
        )
