"""Tools exposed to the agentic vulnerability finder."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from config import _path_config
from utils.codeql_native import CodeQLAnalyzer
from utils.language import (
    dedupe_languages,
    detect_languages as detect_repo_languages,
    get_extensions,
)
from utils.logger import get_logger
from scanner.agent.toolkit_codeql import ToolkitCodeQLMixin
from scanner.agent.toolkit_fs import ToolResult, ToolkitFSMixin
from scanner.agent.toolkit_profile import ToolkitProfileMixin
from scanner.agent.toolkit_reporting import ToolkitReportingMixin
from scanner.agent.shared_memory import SharedPublicMemoryManager

logger = get_logger(__name__)


class AgenticToolkit(
    ToolkitCodeQLMixin,
    ToolkitFSMixin,
    ToolkitReportingMixin,
    ToolkitProfileMixin,
):
    def __init__(
        self,
        repo_path: Path,
        memory_manager=None,
        software_profile=None,
        shared_public_memory_manager: Optional[SharedPublicMemoryManager] = None,
        languages: Optional[List[str]] = None,
        codeql_database_names: Optional[Dict[str, str]] = None,
    ):
        self.repo_path = repo_path.resolve()
        self._file_cache: Dict[str, str] = {}
        self._memory_manager = memory_manager
        self._software_profile = software_profile
        self._shared_public_memory_manager = shared_public_memory_manager
        self._file_to_module_cache: Dict[str, str] = {}  # file_path -> module_name
        self._module_cache: Dict[str, Dict] = {}  # module_name -> module_info
        self._call_graph_edges: List[Dict] = []  # call graph edges from repo_analysis
        self._file_callers: Dict[str, set] = {}  # file -> set of caller files
        self._file_callees: Dict[str, set] = {}  # file -> set of callee files
        self._iteration_touched_files: Set[str] = set()

        # Language configuration (multi-language aware).
        self._languages: List[str] = self._resolve_languages(languages=languages)
        self._source_extensions: Set[str] = self._resolve_source_extensions()
        
        # CodeQL configuration
        self._codeql_template_root: Path = Path(_path_config['repo_root']) / '.codeql-queries'
        self._codeql_db_base_path: Path = _path_config.get('codeql_db_path', Path.home() / 'vuln' / 'codeql_dbs')
        self._codeql_database_names: Dict[str, str] = self._normalize_codeql_database_names(
            codeql_database_names
        )
        self._codeql_analyzer: Optional[CodeQLAnalyzer] = None
        self._codeql_query_dirs: Dict[str, Path] = {}
        self._codeql_query_dirs_ready: Set[str] = set()
        self._init_codeql()
        
        self._build_module_cache()

    def _resolve_repo_path(
        self,
        path_value: str,
        *,
        kind: str,
    ) -> tuple[Optional[Path], Optional[str]]:
        """Resolve one repo-relative path and reject paths that escape the checkout."""
        raw_path = str(path_value or "").strip()
        if not raw_path:
            return None, f"{kind.title()} path is empty"

        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_path / candidate
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            return None, f"{kind.title()} path escapes repository root: {raw_path}"
        return resolved, None

    def _resolve_repo_relative_path(
        self,
        path_value: str,
        *,
        kind: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Resolve one repo-relative path and return a normalized relative key."""
        resolved_path, error = self._resolve_repo_path(path_value, kind=kind)
        if error or resolved_path is None:
            return None, error
        return str(resolved_path.relative_to(self.repo_path)), None

    def _invalid_path_error(self, path_name: str, path_text: str) -> str:
        """Build a consistent error for invalid tool paths."""
        return (
            f"Invalid {path_name}: {path_text}. "
            f"Only repository-relative paths inside {self.repo_path} are allowed."
        )

    def _resolve_languages(
        self,
        languages: Optional[List[str]],
    ) -> List[str]:
        if languages is not None:
            return dedupe_languages(languages)
        detected = dedupe_languages(detect_repo_languages(self.repo_path))
        return detected

    def _resolve_source_extensions(self) -> Set[str]:
        extensions: Set[str] = set()
        for lang in self._languages:
            try:
                extensions |= get_extensions(lang)
            except ValueError:
                logger.warning("Unsupported language in scanner toolkit: %s", lang)
        return extensions

    def _primary_language(self) -> str:
        return self._languages[0] if self._languages else "python"

    def _normalize_codeql_database_names(
        self,
        codeql_database_names: Optional[Dict[str, str]],
    ) -> Dict[str, str]:
        if not isinstance(codeql_database_names, dict):
            return {}
        normalized: Dict[str, str] = {}
        for lang, db_name in codeql_database_names.items():
            lang_key = str(lang).strip().lower()
            db_value = str(db_name).strip()
            if lang_key and db_value:
                normalized[lang_key] = db_value
        return normalized

    def _build_codeql_analyzer(self) -> CodeQLAnalyzer:
        """Build the CodeQL analyzer instance used by the toolkit."""
        return CodeQLAnalyzer()

    def set_memory_manager(self, memory_manager):
        """Set or update the memory manager reference."""
        self._memory_manager = memory_manager
        # Query workspace lives under memory_manager.output_dir.
        # Reset cached state so future queries use the current output directory.
        self._codeql_query_dirs = {}
        self._codeql_query_dirs_ready = set()

    def start_iteration_tracking(self) -> None:
        """Reset per-iteration full-file read tracking."""
        self._iteration_touched_files = set()

    def _record_touched_file(self, file_path: str) -> None:
        """Track one file that received a whole-file read during this iteration."""
        normalized_path = str(file_path or "").strip()
        if normalized_path:
            self._iteration_touched_files.add(normalized_path)

    def consume_tracked_files(self) -> List[str]:
        """Return and clear the files eligible for auto-completion in this iteration."""
        touched_files = sorted(self._iteration_touched_files)
        self._iteration_touched_files = set()
        return touched_files

    def get_available_tools(self) -> List[Dict[str, Any]]:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the content of a file in the repository to inspect source code for potential vulnerabilities.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path relative to the repository root.",
                                "minLength": 1,
                            },
                            "start_line": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Optional start line number (1-indexed). If omitted, read from the beginning.",
                            },
                            "end_line": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Optional end line number (1-indexed). If omitted, read to end of file.",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_file",
                    "description": "Search for a pattern (regex or plain text) in a file and return matching lines with line numbers.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Relative file path.",
                                "minLength": 1,
                            },
                            "pattern": {
                                "type": "string",
                                "description": "Search pattern (regex supported).",
                                "minLength": 1,
                            },
                            "context_lines": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Number of context lines before/after each match (default: 2).",
                            },
                        },
                        "required": ["file_path", "pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_folder",
                    "description": "Search for a pattern across all source files under a folder and return file paths with matching lines.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {"type": "string", "description": "Relative folder path.", "minLength": 1},
                            "pattern": {
                                "type": "string",
                                "description": "Search pattern (regex supported).",
                                "minLength": 1,
                            },
                            "max_results": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Maximum number of results to return (default: 50).",
                            },
                        },
                        "required": ["folder_path", "pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_files_in_folder",
                    "description": "List all source files in a folder along with their sizes.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_path": {
                                "type": "string",
                                "description": "Relative folder path.",
                                "minLength": 1,
                            },
                            "recursive": {
                                "type": "boolean",
                                "description": "Whether to search recursively (default: True).",
                            },
                        },
                        "required": ["folder_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_code",
                    "description": "Extract the source code of a specified function or class from a file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Relative file path.", "minLength": 1},
                            "function_name": {
                                "type": "string",
                                "description": "Function or class name to extract.",
                                "minLength": 1,
                            },
                        },
                        "required": ["file_path", "function_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_imports",
                    "description": "Get all import/include statements in a source file to show which modules and symbols are imported.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Relative file path.", "minLength": 1}
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_data_flow",
                    "description": "Deeply analyze a Python function's code structure and provide details: parameters, variable usage, function calls, attribute access, string operations, assignments, return values, etc.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Relative file path.", "minLength": 1},
                            "function_name": {
                                "type": "string",
                                "description": "Function name to analyze.",
                                "minLength": 1,
                            },
                        },
                        "required": ["file_path", "function_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "report_vulnerability",
                    "description": "Report a potential vulnerability you found.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "File path where the vulnerability exists.", "minLength": 1},
                            "function_name": {"type": "string", "description": "Function or method name that contains the vulnerability.", "minLength": 1},
                            "line_number": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "Approximate line number of the vulnerability.",
                            },
                            "vulnerability_type": {"type": "string", "description": "Vulnerability type.", "minLength": 1},
                            "description": {"type": "string", "description": "Detailed vulnerability description.", "minLength": 1},
                            "evidence": {"type": "string", "description": "Code snippet or evidence proving the vulnerability exists.", "minLength": 1},
                            "similarity_to_known": {"type": "string", "description": "Why this is similar to the known vulnerability.", "minLength": 1},
                            "confidence": {
                                "type": "string",
                                "enum": ["high", "medium", "low"],
                                "description": "Confidence: high / medium / low",
                            },
                            "attack_scenario": {"type": "string", "description": "Attack scenario / exploit narrative.", "minLength": 1},
                        },
                        "required": [
                            "file_path",
                            "vulnerability_type",
                            "description",
                            "evidence",
                            "similarity_to_known",
                            "confidence",
                        ],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "check_file_status",
                    "description": "Check the scan status of a file or list of files. Returns whether each file is 'pending', 'completed', or 'not_tracked'. Use this to avoid re-scanning files you've already analyzed.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minLength": 1,
                                "description": "List of file paths to check status for.",
                            },
                        },
                        "required": ["file_paths"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_module_call_relationships",
                    "description": "Get the call relationships (callers and callees) of a file or module. Returns which modules call this file's module and which modules this file's module calls. Useful for tracing data flow and understanding code dependencies.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path to get call relationships for. The tool will find which module contains this file.",
                                "minLength": 1,
                            },
                            "module_name": {
                                "type": "string",
                                "description": "Optional: directly specify the module name instead of file path.",
                                "minLength": 1,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_related_files",
                    "description": "Get caller or callee files for a given file. Returns a list of file paths from modules that either call or are called by the module containing the given file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path to find related files for.",
                                "minLength": 1,
                            },
                            "query_type": {
                                "type": "string",
                                "enum": ["caller", "callee"],
                                "description": "Type of relationship: 'caller' returns files from modules that call this file's module, 'callee' returns files from modules that this file's module calls.",
                            },
                        },
                        "required": ["file_path", "query_type"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "run_codeql_query",
                    "description": "Run a CodeQL query on the pre-loaded CodeQL database. Pass the QL query code as a string. Results are saved to codeql-results folder and key findings are recorded in memory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "minLength": 1,
                                "description": "The CodeQL query code as a QL string.",
                            },
                            "query_name": {
                                "type": "string",
                                "minLength": 1,
                                "description": "A descriptive name for this query (e.g., 'injection_check', 'taint_analysis'). Used for naming the result file.",
                            },
                        },
                        "required": ["query", "query_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_codeql_results",
                    "description": "Read full CodeQL query results from a previous query. Use this when the summary was truncated and you need to see all findings.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query_name": {
                                "type": "string",
                                "minLength": 1,
                                "description": "The query name used when running the query.",
                            },
                            "offset": {
                                "type": "integer",
                                "minimum": 0,
                                "description": "Start index for pagination (default: 0).",
                            },
                            "limit": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 1000,
                                "description": "Maximum number of findings to return (default: 50).",
                            },
                        },
                        "required": ["query_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mark_file_completed",
                    "description": "Mark a file as completed after thorough analysis. Use this when you are confident that no more vulnerabilities remain in the file. This helps track progress and avoid re-scanning.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "File path to mark as completed.",
                                "minLength": 1,
                            },
                            "reason": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Brief explanation of why the file is considered complete (e.g., 'No dangerous patterns found', 'All sinks properly sanitized').",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
        ]
        if self._shared_public_memory_manager is not None:
            tools.append(
                {
                    "type": "function",
                    "function": {
                        "name": "read_shared_public_memory",
                        "description": (
                            "Read reusable scan observations collected from previous scans of the "
                            "same target repository and commit in the current batch run."
                        ),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Optional lexical filter over stored observations.",
                                },
                                "limit": {
                                    "type": "integer",
                                    "minimum": 1,
                                    "maximum": 20,
                                    "description": "Maximum number of observations to return (default: 10).",
                                },
                            },
                        },
                    },
                }
            )
        return tools

    @staticmethod
    def _normalize_tool_type(value: Any, expected_type: str) -> bool:
        if expected_type == "string":
            return isinstance(value, str)
        if expected_type == "integer":
            return isinstance(value, int) and not isinstance(value, bool)
        if expected_type == "boolean":
            return isinstance(value, bool)
        if expected_type == "array":
            return isinstance(value, list)
        if expected_type == "object":
            return isinstance(value, dict)
        return True

    def _get_tool_spec(self, tool_name: str) -> Dict[str, Any]:
        for tool in self.get_available_tools():
            fn = tool.get("function", {})
            if fn.get("name") == tool_name:
                return fn
        return {}

    def _validate_tool_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> Optional[str]:
        spec = self._get_tool_spec(tool_name)
        if not spec:
            return None

        parameters_schema = spec.get("parameters", {})
        properties = parameters_schema.get("properties", {})
        required = set(parameters_schema.get("required", []))

        for required_field in required:
            if required_field not in parameters:
                return f"Missing required parameter: {required_field}"

        for key, value in parameters.items():
            if key not in properties:
                return f"Unknown parameter: {key}"

            prop_schema = properties.get(key, {})
            value_error = self._validate_schema_constraints(key, value, prop_schema)
            if value_error is not None:
                return value_error

            expected_type = prop_schema.get("type")
            if expected_type and not self._normalize_tool_type(value, expected_type):
                return f"Invalid type for parameter {key}: expected {expected_type}"

            if expected_type == "array":
                item_schema = prop_schema.get("items") or {}
                item_type = item_schema.get("type")
                if item_type:
                    for item in value:
                        if not self._normalize_tool_type(item, item_type):
                            return f"Invalid item type in parameter {key}: expected {item_type}"

        for path_field, kind in (("file_path", "file"), ("folder_path", "folder")):
            if path_field not in parameters:
                continue
            raw_path = str(parameters.get(path_field, "") or "").strip()
            if Path(raw_path).is_absolute() or ".." in Path(raw_path).parts:
                return self._invalid_path_error(path_field, raw_path)
            if path_field == "folder_path":
                resolved_path, error = self._resolve_repo_path(raw_path, kind=kind)
                if error:
                    return self._invalid_path_error(path_field, raw_path)
                if resolved_path is not None and resolved_path.exists() and not resolved_path.is_dir():
                    return f"Not a folder: {raw_path}"

        file_paths = parameters.get("file_paths")
        if isinstance(file_paths, list):
            for raw_path in file_paths:
                normalized = str(raw_path or "").strip()
                if Path(normalized).is_absolute() or ".." in Path(normalized).parts:
                    return self._invalid_path_error("file_path", normalized)

        if "start_line" in parameters or "end_line" in parameters:
            start_line = parameters.get("start_line")
            end_line = parameters.get("end_line")
            if (
                isinstance(start_line, int)
                and isinstance(end_line, int)
                and end_line < start_line
            ):
                return "Invalid range for read_file: end_line must be greater than or equal to start_line"

        return None

    def _validate_schema_constraints(self, name: str, value: Any, schema: Dict[str, Any]) -> Optional[str]:
        if "enum" in schema:
            allowed_values = schema.get("enum") or []
            if value not in allowed_values:
                return (
                    f"Invalid value for parameter {name}: expected one of "
                    f"{', '.join(str(v) for v in allowed_values)}"
                )

        if isinstance(value, (int, float)):
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum is not None and value < minimum:
                return (
                    f"Invalid value for parameter {name}: minimum is {minimum} "
                    f"(expected >= {minimum})"
                )
            if maximum is not None and value > maximum:
                return (
                    f"Invalid value for parameter {name}: maximum is {maximum} "
                    f"(expected <= {maximum})"
                )

        if isinstance(value, str):
            min_length = schema.get("minLength")
            max_length = schema.get("maxLength")
            value_length = len(value)
            if min_length is not None and value_length < min_length:
                return f"Invalid value for parameter {name}: expected minimum length {min_length}"
            if max_length is not None and value_length > max_length:
                return f"Invalid value for parameter {name}: expected maximum length {max_length}"

        if isinstance(value, (list, tuple)):
            min_length = schema.get("minLength")
            max_length = schema.get("maxLength")
            value_length = len(value)
            if min_length is not None and value_length < min_length:
                return f"Invalid value for parameter {name}: expected minimum length {min_length}"
            if max_length is not None and value_length > max_length:
                return f"Invalid value for parameter {name}: expected maximum length {max_length}"

        return None

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        if not isinstance(parameters, dict):
            return ToolResult(
                success=False,
                content="",
                error="Tool arguments must be a JSON object.",
            )

        validation_error = self._validate_tool_parameters(tool_name, parameters)
        if validation_error:
            return ToolResult(
                success=False,
                content="",
                error=validation_error,
            )
        try:
            if tool_name == "read_file":
                result = self._read_file(**parameters)
            elif tool_name == "search_in_file":
                result = self._search_in_file(**parameters)
            elif tool_name == "search_in_folder":
                result = self._search_in_folder(**parameters)
            elif tool_name == "list_files_in_folder":
                result = self._list_files_in_folder(**parameters)
            elif tool_name == "get_function_code":
                result = self._get_function_code(**parameters)
            elif tool_name == "get_imports":
                result = self._get_imports(**parameters)
            elif tool_name == "analyze_data_flow":
                result = self._analyze_data_flow(**parameters)
            elif tool_name == "report_vulnerability":
                result = self._report_vulnerability(**parameters)
            elif tool_name == "check_file_status":
                result = self._check_file_status(**parameters)
            elif tool_name == "get_module_call_relationships":
                result = self._get_module_call_relationships(**parameters)
            elif tool_name == "get_related_files":
                result = self._get_related_files(**parameters)
            elif tool_name == "run_codeql_query":
                result = self._run_codeql_query(**parameters)
            elif tool_name == "read_codeql_results":
                result = self._read_codeql_results(**parameters)
            elif tool_name == "mark_file_completed":
                result = self._mark_file_completed(**parameters)
            elif tool_name == "read_shared_public_memory":
                result = self._read_shared_public_memory(**parameters)
            else:
                return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
            self._track_tool_file_touch(tool_name, parameters, result)
            self._record_shared_public_observation(tool_name, parameters, result)
            return result
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _record_shared_public_observation(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        result: ToolResult,
    ) -> None:
        """Persist allowlisted tool observations into shared public memory."""
        if not result.success or not isinstance(result.metadata, dict):
            return
        if tool_name == "read_shared_public_memory":
            return
        if self._shared_public_memory_manager is None:
            return
        try:
            self._shared_public_memory_manager.record_observation(
                tool_name,
                parameters,
                result.metadata,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Failed to record shared public memory observation: %s", exc)

    def _track_tool_file_touch(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        result: ToolResult,
    ) -> None:
        """Track only whole-file reads so auto-completion does not over-count coverage."""
        if not result.success:
            return
        if tool_name != "read_file":
            return
        start_line = parameters.get("start_line")
        end_line = parameters.get("end_line")
        if start_line not in (None, 1) or end_line is not None:
            return
        if result.truncated:
            return
        file_path, error = self._resolve_repo_relative_path(
            parameters.get("file_path", ""),
            kind="file",
        )
        if error or not file_path:
            return
        self._record_touched_file(file_path)

    def _analyze_data_flow(self, file_path: str, function_name: str) -> ToolResult:
        full_path, error = self._resolve_repo_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        if full_path.suffix.lower() not in {".py", ".pyi"}:
            return ToolResult(
                success=False,
                content="",
                error="analyze_data_flow only supports Python source files",
            )
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
            lines = content.split("\n")
            target_func = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
                    target_func = node
                    break
            if not target_func:
                return ToolResult(success=False, content="", error=f"Function not found: {function_name}")
            analysis: Dict[str, Any] = {
                "function_name": function_name,
                "parameters": [arg.arg for arg in target_func.args.args],
                "variables_used": [],
                "function_calls": [],
                "attribute_accesses": [],
                "string_operations": [],
                "assignments": [],
                "returns": [],
                "code_with_line_numbers": [],
            }
            start_line = target_func.lineno - 1
            end_line = target_func.end_lineno if hasattr(target_func, "end_lineno") else start_line + 50
            func_lines = lines[start_line:end_line]
            analysis["code_with_line_numbers"] = [
                f"{start_line + i + 1}: {line}" for i, line in enumerate(func_lines)
            ]
            for node in ast.walk(target_func):
                if isinstance(node, ast.Name):
                    analysis["variables_used"].append(
                        {"name": node.id, "context": type(node.ctx).__name__, "line": node.lineno}
                    )
                if isinstance(node, ast.Call):
                    call_info: Dict[str, Any] = {"line": node.lineno}
                    if isinstance(node.func, ast.Attribute):
                        call_info["type"] = "method_call"
                        call_info["object"] = ast.unparse(node.func.value)
                        call_info["method"] = node.func.attr
                        call_info["full_call"] = f"{call_info['object']}.{call_info['method']}"
                    elif isinstance(node.func, ast.Name):
                        call_info["type"] = "function_call"
                        call_info["function"] = node.func.id
                        call_info["full_call"] = node.func.id
                    else:
                        call_info["type"] = "complex_call"
                        call_info["full_call"] = ast.unparse(node.func)
                    call_info["args"] = [ast.unparse(arg) for arg in node.args]
                    call_info["kwargs"] = {kw.arg: ast.unparse(kw.value) for kw in node.keywords}
                    analysis["function_calls"].append(call_info)
                if isinstance(node, ast.Attribute):
                    analysis["attribute_accesses"].append(
                        {
                            "object": ast.unparse(node.value),
                            "attribute": node.attr,
                            "full": ast.unparse(node),
                            "line": node.lineno,
                        }
                    )
                if isinstance(node, ast.JoinedStr):
                    analysis["string_operations"].append(
                        {"type": "f-string", "expression": ast.unparse(node), "line": node.lineno}
                    )
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    analysis["string_operations"].append(
                        {
                            "type": "binary_op_add",
                            "expression": ast.unparse(node),
                            "line": node.lineno,
                        }
                    )
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ["format", "join"]:
                        analysis["string_operations"].append(
                            {
                                "type": node.func.attr,
                                "expression": ast.unparse(node),
                                "line": node.lineno,
                            }
                        )
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        analysis["assignments"].append(
                            {
                                "target": ast.unparse(target),
                                "value": ast.unparse(node.value),
                                "line": node.lineno,
                            }
                        )
                if isinstance(node, ast.Return) and node.value:
                    analysis["returns"].append(
                        {"value": ast.unparse(node.value), "line": node.lineno}
                    )
            seen_vars = set()
            unique_vars = []
            for var in analysis["variables_used"]:
                var_key = (var["name"], var["line"])
                if var_key not in seen_vars:
                    seen_vars.add(var_key)
                    unique_vars.append(var)
            analysis["variables_used"] = unique_vars[:50]
            analysis["function_calls"] = analysis["function_calls"][:50]
            analysis["attribute_accesses"] = analysis["attribute_accesses"][:50]
            analysis["file_path"] = file_path
            return ToolResult(
                success=True,
                content=json.dumps(analysis, indent=2, ensure_ascii=False),
                metadata=analysis,
            )
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _read_shared_public_memory(self, query: str = "", limit: int = 10) -> ToolResult:
        """Read shared public scan observations for this target repo and commit."""
        if self._shared_public_memory_manager is None:
            return ToolResult(
                success=False,
                content="",
                error="Shared public memory is not configured for this scan.",
            )
        normalized_limit = max(1, min(int(limit), 20))
        payload = self._shared_public_memory_manager.read_observations(
            query=query,
            limit=normalized_limit,
        )
        return ToolResult(success=True, content=json.dumps(payload, indent=2, ensure_ascii=False))
