"""Tools exposed to the agentic vulnerability finder."""

import ast
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import _path_config
from utils.codeql_native import CodeQLAnalyzer
from utils.language import (
    detect_language as detect_repo_language,
    get_codeql_pack,
    get_extensions,
)
from utils.logger import get_logger
from utils.tree_utils import build_path_tree, format_file_size, render_tree
from scanner.agent.utils import _to_dict

logger = get_logger(__name__)

@dataclass
class ToolResult:
    success: bool
    content: str
    error: Optional[str] = None



class AgenticToolkit:
    def __init__(self, repo_path: Path, memory_manager=None, software_profile=None,
                 codeql_database_name: Optional[str] = None, language: Optional[str] = None):
        self.repo_path = repo_path
        self._file_cache: Dict[str, str] = {}
        self._memory_manager = memory_manager
        self._software_profile = software_profile
        self._file_to_module_cache: Dict[str, str] = {}  # file_path -> module_name
        self._module_cache: Dict[str, Dict] = {}  # module_name -> module_info
        self._call_graph_edges: List[Dict] = []  # call graph edges from repo_analysis
        self._file_callers: Dict[str, set] = {}  # file -> set of caller files
        self._file_callees: Dict[str, set] = {}  # file -> set of callee files

        # Language configuration (auto-detect if not specified)
        self._language: str = language or detect_repo_language(repo_path)
        self._source_extensions = get_extensions(self._language)
        
        # CodeQL configuration
        self._codeql_db_base_path: Path = _path_config.get('codeql_db_path', Path.home() / 'vuln' / 'codeql_dbs')
        self._codeql_database_name: Optional[str] = codeql_database_name
        self._codeql_analyzer: Optional[CodeQLAnalyzer] = None
        self._codeql_query_dir: Optional[Path] = None
        self._init_codeql()
        
        self._build_module_cache()
    
    def _init_codeql(self):
        """Initialize CodeQL analyzer and query directory."""
        try:
            self._codeql_analyzer = CodeQLAnalyzer()
            if not self._codeql_analyzer.is_available:
                logger.warning("CodeQL CLI is not available. CodeQL tools will be disabled.")
                self._codeql_analyzer = None
        except Exception as e:
            logger.warning(f"Failed to initialize CodeQL analyzer: {e}")
            self._codeql_analyzer = None
        
        # Template query directory (contains pre-installed qlpack.yml / lock files)
        self._codeql_query_template_dir = Path(_path_config['repo_root']) / '.codeql-queries' / self._language
        # Actual query directory will be created lazily under the output folder
        self._codeql_query_dir: Optional[Path] = None
        self._codeql_query_dir_ready = False
    
    def _setup_query_dir(self) -> bool:
        """Lazily set up the CodeQL query directory under the output folder.
        
        Creates <output_dir>/codeql-queries/<language>/ and copies yml files
        (qlpack.yml, codeql-pack.lock.yml) from the template directory so that
        generated .ql files live alongside the results.
        """
        if not self._memory_manager:
            logger.warning("Memory manager not available. Cannot set up query directory.")
            return False
        
        output_dir: Path = self._memory_manager.output_dir
        query_dir = output_dir / "codeql-queries" / self._language
        if self._codeql_query_dir_ready and self._codeql_query_dir == query_dir:
            return True

        if self._codeql_query_dir_ready and self._codeql_query_dir != query_dir:
            logger.info(
                "CodeQL query directory changed from %s to %s; rebuilding query workspace.",
                self._codeql_query_dir,
                query_dir,
            )

        query_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy yml files from template directory if available
        if self._codeql_query_template_dir and self._codeql_query_template_dir.exists():
            for yml_file in self._codeql_query_template_dir.glob("*.yml"):
                dest = query_dir / yml_file.name
                if not dest.exists():
                    shutil.copy2(yml_file, dest)
                    logger.info(f"Copied {yml_file.name} to {query_dir}")
        
        self._codeql_query_dir = query_dir
        self._codeql_query_dir_ready = True
        logger.info(f"CodeQL query directory set up at: {query_dir}")
        return True

    def _ensure_query_pack(self) -> bool:
        """Ensure the CodeQL query pack is prepared with dependencies installed."""
        if not self._setup_query_dir():
            return False
        
        qlpack_file = self._codeql_query_dir / "qlpack.yml"
        qlpack_lock_file = self._codeql_query_dir / "codeql-pack.lock.yml"
        
        # Check if already prepared (lock file copied from template or previously installed)
        if qlpack_lock_file.exists():
            return True
        
        # Create qlpack.yml if not exists (no template available)
        if not qlpack_file.exists():
            codeql_pack = get_codeql_pack(self._language)
            if not codeql_pack:
                logger.warning(f"No CodeQL pack available for language: {self._language}")
                return False
            pack_name = f"llm-vulvariant-queries-{self._language}"
            qlpack_content = f"""name: {pack_name}
version: 1.0.0
description: CodeQL queries for LLM vulnerability variant analysis
dependencies:
  {codeql_pack}: "*"
"""
            qlpack_file.write_text(qlpack_content, encoding="utf-8")
        
        # Install dependencies
        logger.info("Installing CodeQL pack dependencies...")
        try:
            result = subprocess.run(
                ["codeql", "pack", "install", str(self._codeql_query_dir)],
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode != 0:
                logger.error(f"CodeQL pack install failed: {result.stderr}")
                return False
            logger.info("CodeQL pack dependencies installed successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("CodeQL pack install timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to install CodeQL pack: {e}")
            return False
    
    def set_codeql_database(self, database_name: str):
        """Set or update the CodeQL database name."""
        self._codeql_database_name = database_name
    
    def _get_codeql_database_path(self) -> Optional[Path]:
        """Get the full path to the CodeQL database."""
        if not self._codeql_database_name:
            return None
        db_path = self._codeql_db_base_path / self._codeql_database_name
        if db_path.exists():
            return db_path
        return None
    
    def _build_module_cache(self):
        """Build lookup caches from software profile."""
        if not self._software_profile:
            return
        
        modules = []
        if hasattr(self._software_profile, 'modules'):
            modules = self._software_profile.modules
        elif isinstance(self._software_profile, dict):
            modules = self._software_profile.get('modules', [])
        
        for m in modules:
            m_dict = _to_dict(m)
            if not m_dict:
                continue
            
            module_name = m_dict.get('name', '')
            self._module_cache[module_name] = m_dict
            
            # Map files to module
            for f in m_dict.get('files', []):
                self._file_to_module_cache[f] = module_name
        
        # Build call graph cache
        self._build_call_graph_cache()
    
    def _build_call_graph_cache(self):
        """Build file-level caller/callee lookup from call_graph_edges."""
        self._file_callers = {}
        self._file_callees = {}
        
        # Get call_graph_edges from repo_info.repo_analysis
        repo_analysis = {}
        if isinstance(self._software_profile, dict):
            repo_info = self._software_profile.get('repo_info', {})
            repo_analysis = repo_info.get('repo_analysis', {})
        elif hasattr(self._software_profile, 'repo_info'):
            repo_info = self._software_profile.repo_info or {}
            repo_analysis = repo_info.get('repo_analysis', {}) if isinstance(repo_info, dict) else {}
        
        self._call_graph_edges = repo_analysis.get('call_graph_edges', [])
        
        for edge in self._call_graph_edges:
            caller_file = edge.get('caller_file', '')
            callee_file = edge.get('callee_file', '')
            
            if caller_file and callee_file:
                # callee_file's callers include caller_file
                if callee_file not in self._file_callers:
                    self._file_callers[callee_file] = set()
                self._file_callers[callee_file].add(caller_file)
                
                # caller_file's callees include callee_file
                if caller_file not in self._file_callees:
                    self._file_callees[caller_file] = set()
                self._file_callees[caller_file].add(callee_file)
    
    def set_memory_manager(self, memory_manager):
        """Set or update the memory manager reference."""
        self._memory_manager = memory_manager
        # Query workspace lives under memory_manager.output_dir.
        # Reset cached state so future queries use the current output directory.
        self._codeql_query_dir = None
        self._codeql_query_dir_ready = False
    
    def set_software_profile(self, software_profile):
        """Set or update the software profile reference."""
        self._software_profile = software_profile
        self._build_module_cache()


    @staticmethod
    def _format_size(size_bytes: int) -> str:
        return format_file_size(size_bytes)

    @staticmethod
    def _build_path_tree(paths_with_values: List[Any]) -> Dict:
        return build_path_tree(paths_with_values)

    @staticmethod
    def _render_tree(node: Dict, prefix: str = "", value_formatter=None) -> List[str]:
        return render_tree(node, prefix, value_formatter)

    # ---- Multi-language file iteration helpers ----

    def _is_source_file(self, path: Path) -> bool:
        """Check if *path* is a source file of the current language."""
        return path.suffix.lower() in self._source_extensions

    def _iter_source_files(self, root: Path, recursive: bool = True):
        """Yield source files under *root* matching the current language."""
        IGNORED_DIRS = {".git", "node_modules", "__pycache__", "build", "dist",
                        ".tox", "venv", ".venv", "vendor", "third_party"}
        if recursive:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    if self._is_source_file(fpath):
                        yield fpath
        else:
            for fpath in root.iterdir():
                if fpath.is_file() and self._is_source_file(fpath):
                    yield fpath

    def get_available_tools(self) -> List[Dict[str, Any]]:
        return [
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
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "Optional start line number (1-indexed). If omitted, read from the beginning.",
                            },
                            "end_line": {
                                "type": "integer",
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
                            "file_path": {"type": "string", "description": "Relative file path."},
                            "pattern": {"type": "string", "description": "Search pattern (regex supported)."},
                            "context_lines": {
                                "type": "integer",
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
                            "folder_path": {"type": "string", "description": "Relative folder path."},
                            "pattern": {"type": "string", "description": "Search pattern (regex supported)."},
                            "max_results": {
                                "type": "integer",
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
                            "folder_path": {"type": "string", "description": "Relative folder path."},
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
                            "file_path": {"type": "string", "description": "Relative file path."},
                            "function_name": {"type": "string", "description": "Function or class name to extract."},
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
                            "file_path": {"type": "string", "description": "Relative file path."}
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "analyze_data_flow",
                    "description": "Deeply analyze a function's code structure and provide details: parameters, variable usage, function calls, attribute access, string operations, assignments, return values, etc.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string", "description": "Relative file path."},
                            "function_name": {"type": "string", "description": "Function name to analyze."},
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
                            "file_path": {"type": "string", "description": "File path where the vulnerability exists."},
                            "function_name": {"type": "string", "description": "Function or method name that contains the vulnerability."},
                            "line_number": {"type": "integer", "description": "Approximate line number of the vulnerability."},
                            "vulnerability_type": {"type": "string", "description": "Vulnerability type."},
                            "description": {"type": "string", "description": "Detailed vulnerability description."},
                            "evidence": {"type": "string", "description": "Code snippet or evidence proving the vulnerability exists."},
                            "similarity_to_known": {"type": "string", "description": "Why this is similar to the known vulnerability."},
                            "confidence": {"type": "string", "description": "Confidence: high / medium / low"},
                            "attack_scenario": {"type": "string", "description": "Attack scenario / exploit narrative."},
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
                            },
                            "module_name": {
                                "type": "string",
                                "description": "Optional: directly specify the module name instead of file path.",
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
                                "description": "The CodeQL query code as a QL string.",
                            },
                            "query_name": {
                                "type": "string",
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
                                "description": "The query name used when running the query.",
                            },
                            "offset": {
                                "type": "integer",
                                "description": "Start index for pagination (default: 0).",
                            },
                            "limit": {
                                "type": "integer",
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
                            },
                            "reason": {
                                "type": "string",
                                "description": "Brief explanation of why the file is considered complete (e.g., 'No dangerous patterns found', 'All sinks properly sanitized').",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
        ]

    def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        try:
            if tool_name == "read_file":
                return self._read_file(**parameters)
            if tool_name == "search_in_file":
                return self._search_in_file(**parameters)
            if tool_name == "search_in_folder":
                return self._search_in_folder(**parameters)
            if tool_name == "list_files_in_folder":
                return self._list_files_in_folder(**parameters)
            if tool_name == "get_function_code":
                return self._get_function_code(**parameters)
            if tool_name == "get_imports":
                return self._get_imports(**parameters)
            if tool_name == "analyze_data_flow":
                return self._analyze_data_flow(**parameters)
            if tool_name == "report_vulnerability":
                return self._report_vulnerability(**parameters)
            if tool_name == "check_file_status":
                return self._check_file_status(**parameters)
            if tool_name == "get_module_call_relationships":
                return self._get_module_call_relationships(**parameters)
            if tool_name == "get_related_files":
                return self._get_related_files(**parameters)
            if tool_name == "run_codeql_query":
                return self._run_codeql_query(**parameters)
            if tool_name == "read_codeql_results":
                return self._read_codeql_results(**parameters)
            if tool_name == "mark_file_completed":
                return self._mark_file_completed(**parameters)
            return ToolResult(success=False, content="", error=f"Unknown tool: {tool_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _read_file(self, file_path: str, start_line: int = None, end_line: int = None) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            if start_line is not None or end_line is not None:
                start_idx = (start_line - 1) if start_line else 0
                end_idx = end_line if end_line else len(lines)
                lines = lines[start_idx:end_idx]
                numbered_lines = [f"{start_idx + i + 1}: {line}" for i, line in enumerate(lines)]
                content = "\n".join(numbered_lines)
            else:
                numbered_lines = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
                content = "\n".join(numbered_lines)
            if len(content) > 5000:
                content = content[:5000] + "\n... [truncated, use start_line/end_line to read specific sections]"
            return ToolResult(success=True, content=content)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _search_in_file(self, file_path: str, pattern: str, context_lines: int = 2) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")
            regex = re.compile(pattern, re.IGNORECASE)
            matches = []
            for i, line in enumerate(lines):
                if regex.search(line):
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    context = []
                    for j in range(start, end):
                        prefix = ">>> " if j == i else "    "
                        context.append(f"{prefix}{j + 1}: {lines[j]}")
                    matches.append("\n".join(context))
            if not matches:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            result = f"Found {len(matches)} matches:\n\n" + "\n\n---\n\n".join(matches[:20])
            if len(matches) > 20:
                result += f"\n\n... and {len(matches) - 20} more matches"
            return ToolResult(success=True, content=result)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _search_in_folder(self, folder_path: str, pattern: str, max_results: int = 50) -> ToolResult:
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            file_results: Dict[str, List[Any]] = {}
            total_matches = 0
            for src_file in self._iter_source_files(full_path):
                if total_matches >= max_results:
                    break
                try:
                    content = src_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.split("\n")
                    for i, line in enumerate(lines):
                        if regex.search(line):
                            rel_path = str(src_file.relative_to(self.repo_path))
                            file_results.setdefault(rel_path, []).append((i + 1, line.strip()))
                            total_matches += 1
                            if total_matches >= max_results:
                                break
                except Exception:  # pylint: disable=broad-except
                    continue
            if not file_results:
                return ToolResult(success=True, content=f"No matches found for pattern: {pattern}")
            result_lines = [f"Found {total_matches} matches in {len(file_results)} files:\n"]
            for file_path in sorted(file_results.keys()):
                result_lines.append(f"\n{file_path}:")
                for line_num, line_content in file_results[file_path][:10]:
                    result_lines.append(f"  L{line_num}: {line_content}")
                if len(file_results[file_path]) > 10:
                    result_lines.append(
                        f"  ... and {len(file_results[file_path]) - 10} more matches in this file"
                    )
            return ToolResult(success=True, content="\n".join(result_lines))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _list_files_in_folder(self, folder_path: str, recursive: bool = True) -> ToolResult:
        full_path = self.repo_path / folder_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"Folder not found: {folder_path}")
        try:
            file_info: List[Any] = []
            total_size = 0
            for src_file in self._iter_source_files(full_path, recursive=recursive):
                rel_path = str(src_file.relative_to(self.repo_path))
                size = src_file.stat().st_size
                total_size += size
                file_info.append((rel_path, size))
            if not file_info:
                return ToolResult(success=True, content="No source files found")
            tree = self._build_path_tree(file_info)
            tree_lines = self._render_tree(tree, value_formatter=self._format_size)
            result = f"Found {len(file_info)} source files (total: {self._format_size(total_size)}):\n\n" + "\n".join(tree_lines)
            return ToolResult(success=True, content=result)
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_function_code(self, file_path: str, function_name: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.split("\n")

            # Python: use ast for precise extraction
            if full_path.suffix == ".py":
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if node.name == function_name:
                            start_line = node.lineno - 1
                            end_line = node.end_lineno if hasattr(node, "end_lineno") else start_line + 50
                            func_lines = lines[start_line:end_line]
                            numbered = [f"{start_line + i + 1}: {line}" for i, line in enumerate(func_lines)]
                            return ToolResult(success=True, content="\n".join(numbered))
                return ToolResult(success=False, content="", error=f"Function/class not found: {function_name}")

            # Non-Python: regex-based extraction (C/C++/Go/Java/JS/Rust/Ruby…)
            # Look for a line that starts with the function name and capture until a
            # balanced closing brace (or end-of-indent for Ruby).
            pattern = re.compile(
                rf'(?:^|\s)(?:(?:pub(?:\(crate\))?\s+)?(?:static\s+)?(?:async\s+)?'
                rf'(?:fn|func|def|function|void|int|auto|class|struct)\s+)?'
                rf'{re.escape(function_name)}\s*[(<]',
                re.MULTILINE,
            )
            match = pattern.search(content)
            if match:
                start_idx = content[:match.start()].count("\n")
                # Heuristic: grab up to 80 lines or until brace-depth returns to 0
                depth = 0
                end_idx = start_idx
                started = False
                for idx in range(start_idx, min(len(lines), start_idx + 200)):
                    if '{' in lines[idx]:
                        depth += lines[idx].count('{') - lines[idx].count('}')
                        started = True
                    elif '}' in lines[idx]:
                        depth += lines[idx].count('{') - lines[idx].count('}')
                    end_idx = idx + 1
                    if started and depth <= 0:
                        break
                func_lines = lines[start_idx:end_idx]
                numbered = [f"{start_idx + i + 1}: {line}" for i, line in enumerate(func_lines)]
                return ToolResult(success=True, content="\n".join(numbered))

            return ToolResult(success=False, content="", error=f"Function/class not found: {function_name}")
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _get_imports(self, file_path: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
            suffix = full_path.suffix.lower()

            imports: List[str] = []

            if suffix == ".py":
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append(
                                f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                            )
                    elif isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        names = ", ".join(
                            alias.name + (f" as {alias.asname}" if alias.asname else "") for alias in node.names
                        )
                        imports.append(f"from {module} import {names}")
            elif suffix in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}:
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#include"):
                        imports.append(stripped)
            elif suffix == ".go":
                # Match single and grouped imports
                imports.extend(re.findall(r'^\s*import\s+(?:".+?"|\((?:[^)]+)\))', content, re.MULTILINE | re.DOTALL))
            elif suffix == ".java":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("import "):
                        imports.append(stripped.rstrip(";"))
            elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
                imports.extend(re.findall(r'^(?:import|const|let|var)\s+.*(?:from|require)\s*[\(\'"].*', content, re.MULTILINE))
            elif suffix == ".rs":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("use ") or stripped.startswith("extern crate "):
                        imports.append(stripped.rstrip(";"))
            elif suffix == ".rb":
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("require ") or stripped.startswith("require_relative "):
                        imports.append(stripped)
            else:
                # Fallback: grep for common import patterns
                for line in content.splitlines():
                    stripped = line.strip()
                    if re.match(r'^(import |from |#include |require |use |extern crate )', stripped):
                        imports.append(stripped)

            if not imports:
                return ToolResult(success=True, content="No imports found")
            return ToolResult(success=True, content="\n".join(imports))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _analyze_data_flow(self, file_path: str, function_name: str) -> ToolResult:
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(success=False, content="", error=f"File not found: {file_path}")
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
            return ToolResult(success=True, content=json.dumps(analysis, indent=2, ensure_ascii=False))
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(success=False, content="", error=str(exc))

    def _report_vulnerability(self, **kwargs) -> ToolResult:
        return ToolResult(success=True, content=json.dumps(kwargs, indent=2, ensure_ascii=False))

    def _check_file_status(self, file_paths: List[str]) -> ToolResult:
        """Check the scan status of files from memory."""
        if not self._memory_manager:
            return ToolResult(
                success=True,
                content=json.dumps({
                    "note": "Memory not available. All files are considered pending.",
                    "files": {fp: "pending" for fp in file_paths}
                }, indent=2)
            )
        
        result = {}
        for fp in file_paths:
            status = self._memory_manager.memory.file_status.get(fp, "not_tracked")
            result[fp] = status
        
        # Add summary
        completed = sum(1 for s in result.values() if s == "completed")
        pending = sum(1 for s in result.values() if s == "pending")
        not_tracked = sum(1 for s in result.values() if s == "not_tracked")
        
        return ToolResult(
            success=True,
            content=json.dumps({
                "summary": f"{completed} completed, {pending} pending, {not_tracked} not tracked",
                "files": result
            }, indent=2, ensure_ascii=False)
        )

    def _mark_file_completed(self, file_path: str, reason: str = "") -> ToolResult:
        """Mark a file as completed after thorough analysis.
        
        Args:
            file_path: File path to mark as completed
            reason: Brief explanation of why the file is considered complete
        
        Returns:
            ToolResult confirming the file was marked
        """
        if not self._memory_manager:
            return ToolResult(
                success=False,
                content="",
                error="Memory manager not available. Cannot mark file status."
            )
        
        # Verify the file exists
        full_path = self.repo_path / file_path
        if not full_path.exists():
            return ToolResult(
                success=False,
                content="",
                error=f"File not found: {file_path}"
            )
        
        # Mark as completed in memory
        self._memory_manager.memory.file_status[file_path] = "completed"
        
        # Save reason to memory
        if reason:
            self._memory_manager.memory.file_completion_reasons[file_path] = reason
            logger.info(f"File marked completed: {file_path} - {reason}")
        else:
            logger.info(f"File marked completed: {file_path}")
        
        return ToolResult(
            success=True,
            content=json.dumps({
                "file_path": file_path,
                "status": "completed",
                "reason": reason or "No reason provided"
            }, indent=2, ensure_ascii=False)
        )

    def _get_module_call_relationships(self, file_path: str = None, module_name: str = None) -> ToolResult:
        """Get call relationships for a file or module."""
        if not self._software_profile:
            return ToolResult(
                success=False,
                content="",
                error="Software profile not available. Cannot determine call relationships."
            )
        
        # Determine the module name
        target_module = module_name
        if not target_module and file_path:
            target_module = self._file_to_module_cache.get(file_path)
            if not target_module:
                # Try partial match
                for cached_file, mod in self._file_to_module_cache.items():
                    if file_path in cached_file or cached_file in file_path:
                        target_module = mod
                        break
        
        if not target_module:
            return ToolResult(
                success=True,
                content=json.dumps({
                    "error": f"Could not find module for file: {file_path}",
                    "hint": "The file may not be part of any tracked module. Try listing modules first."
                }, indent=2)
            )
        
        # Get module info
        module_info = self._module_cache.get(target_module, {})
        if not module_info:
            return ToolResult(
                success=True,
                content=json.dumps({
                    "error": f"Module '{target_module}' not found in profile",
                    "available_modules": list(self._module_cache.keys())[:20]
                }, indent=2)
            )
        
        # Build relationships info
        callers = module_info.get('called_by_modules', [])
        callees = module_info.get('calls_modules', [])
        
        # Get files for each related module
        caller_details = []
        for caller in callers:
            caller_info = self._module_cache.get(caller, {})
            caller_details.append({
                "module": caller,
                "category": caller_info.get('category', 'unknown'),
                "files": caller_info.get('files', [])[:5],  # Limit files shown
                "file_count": len(caller_info.get('files', []))
            })
        
        callee_details = []
        for callee in callees:
            callee_info = self._module_cache.get(callee, {})
            callee_details.append({
                "module": callee,
                "category": callee_info.get('category', 'unknown'),
                "files": callee_info.get('files', [])[:5],
                "file_count": len(callee_info.get('files', []))
            })
        
        result = {
            "module": target_module,
            "category": module_info.get('category', 'unknown'),
            "files_in_module": module_info.get('files', []),
            "callers": {
                "count": len(callers),
                "modules": caller_details
            },
            "callees": {
                "count": len(callees),
                "modules": callee_details
            },
            "data_sources": module_info.get('data_sources', []),
            "data_formats": module_info.get('data_formats', []),
        }
        
        return ToolResult(
            success=True,
            content=json.dumps(result, indent=2, ensure_ascii=False)
        )

    def _get_related_files(self, file_path: str, query_type: str) -> ToolResult:
        """Get caller or callee files for a given file using call graph edges."""
        if not self._software_profile:
            return ToolResult(
                success=False,
                content="",
                error="Software profile not available. Cannot determine related files."
            )
        
        if query_type not in ("caller", "callee"):
            return ToolResult(
                success=False,
                content="",
                error=f"Invalid query_type: {query_type}. Must be 'caller' or 'callee'."
            )
        
        # Try to find the file in cache (exact match or partial match)
        target_file = file_path
        if file_path not in self._file_callers and file_path not in self._file_callees:
            # Try partial match
            for cached_file in set(self._file_callers.keys()) | set(self._file_callees.keys()):
                if file_path in cached_file or cached_file in file_path:
                    target_file = cached_file
                    break
        
        # Get related files based on query type
        if query_type == "caller":
            related_files = list(self._file_callers.get(target_file, set()))
        else:  # callee
            related_files = list(self._file_callees.get(target_file, set()))
        
        # Get detailed edges for context
        detailed_edges = []
        for edge in self._call_graph_edges:
            if query_type == "caller":
                if edge.get('callee_file', '') == target_file:
                    detailed_edges.append({
                        "caller_file": edge.get('caller_file'),
                        "caller_name": edge.get('caller'),
                        "callee_name": edge.get('callee'),
                        "call_site_line": edge.get('call_site_line')
                    })
            else:  # callee
                if edge.get('caller_file', '') == target_file:
                    detailed_edges.append({
                        "callee_file": edge.get('callee_file'),
                        "callee_name": edge.get('callee'),
                        "caller_name": edge.get('caller'),
                        "call_site_line": edge.get('call_site_line')
                    })
        
        return ToolResult(
            success=True,
            content=json.dumps({
                "source_file": file_path,
                "matched_file": target_file if target_file != file_path else None,
                "query_type": query_type,
                "total_files": len(related_files),
                "files": sorted(related_files),
                "call_edges": detailed_edges[:50]  # Limit to 50 edges
            }, indent=2, ensure_ascii=False)
        )

    def _run_codeql_query(self, query: str, query_name: str) -> ToolResult:
        """Run a CodeQL query on the pre-loaded database.
        
        Args:
            query: QL query code string or path to a .ql file
            query_name: Descriptive name for the query (used for result file naming)
        
        Returns:
            ToolResult with query findings summary
        """
        # Check if CodeQL is available
        if not self._codeql_analyzer:
            return ToolResult(
                success=False,
                content="",
                error="CodeQL analyzer is not available. Please ensure CodeQL CLI is installed."
            )
        
        # Check if database is configured
        db_path = self._get_codeql_database_path()
        if not db_path:
            return ToolResult(
                success=False,
                content="",
                error=f"CodeQL database not found. Database name: {self._codeql_database_name}, "
                      f"Search path: {self._codeql_db_base_path}"
            )
        
        # Ensure query pack is ready
        if not self._ensure_query_pack():
            return ToolResult(
                success=False,
                content="",
                error="Failed to prepare CodeQL query pack. Check logs for details."
            )
        
        # Write query code to the qlpack directory (where dependencies are installed)
        # This is required for CodeQL to resolve dependencies like 'import python'
        safe_name = re.sub(r'[^\w\-]', '_', query_name)
        query_path = self._codeql_query_dir / f"{safe_name}.ql"
        query_path.write_text(query, encoding="utf-8")
        
        try:
            # Run the query
            logger.info(f"Running CodeQL query '{query_name}' on database: {db_path}")
            success, result = self._codeql_analyzer.run_query(
                database_path=str(db_path),
                query=str(query_path),
                output_format="sarif-latest")
            
            if not success:
                error_msg = str(result) if result else "Unknown error"
                return ToolResult(
                    success=False,
                    content="",
                    error=f"CodeQL query execution failed: {error_msg}"
                )
            
            # Extract findings from SARIF result
            findings = self._extract_codeql_findings(result)
            
            # Save results to output_dir/codeql-results/
            self._save_codeql_results(query_name, result, findings)
            
            # Record findings in memory
            self._record_codeql_findings_in_memory(query_name, findings)
            
            # Return summary
            summary = self._format_codeql_summary(query_name, findings)
            return ToolResult(success=True, content=summary)
            
        except Exception as e:
            logger.error(f"CodeQL query execution error: {e}")
            return ToolResult(
                success=False,
                content="",
                error=f"CodeQL query error: {str(e)}"
            )

    def _extract_codeql_findings(self, sarif_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from SARIF result."""
        findings = []
        runs = sarif_result.get("runs", []) if isinstance(sarif_result, dict) else []
        
        for run in runs:
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                message = result.get("message", {}).get("text", "No message")
                level = result.get("level", "warning")
                
                locations = result.get("locations", [])
                for loc in locations:
                    physical_loc = loc.get("physicalLocation", {})
                    artifact_loc = physical_loc.get("artifactLocation", {})
                    uri = artifact_loc.get("uri", "")
                    region = physical_loc.get("region", {})
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine", start_line)
                    snippet = region.get("snippet", {}).get("text", "")
                    
                    findings.append({
                        "rule_id": rule_id,
                        "message": message,
                        "level": level,
                        "file": uri,
                        "start_line": start_line,
                        "end_line": end_line,
                        "snippet": snippet[:200] if snippet else ""
                    })
        
        return findings

    def _save_codeql_results(self, query_name: str, sarif_result: Dict[str, Any], findings: List[Dict[str, Any]]):
        """Save CodeQL results to output_dir/codeql-results/."""
        if not self._memory_manager:
            logger.warning("Memory manager not available, cannot save CodeQL results to output_dir")
            return
        
        output_dir = self._memory_manager.output_dir
        results_dir = output_dir / "codeql-results"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Sanitize query name for filename
        safe_name = re.sub(r'[^\w\-]', '_', query_name)
        
        # Save full SARIF result
        sarif_file = results_dir / f"{safe_name}.sarif"
        sarif_file.write_text(json.dumps(sarif_result, indent=2, ensure_ascii=False), encoding="utf-8")
        
        # Save summarized findings as JSON
        summary_file = results_dir / f"{safe_name}_findings.json"
        summary_data = {
            "query_name": query_name,
            "timestamp": datetime.now().isoformat(),
            "database": self._codeql_database_name,
            "total_findings": len(findings),
            "findings": findings
        }
        summary_file.write_text(json.dumps(summary_data, indent=2, ensure_ascii=False), encoding="utf-8")
        
        logger.info(f"CodeQL results saved to {results_dir}/{safe_name}.*")

    def _record_codeql_findings_in_memory(self, query_name: str, findings: List[Dict[str, Any]]):
        """Record CodeQL findings in agent memory."""
        if not self._memory_manager:
            return
        
        # Record each finding
        for finding in findings:
            finding_record = {
                "source": "codeql",
                "query_name": query_name,
                "file_path": finding.get("file", ""),
                "vulnerability_type": finding.get("rule_id", "unknown"),
                "description": finding.get("message", ""),
                "evidence": finding.get("snippet", ""),
                "line_number": finding.get("start_line", 0),
                "confidence": "codeql-generated",
                "similarity_to_known": f"Detected by CodeQL query: {query_name}"
            }
            self._memory_manager.add_finding(finding_record)
        
        # Also add a summary to issues if there are findings
        if findings:
            summary = f"CodeQL query '{query_name}' found {len(findings)} potential issues"
            self._memory_manager.add_issue(summary)

    def _format_codeql_summary(self, query_name: str, findings: List[Dict[str, Any]]) -> str:
        """Format CodeQL findings into a readable summary."""
        if not findings:
            return f"CodeQL query '{query_name}' completed. No vulnerabilities found."
        
        lines = [
            f"## CodeQL Query Results: {query_name}",
            f"Found **{len(findings)}** potential issue(s):",
            ""
        ]
        
        # Group by file
        by_file: Dict[str, List[Dict]] = {}
        for f in findings:
            file_path = f.get("file", "unknown")
            by_file.setdefault(file_path, []).append(f)
        
        for file_path, file_findings in sorted(by_file.items()):
            lines.append(f"### {file_path}")
            for finding in file_findings[:5]:  # Limit per file
                line = finding.get("start_line", "?")
                rule = finding.get("rule_id", "unknown")
                msg = finding.get("message", "")[:100]
                lines.append(f"- **L{line}** [{rule}]: {msg}")
            if len(file_findings) > 5:
                lines.append(f"  ... and {len(file_findings) - 5} more in this file")
            lines.append("")
        
        if len(by_file) > 10:
            lines.append(f"... and issues in {len(by_file) - 10} more files")
        
        lines.append("")
        lines.append("Results saved to `codeql-results/`. Use `read_codeql_results` tool to see full findings if truncated.")
        
        return "\n".join(lines)

    def _read_codeql_results(self, query_name: str, offset: int = 0, limit: int = 50) -> ToolResult:
        """Read full CodeQL query results from a previous query.
        
        Args:
            query_name: The query name used when running the query
            offset: Start index for pagination (default: 0)
            limit: Maximum number of findings to return (default: 50)
        
        Returns:
            ToolResult with paginated findings
        """
        if not self._memory_manager:
            return ToolResult(
                success=False,
                content="",
                error="Memory manager not available. Cannot read CodeQL results."
            )
        
        # Sanitize query name for filename
        safe_name = re.sub(r'[^\w\-]', '_', query_name)
        results_dir = self._memory_manager.output_dir / "codeql-results"
        findings_file = results_dir / f"{safe_name}_findings.json"
        
        if not findings_file.exists():
            # List available results
            available = []
            if results_dir.exists():
                available = [f.stem.replace('_findings', '') for f in results_dir.glob('*_findings.json')]
            return ToolResult(
                success=False,
                content="",
                error=f"Results not found for query: {query_name}. Available queries: {available}"
            )
        
        try:
            data = json.loads(findings_file.read_text(encoding="utf-8"))
            findings = data.get("findings", [])
            total = len(findings)
            
            # Apply pagination
            paginated = findings[offset:offset + limit]
            
            result = {
                "query_name": query_name,
                "total_findings": total,
                "offset": offset,
                "limit": limit,
                "returned": len(paginated),
                "has_more": offset + limit < total,
                "findings": paginated
            }
            
            return ToolResult(
                success=True,
                content=json.dumps(result, indent=2, ensure_ascii=False)
            )
        except Exception as e:
            return ToolResult(
                success=False,
                content="",
                error=f"Failed to read CodeQL results: {str(e)}"
            )
