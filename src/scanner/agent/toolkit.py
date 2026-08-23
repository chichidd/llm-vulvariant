"""Tools exposed to the agentic vulnerability finder."""

from __future__ import annotations

import ast
import json
import re
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
from scanner.agent.schedule_window import (
    FROZEN_SCHEDULE_PAGE_ALGORITHM,
    FROZEN_SCHEDULE_PAGE_SIZE,
)

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
        memory_guidance_enabled: bool = True,
        verifier_enabled: bool = True,
    ):
        self.repo_path = repo_path.resolve()
        self._file_cache: Dict[str, str] = {}
        self._memory_manager = memory_manager
        self._software_profile = software_profile
        self._shared_public_memory_manager = shared_public_memory_manager
        self._memory_guidance_enabled = bool(memory_guidance_enabled)
        self._verifier_enabled = bool(verifier_enabled)
        self._file_to_module_cache: Dict[str, str] = {}  # file_path -> module_name
        self._module_cache: Dict[str, Dict] = {}  # module_name -> module_info
        self._call_graph_edges: List[Dict] = []  # call graph edges from repo_analysis
        self._file_callers: Dict[str, set] = {}  # file -> set of caller files
        self._file_callees: Dict[str, set] = {}  # file -> set of callee files
        self._iteration_touched_files: Set[str] = set()
        self._scheduled_mode = False
        self._file_enumeration_order: tuple[str, ...] = ()
        self._file_enumeration_rank: Dict[str, int] = {}
        self._model_path_projection_order: tuple[str, ...] = ()
        self._model_path_projection_pattern: Optional[re.Pattern[str]] = None
        self._scheduled_path_token_pattern: Optional[re.Pattern[str]] = None
        self._active_file_page_order: tuple[str, ...] = ()
        self._active_file_window_order: tuple[str, ...] = ()
        self._active_file_window_rank: Dict[str, int] = {}
        self._active_file_window_cursor: Optional[int] = None
        self._active_file_window_end_cursor: Optional[int] = None
        self._observed_first_touches: List[str] = []
        self._observed_first_touch_set: Set[str] = set()

        # Language configuration (multi-language aware).
        self._languages: List[str] = self._resolve_languages(languages=languages)
        self._source_extensions: Set[str] = self._resolve_source_extensions()

        # CodeQL configuration
        self._codeql_template_root: Path = Path(_path_config['repo_root']) / '.codeql-queries'
        self._codeql_db_base_path: Path = _path_config['codeql_db_path']
        self._codeql_database_names: Dict[str, str] = self._normalize_codeql_database_names(
            codeql_database_names
        )
        self._codeql_analyzer: Optional[CodeQLAnalyzer] = None
        self._codeql_query_dirs: Dict[str, Path] = {}
        self._codeql_query_dirs_ready: Set[str] = set()
        self._init_codeql()

        self._build_module_cache()
        self._restore_coverage_first_touches()

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
        self._restore_coverage_first_touches()

    def _restore_coverage_first_touches(self) -> None:
        """Restore the ordered durable reached-work ledger from scan memory."""
        memory_payload = getattr(self._memory_manager, "memory", None)
        raw_touches = getattr(memory_payload, "coverage_first_touches", [])
        if raw_touches is None:
            raw_touches = []
        if not isinstance(raw_touches, list):
            raise ValueError("coverage first-touch ledger must be a list")
        normalized = [str(path).strip() for path in raw_touches]
        if any(not path for path in normalized) or len(set(normalized)) != len(normalized):
            raise ValueError("coverage first-touch ledger contains invalid or duplicate paths")
        self._observed_first_touches = normalized
        self._observed_first_touch_set = set(normalized)

    def _normalize_projection_paths(self, file_paths: List[str]) -> tuple[str, ...]:
        """Validate one complete canonical target-file vocabulary."""
        normalized_paths: List[str] = []
        seen: Set[str] = set()
        for raw_path in file_paths:
            normalized_path, error = self._resolve_repo_relative_path(
                raw_path,
                kind="file",
            )
            resolved_file = self.repo_path / normalized_path if normalized_path else None
            if (
                error
                or not normalized_path
                or str(raw_path).strip() != normalized_path
                or resolved_file is None
                or not resolved_file.is_file()
                or normalized_path in seen
            ):
                raise ValueError(
                    "Invalid, missing, or duplicate target path projection entry"
                )
            seen.add(normalized_path)
            normalized_paths.append(normalized_path)
        if not normalized_paths:
            raise ValueError("Target path projection vocabulary cannot be empty")
        return tuple(normalized_paths)

    def set_model_path_projection_order(self, file_paths: List[str]) -> None:
        """Install a frozen target-path vocabulary without changing tool eligibility."""
        frozen_order = self._normalize_projection_paths(file_paths)
        if self._model_path_projection_order:
            if frozen_order == self._model_path_projection_order:
                return
            raise ValueError("Target path projection vocabulary cannot be replaced")
        self._model_path_projection_order = frozen_order
        self._model_path_projection_pattern = (
            self._compile_model_path_projection_pattern(frozen_order)
        )

    def set_file_enumeration_order(self, file_paths: List[str]) -> None:
        """Set an externally frozen repository-relative presentation/enumeration order."""
        frozen_order = self._normalize_projection_paths(file_paths)
        if self._scheduled_mode:
            if frozen_order == self._file_enumeration_order:
                return
            raise ValueError("Frozen file enumeration order cannot be replaced")
        scheduled_guard_order = self._model_path_projection_order or frozen_order
        self._scheduled_path_token_pattern = self._compile_scheduled_path_token_pattern(
            scheduled_guard_order
        )
        self._scheduled_mode = True
        self._file_enumeration_order = frozen_order
        self._file_enumeration_rank = {
            path: index for index, path in enumerate(frozen_order)
        }
        self._active_file_page_order = ()
        self._active_file_window_order = ()
        self._active_file_window_rank = {}
        self._active_file_window_cursor = None
        self._active_file_window_end_cursor = None

    def set_active_file_window(
        self,
        file_paths: List[str],
        *,
        cursor: int,
        completed_files: Optional[List[str]] = None,
        page_size: int = FROZEN_SCHEDULE_PAGE_SIZE,
        page_algorithm: str = FROZEN_SCHEDULE_PAGE_ALGORITHM,
    ) -> None:
        """Install one exact host-selected page with a pending-only allowlist."""
        if not self._scheduled_mode:
            raise ValueError("Cannot set an active window without a frozen schedule")
        if (
            isinstance(page_size, bool)
            or page_size != FROZEN_SCHEDULE_PAGE_SIZE
            or page_algorithm != FROZEN_SCHEDULE_PAGE_ALGORITHM
        ):
            raise ValueError("Active file window policy does not match the frozen host contract")
        if isinstance(cursor, bool) or not isinstance(cursor, int):
            raise ValueError("Active file window cursor must be an integer")
        if cursor < 0 or cursor > len(self._file_enumeration_order):
            raise ValueError("Active file window cursor is out of range")
        if (
            cursor != len(self._file_enumeration_order)
            and cursor % FROZEN_SCHEDULE_PAGE_SIZE != 0
        ):
            raise ValueError("Active file window cursor must be page aligned")
        expected = self._file_enumeration_order[
            cursor : cursor + FROZEN_SCHEDULE_PAGE_SIZE
        ]
        normalized = tuple(str(path) for path in file_paths)
        if normalized != expected:
            raise ValueError("Active file window is not the exact frozen schedule slice")
        completed = {str(path) for path in (completed_files or [])}
        if not completed.issubset(set(expected)):
            raise ValueError("Completed active-window paths must belong to the exact page")
        pending = tuple(path for path in expected if path not in completed)
        previous_cursor = self._active_file_window_cursor
        if previous_cursor is not None:
            if cursor < previous_cursor:
                raise ValueError("Active file window cursor cannot move backwards")
            if cursor > previous_cursor:
                if cursor != self._active_file_window_end_cursor:
                    raise ValueError("Active file window cursor cannot skip a page")
                if self._active_file_window_order:
                    raise ValueError("Active file window cannot advance before its page is complete")
            elif not set(pending).issubset(set(self._active_file_window_order)):
                raise ValueError("Completed active-window files cannot become pending again")
        self._active_file_page_order = expected
        self._active_file_window_order = pending
        self._active_file_window_rank = {
            path: self._file_enumeration_rank[path] for path in pending
        }
        self._active_file_window_cursor = cursor
        self._active_file_window_end_cursor = cursor + len(expected)

    def retire_completed_file(self, file_path: str) -> None:
        """Remove one successfully persisted completion from the active allowlist."""
        normalized = str(file_path or "").strip()
        if normalized not in self._active_file_window_rank:
            raise ValueError(
                f"File is unavailable in the active frozen schedule window: {normalized}"
            )
        self._active_file_window_order = tuple(
            path for path in self._active_file_window_order if path != normalized
        )
        self._active_file_window_rank.pop(normalized, None)

    def get_active_file_window_snapshot(self) -> Dict[str, Any]:
        """Return the immutable page plus its current pending-only allowlist."""
        return {
            "cursor": self._active_file_window_cursor,
            "page_files": list(self._active_file_page_order),
            "active_pending_files": list(self._active_file_window_order),
        }

    def order_repo_relative_paths(self, file_paths: List[str]) -> List[str]:
        """Order scheduled paths exactly, without fallback or duplicates."""
        if not self._scheduled_mode:
            return sorted(str(path) for path in file_paths)
        candidates = {str(path) for path in file_paths}
        return [
            path
            for path in self._active_file_window_order
            if path in candidates
        ]

    def get_observed_first_touches(self) -> List[str]:
        """Return successful file touches in first-observed order."""
        return list(self._observed_first_touches)

    @staticmethod
    def _compile_model_path_projection_pattern(
        file_paths: tuple[str, ...],
    ) -> re.Pattern[str]:
        """Compile the frozen v2 asymmetric ASCII suffix-boundary matcher."""
        alternatives = "|".join(
            re.escape(path)
            for path in sorted(
                file_paths,
                key=lambda path: (-len(path), path.encode("utf-8")),
            )
        )
        if not alternatives:
            raise ValueError("Target path projection vocabulary cannot be empty")
        return re.compile(
            r"(?<![A-Za-z0-9._~-])(?:"
            + alternatives
            + r")(?![A-Za-z0-9._~/-])"
        )

    @staticmethod
    def _compile_scheduled_path_token_pattern(
        file_paths: tuple[str, ...],
    ) -> re.Pattern[str]:
        """Compile the schedule guard, including host absolute-prefix suffixes."""
        alternatives = "|".join(
            re.escape(path)
            for path in sorted(
                file_paths,
                key=lambda path: (-len(path), path.encode("utf-8")),
            )
        )
        if not alternatives:
            raise ValueError("Scheduled file vocabulary cannot be empty")
        return re.compile(
            r"(?<![\w.-])(?:" + alternatives + r")(?![\w./-])"
        )

    @staticmethod
    def _sanitize_structured_path_tokens(
        value: Any,
        *,
        token_pattern: re.Pattern[str],
        replacement,
    ) -> Any:
        """Recursively project strings and collision-safely retain every dict child."""
        def sanitize(item: Any) -> Any:
            if isinstance(item, dict):
                projected: Dict[Any, Any] = {}
                for key, child in item.items():
                    projected_key = sanitize(key) if isinstance(key, str) else key
                    if projected_key in projected:
                        suffix = 2
                        candidate_key = f"{projected_key}#{suffix}"
                        while candidate_key in projected:
                            suffix += 1
                            candidate_key = f"{projected_key}#{suffix}"
                        projected_key = candidate_key
                    projected[projected_key] = sanitize(child)
                return projected
            if isinstance(item, list):
                return [sanitize(child) for child in item]
            if isinstance(item, tuple):
                return tuple(sanitize(child) for child in item)
            if not isinstance(item, str):
                return item
            return token_pattern.sub(replacement, item)

        return sanitize(value)

    def sanitize_invariant_model_value(self, value: Any) -> Any:
        """Apply frozen recursive v2 redaction before policy injection."""
        if not self._model_path_projection_order:
            return value
        token_pattern = self._model_path_projection_pattern
        if token_pattern is None:
            raise ValueError("Target path projection matcher is unavailable")

        def project_text(raw: str) -> str:
            return token_pattern.sub("<TARGET_PATH>", raw)

        def project(item: Any) -> Any:
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise ValueError("Invariant projection requires JSON string mapping keys")
                rows = [
                    (raw_key, project_text(raw_key), child)
                    for raw_key, child in item.items()
                ]
                reserved_bases = {base for _raw, base, _child in rows}
                groups: Dict[str, List[str]] = {}
                base_by_raw_key: Dict[str, str] = {}
                by_raw_key: Dict[str, Any] = {}
                for raw_key, base, child in rows:
                    groups.setdefault(base, []).append(raw_key)
                    base_by_raw_key[raw_key] = base
                    by_raw_key[raw_key] = child
                owner_by_base = {
                    base: (
                        base
                        if base in raw_keys
                        else min(raw_keys, key=lambda value: value.encode("utf-8"))
                    )
                    for base, raw_keys in groups.items()
                }
                assigned: Dict[str, str] = {}
                assigned_outputs: Set[str] = set()
                raw_key_order = sorted(by_raw_key, key=lambda value: value.encode("utf-8"))
                for raw_key in raw_key_order:
                    base = base_by_raw_key[raw_key]
                    if owner_by_base[base] == raw_key:
                        output_key = base
                    else:
                        suffix = 2
                        output_key = f"{base}#{suffix}"
                        while output_key in reserved_bases or output_key in assigned_outputs:
                            suffix += 1
                            output_key = f"{base}#{suffix}"
                    assigned[raw_key] = output_key
                    assigned_outputs.add(output_key)
                return {
                    assigned[raw_key]: project(by_raw_key[raw_key])
                    for raw_key in raw_key_order
                }
            if isinstance(item, list):
                return [project(child) for child in item]
            if isinstance(item, tuple):
                return tuple(project(child) for child in item)
            if isinstance(item, str):
                return project_text(item)
            return item

        return project(value)

    def _sanitize_scheduled_structured_value(
        self,
        value: Any,
        *,
        preserve_active: bool = True,
    ) -> Any:
        """Guard scheduled model data while preserving only active-page paths."""
        if not self._scheduled_mode:
            return value
        token_pattern = self._scheduled_path_token_pattern
        if token_pattern is None:
            raise ValueError("Scheduled path-token matcher is unavailable")
        return self._sanitize_structured_path_tokens(
            value,
            token_pattern=token_pattern,
            replacement=lambda match: (
                match.group(0)
                if preserve_active
                and match.group(0) in self._active_file_window_rank
                else "<inactive-schedule-path>"
            ),
        )

    def sanitize_scheduled_model_value(
        self,
        value: Any,
        *,
        preserve_active: bool = True,
    ) -> Any:
        """Apply the policy-specific active-schedule eligibility guard."""
        return self._sanitize_scheduled_structured_value(
            value,
            preserve_active=preserve_active,
        )


    def _sanitize_scheduled_tool_result(self, result: ToolResult) -> ToolResult:
        """Remove inactive scheduled paths from one model-facing tool result."""
        if not self._scheduled_mode:
            return result
        sanitized = self._sanitize_scheduled_structured_value(
            {
                "content": result.content,
                "error": result.error,
                "metadata": result.metadata,
            }
        )
        return ToolResult(
            success=result.success,
            content=str(sanitized["content"] or ""),
            error=(
                str(sanitized["error"])
                if sanitized["error"] is not None
                else None
            ),
            truncated=result.truncated,
            metadata=sanitized["metadata"],
        )


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
                            "attack_scenario": {
                                "type": "string",
                                "description": (
                                    "Evidence-backed exploit narrative naming the attacker-controlled source, "
                                    "trust boundary, sink, missing/bypassed protection, and impact."
                                ),
                                "minLength": 1,
                            },
                        },
                        "required": [
                            "file_path",
                            "vulnerability_type",
                            "description",
                            "evidence",
                            "similarity_to_known",
                            "confidence",
                            "attack_scenario",
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
        report_tool = next(
            (
                tool
                for tool in tools
                if tool.get("function", {}).get("name") == "report_vulnerability"
            ),
            None,
        )
        if report_tool is not None and not self._verifier_enabled:
            report_parameters = report_tool["function"]["parameters"]
            report_parameters["required"] = [
                field_name
                for field_name in report_parameters.get("required", [])
                if field_name != "attack_scenario"
            ]
            attack_schema = report_parameters.get("properties", {}).get("attack_scenario")
            if isinstance(attack_schema, dict):
                attack_schema["description"] = (
                    "Optional concise scenario describing how the reported weakness could be reached."
                )

        if not self._memory_guidance_enabled:
            for tool in tools:
                function = tool.get("function", {})
                if function.get("name") == "run_codeql_query":
                    function["description"] = (
                        "Run a CodeQL query on the pre-loaded CodeQL database. "
                        "Results are saved to the codeql-results folder and summarized in the response."
                    )
                elif function.get("name") == "mark_file_completed":
                    function["description"] = (
                        "Record that a file has been fully analyzed for private coverage accounting."
                    )
        if not self._memory_guidance_enabled:
            hidden_memory_tools = {"check_file_status", "read_shared_public_memory"}
            tools = [
                tool
                for tool in tools
                if tool.get("function", {}).get("name") not in hidden_memory_tools
            ]
        if self._scheduled_mode:
            tools = [
                tool
                for tool in tools
                if tool.get("function", {}).get("name")
                != "get_module_call_relationships"
            ]
            related_tool = next(
                (
                    tool
                    for tool in tools
                    if tool.get("function", {}).get("name") == "get_related_files"
                ),
                None,
            )
            if related_tool is not None:
                related_tool["function"]["description"] = (
                    "Get the frozen-schedule-ordered unique caller or callee file "
                    "subset for one scheduled file."
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
            return f"Tool is unavailable in the current scanner configuration: {tool_name}"

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
            if path_field == "file_path" and self._scheduled_mode:
                normalized_path, path_error = self._resolve_repo_relative_path(
                    raw_path, kind="file"
                )
                if (
                    path_error
                    or normalized_path not in self._active_file_window_rank
                ):
                    return f"File is unavailable in the active frozen schedule window: {raw_path}"
            if path_field == "folder_path":
                if self._scheduled_mode:
                    normalized_folder, folder_error = self._resolve_repo_relative_path(
                        raw_path or ".", kind="folder"
                    )
                    folder_prefix = Path(normalized_folder or ".")
                    has_active_descendant = (
                        not folder_error
                        and any(
                            Path(path) == folder_prefix
                            or folder_prefix in Path(path).parents
                            for path in self._active_file_window_order
                        )
                    )
                    if not has_active_descendant:
                        return (
                            "Folder is unavailable in the active frozen schedule window: "
                            f"{raw_path}"
                        )
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
                if self._scheduled_mode:
                    normalized_path, path_error = self._resolve_repo_relative_path(
                        normalized, kind="file"
                    )
                    if (
                        path_error
                        or normalized_path not in self._active_file_window_rank
                    ):
                        return (
                            "File is unavailable in the active frozen schedule window: "
                            f"{normalized}"
                        )

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
        if not self._get_tool_spec(tool_name):
            return ToolResult(
                success=False,
                content="",
                error=f"Tool is unavailable in the current scanner configuration: {tool_name}",
            )
        if (
            self._scheduled_mode
            and tool_name == "get_module_call_relationships"
        ):
            return ToolResult(
                success=False,
                content="",
                error=(
                    "Module relationship enumeration is unavailable under the "
                    "frozen global file schedule."
                ),
            )

        validation_error = self._validate_tool_parameters(tool_name, parameters)
        if validation_error:
            return ToolResult(
                success=False,
                content="",
                error=validation_error,
            )
        if self._scheduled_mode:
            parameters = dict(parameters)
            if "file_path" in parameters:
                normalized_path, _ = self._resolve_repo_relative_path(
                    parameters["file_path"],
                    kind="file",
                )
                parameters["file_path"] = normalized_path
            if isinstance(parameters.get("file_paths"), list):
                normalized_paths = []
                for raw_path in parameters["file_paths"]:
                    normalized_path, _ = self._resolve_repo_relative_path(
                        raw_path,
                        kind="file",
                    )
                    normalized_paths.append(normalized_path)
                parameters["file_paths"] = normalized_paths
        active_paths_at_dispatch = (
            set(self._active_file_window_order)
            if self._scheduled_mode
            else None
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
            self._track_tool_file_touch(
                tool_name,
                parameters,
                result,
                active_paths_at_dispatch=active_paths_at_dispatch,
            )
            result = self._sanitize_scheduled_tool_result(result)
            self._record_shared_public_observation(tool_name, parameters, result)
            return result
        except Exception as exc:  # pylint: disable=broad-except
            if self._scheduled_mode:
                logger.warning(
                    "Scheduled tool execution failed without exposing private path details; type=%s",
                    type(exc).__name__,
                )
                sanitized_error = self._sanitize_scheduled_structured_value(str(exc))
                return ToolResult(
                    success=False,
                    content="",
                    error=str(sanitized_error),
                )
            return ToolResult(success=False, content="", error=str(exc))

    def _record_shared_public_observation(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        result: ToolResult,
    ) -> None:
        """Persist allowlisted tool observations into shared public memory."""
        if not self._memory_guidance_enabled:
            return
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
        *,
        active_paths_at_dispatch: Optional[Set[str]] = None,
    ) -> None:
        """Persist successful path-bearing tool-result first touches."""
        if not result.success:
            return
        touch_candidates: List[str] = []
        raw_file_path = parameters.get("file_path")
        if raw_file_path:
            touch_candidates.append(str(raw_file_path))
        raw_file_paths = parameters.get("file_paths", [])
        if isinstance(raw_file_paths, list):
            touch_candidates.extend(str(path) for path in raw_file_paths)
        metadata = result.metadata if isinstance(result.metadata, dict) else {}
        self._collect_path_bearing_values(metadata, touch_candidates)
        structured_content_tools = {
            "analyze_data_flow",
            "check_file_status",
            "get_imports",
            "get_related_files",
            "mark_file_completed",
            "read_codeql_results",
            "read_shared_public_memory",
            "report_vulnerability",
        }
        if tool_name in structured_content_tools and result.content:
            try:
                structured_content = json.loads(result.content)
            except (TypeError, ValueError, json.JSONDecodeError):
                structured_content = None
            if isinstance(structured_content, (dict, list)):
                self._collect_path_bearing_values(
                    structured_content,
                    touch_candidates,
                )
        new_touches: List[str] = []
        for candidate in touch_candidates:
            normalized_path, touch_error = self._resolve_repo_relative_path(
                candidate,
                kind="file",
            )
            if self._scheduled_mode and (
                touch_error
                or not normalized_path
                or active_paths_at_dispatch is None
                or normalized_path not in active_paths_at_dispatch
            ):
                logger.warning(
                    "Rejecting a successful scheduled tool result that exposed "
                    "an inactive repository path"
                )
                raise ValueError(
                    "Successful tool result exposed a path outside the active "
                    "frozen schedule window"
                )
            if touch_error or not normalized_path:
                continue
            if normalized_path in self._observed_first_touch_set:
                continue
            if normalized_path not in new_touches:
                new_touches.append(normalized_path)
        if new_touches:
            record_touches = getattr(
                self._memory_manager,
                "record_coverage_first_touches",
                None,
            )
            if callable(record_touches):
                record_touches(new_touches)
            for normalized_path in new_touches:
                self._observed_first_touch_set.add(normalized_path)
                self._observed_first_touches.append(normalized_path)

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

    @classmethod
    def _collect_path_bearing_values(
        cls,
        value: Any,
        output: List[str],
        *,
        parent_key: str = "",
    ) -> None:
        """Collect paths only from explicitly path-bearing structured fields."""
        singular_keys = {"file", "file_path"}
        plural_keys = {"files", "file_paths"}
        if isinstance(value, dict):
            for raw_key, item in value.items():
                key = str(raw_key)
                if key in singular_keys and isinstance(item, str) and item.strip():
                    output.append(item)
                elif key in plural_keys and isinstance(item, list):
                    for row in item:
                        if isinstance(row, str) and row.strip():
                            output.append(row)
                        elif isinstance(row, (dict, list)):
                            cls._collect_path_bearing_values(
                                row,
                                output,
                                parent_key=key,
                            )
                elif isinstance(item, (dict, list)):
                    cls._collect_path_bearing_values(
                        item,
                        output,
                        parent_key=key,
                    )
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and parent_key in plural_keys and item.strip():
                    output.append(item)
                elif isinstance(item, (dict, list)):
                    cls._collect_path_bearing_values(
                        item,
                        output,
                        parent_key=parent_key,
                    )

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

    def _project_shared_memory_payload(
        self,
        payload: Dict[str, Any],
        *,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Project scheduled shared-memory evidence into one globally ordered file list."""
        if not self._file_enumeration_rank:
            return payload

        cloned_payload = json.loads(json.dumps(payload))
        evidence_by_path: Dict[str, List[Dict[str, Any]]] = {}
        eligible_observation_count = 0
        for observation in cloned_payload.get("observations", []):
            if not isinstance(observation, dict):
                continue
            query = observation.get("query", {})
            summary = observation.get("summary", {})
            if not isinstance(query, dict):
                query = {}
            if not isinstance(summary, dict):
                summary = {}

            clean_query = {
                key: value
                for key, value in query.items()
                if key not in {"file_path", "file_paths", "folder_path"}
            }
            common_summary = {
                key: value
                for key, value in summary.items()
                if key not in {
                    "file_path",
                    "files",
                    "folder_path",
                    "matches",
                    "findings",
                }
            }
            base_evidence = {
                key: value
                for key, value in observation.items()
                if key not in {"query", "summary"}
            }
            if clean_query:
                base_evidence["query"] = clean_query
            if common_summary:
                base_evidence["summary"] = common_summary

            paths = []
            direct_path = summary.get("file_path")
            if direct_path:
                paths.append(str(direct_path))
            raw_files = summary.get("files", [])
            if isinstance(raw_files, list):
                paths.extend(str(path) for path in raw_files)

            matches_by_path: Dict[str, List[Dict[str, Any]]] = {}
            findings_by_path: Dict[str, List[Dict[str, Any]]] = {}
            for list_key, path_key in (("matches", "file_path"), ("findings", "file")):
                rows = summary.get(list_key, [])
                if not isinstance(rows, list):
                    continue
                rows_by_path = (
                    matches_by_path if list_key == "matches" else findings_by_path
                )
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    row_path = str(row.get(path_key, "") or "").strip()
                    if not row_path:
                        continue
                    rows_by_path.setdefault(row_path, []).append(
                        {
                            key: value
                            for key, value in row.items()
                            if key != path_key
                        }
                    )
                    paths.append(row_path)

            observation_paths = self.order_repo_relative_paths(paths)
            if not observation_paths:
                continue
            if limit is not None and eligible_observation_count >= limit:
                break
            eligible_observation_count += 1
            for path in observation_paths:
                evidence = json.loads(json.dumps(base_evidence))
                if path in matches_by_path:
                    evidence["matches"] = matches_by_path[path]
                if path in findings_by_path:
                    evidence["findings"] = findings_by_path[path]
                evidence_by_path.setdefault(path, []).append(evidence)

        ordered_paths = self.order_repo_relative_paths(list(evidence_by_path))
        projected_payload = {
            key: value
            for key, value in cloned_payload.items()
            if key not in {"observations", "total"}
        }
        projected_payload.update(
            {
                "schedule_scope": "frozen_global_unique",
                "total_files": len(ordered_paths),
                "returned_observations": eligible_observation_count,
                "returned_files": len(ordered_paths),
                "files": [
                    {
                        "file": path,
                        "observations": evidence_by_path[path],
                    }
                    for path in ordered_paths
                ],
            }
        )
        return self._sanitize_scheduled_structured_value(projected_payload)

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
            limit=None if self._scheduled_mode else normalized_limit,
        )
        payload = self._project_shared_memory_payload(
            payload,
            limit=normalized_limit if self._scheduled_mode else None,
        )
        return ToolResult(
            success=True,
            content=json.dumps(payload, indent=2, ensure_ascii=False),
            metadata=payload,
        )
