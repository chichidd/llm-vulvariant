"""Run-scoped shared public memory for scan-time reusable observations."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

from profiler.fingerprint import stable_data_hash
from utils.io_utils import write_atomic_text
from utils.logger import get_logger
from utils.repo_lock import acquire_repo_lock, release_repo_lock

logger = get_logger(__name__)

_SCHEMA_VERSION = 1


def _sanitize_component(value: str) -> str:
    """Sanitize a path component for shared-memory folders."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip())
    return sanitized.strip("-") or "unknown"


def _compact_text(value: str, *, max_length: int = 160) -> str:
    """Normalize and truncate free-form text."""
    normalized = " ".join(str(value or "").split())
    if len(normalized) <= max_length:
        return normalized
    return normalized[: max_length - 3] + "..."


class SharedPublicMemoryManager:
    """Persist scan-time observations shared across target scans in one batch run."""

    def __init__(
        self,
        root_dir: Path,
        repo_name: str,
        repo_commit: str,
        repo_scope_key: str = "",
        producer_id: str = "",
        visibility_scope_id: str = "",
    ) -> None:
        self.root_dir = Path(root_dir)
        self.repo_name = str(repo_name or "").strip()
        self.repo_commit = str(repo_commit or "").strip()
        self.repo_scope_key = str(repo_scope_key or "").strip()
        self.producer_id = str(producer_id or "").strip()
        self.visibility_scope_id = str(visibility_scope_id or "").strip()
        repo_folder = f"{_sanitize_component(self.repo_name)}-{_sanitize_component(self.repo_commit[:12])}"
        if self.repo_scope_key:
            repo_folder += f"-{_sanitize_component(self.repo_scope_key[:12])}"
        self.repo_dir = self.root_dir / repo_folder
        self.observations_dir = self.repo_dir / "observations"

    def record_observation(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        summary: Dict[str, Any],
    ) -> Optional[Path]:
        """Record one structured observation if the tool is on the allowlist.

        Args:
            tool_name: Tool name that produced the observation.
            parameters: Tool parameters used to produce the observation.
            summary: Structured, compact observation payload.

        Returns:
            Observation file path when persisted, otherwise ``None``.
        """
        observation = self._build_observation(tool_name, parameters, summary)
        if observation is None:
            return None

        observation_hash = stable_data_hash(
            {
                key: value
                for key, value in observation.items()
                if key not in {"producer_id", "producer_ids", "scan_scope_id", "scan_scope_ids"}
            }
        )
        observation_path = self.observations_dir / f"{observation_hash}.json"
        lock_info = acquire_repo_lock(
            observation_path,
            purpose=f"shared_public_memory_write:{tool_name}:{observation_hash[:12]}",
        )
        try:
            if observation_path.exists():
                if self.producer_id:
                    try:
                        existing_observation = json.loads(observation_path.read_text(encoding="utf-8"))
                    except Exception:
                        existing_observation = {}
                    existing_producer_ids = [
                        str(producer_id).strip()
                        for producer_id in existing_observation.get("producer_ids", [])
                        if str(producer_id).strip()
                    ]
                    legacy_producer_id = str(existing_observation.get("producer_id", "")).strip()
                    if legacy_producer_id and legacy_producer_id not in existing_producer_ids:
                        existing_producer_ids.append(legacy_producer_id)
                    if self.producer_id not in existing_producer_ids:
                        existing_observation["producer_ids"] = existing_producer_ids + [self.producer_id]
                    current_scope_id = self.visibility_scope_id or self.producer_id
                    existing_scope_ids = [
                        str(scope_id).strip()
                        for scope_id in existing_observation.get("scan_scope_ids", [])
                        if str(scope_id).strip()
                    ]
                    legacy_scope_id = str(existing_observation.get("scan_scope_id", "")).strip()
                    if legacy_scope_id and legacy_scope_id not in existing_scope_ids:
                        existing_scope_ids.append(legacy_scope_id)
                    legacy_producer_id = str(existing_observation.get("producer_id", "")).strip()
                    if not existing_scope_ids and legacy_producer_id:
                        existing_scope_ids.append(legacy_producer_id)
                    if current_scope_id and current_scope_id not in existing_scope_ids:
                        existing_observation["scan_scope_ids"] = existing_scope_ids + [current_scope_id]
                    elif existing_scope_ids:
                        existing_observation["scan_scope_ids"] = existing_scope_ids
                    if (
                        self.producer_id not in existing_producer_ids
                        or (current_scope_id and current_scope_id not in existing_scope_ids)
                    ):
                        write_atomic_text(
                            observation_path,
                            json.dumps(existing_observation, indent=2, ensure_ascii=False),
                        )
                return observation_path
            self.observations_dir.mkdir(parents=True, exist_ok=True)
            write_atomic_text(
                observation_path,
                json.dumps(
                    {
                        **observation,
                        "observation_hash": observation_hash,
                        "created_at": datetime.now().isoformat(),
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
            )
            return observation_path
        finally:
            release_repo_lock(
                lock_info,
                observation_path,
                f"shared_public_memory_write:{tool_name}:{observation_hash[:12]}",
            )

    def read_observations(
        self,
        *,
        query: str = "",
        tool_names: Optional[List[str]] = None,
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Read shared observations for the current repo/commit scope.

        Args:
            query: Optional lexical filter.
            tool_names: Optional allowlist of tool names.
            limit: Maximum observation count to return.

        Returns:
            A JSON-serializable payload containing matching observations.
        """
        normalized_tool_names = {
            str(tool_name).strip()
            for tool_name in tool_names or []
            if str(tool_name).strip()
        }
        serialized_query = " ".join(str(query or "").lower().split())
        normalized_limit = max(1, min(int(limit), 20))
        matching_observations: List[Dict[str, Any]] = []
        for observation_path in sorted(
            self.observations_dir.glob("*.json"),
            key=lambda path: path.stat().st_mtime_ns if path.exists() else 0,
            reverse=True,
        ):
            try:
                observation = json.loads(observation_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to read shared public memory observation: %s", observation_path)
                continue
            if not isinstance(observation, dict):
                continue
            if not self._is_visible_observation(observation):
                continue
            tool_name = str(observation.get("tool_name", "")).strip()
            if normalized_tool_names and tool_name not in normalized_tool_names:
                continue
            if serialized_query:
                haystack = json.dumps(
                    {
                        "tool_name": tool_name,
                        "query": observation.get("query", {}),
                        "summary": observation.get("summary", {}),
                    },
                    ensure_ascii=False,
                ).lower()
                if not all(token in haystack for token in serialized_query.split()):
                    continue
            matching_observations.append(observation)
            if len(matching_observations) >= normalized_limit:
                break

        return {
            "schema_version": _SCHEMA_VERSION,
            "repo_name": self.repo_name,
            "repo_commit": self.repo_commit,
            "repo_scope_key": self.repo_scope_key,
            "root_hash": stable_data_hash(str(self.root_dir.resolve())),
            "total": len(matching_observations),
            "observations": matching_observations,
        }

    def describe_scope(self) -> Dict[str, Any]:
        """Describe the visible shared-memory input for this scan."""
        visible_entries: List[Dict[str, Any]] = []
        for observation_path in sorted(self.observations_dir.glob("*.json")):
            try:
                observation = json.loads(observation_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not self._is_visible_observation(observation):
                continue
            try:
                stat_result = observation_path.stat()
            except OSError:
                continue
            visible_entries.append(
                {
                    "filename": observation_path.name,
                    "size": int(stat_result.st_size),
                    "mtime_ns": int(stat_result.st_mtime_ns),
                }
            )
        return {
            "enabled": True,
            "root_hash": stable_data_hash(str(self.root_dir.resolve())),
            "scope_key": self.repo_scope_key,
            "state_hash": stable_data_hash(visible_entries),
            "observation_count": len(visible_entries),
        }

    def _build_observation(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        summary: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Build one deduplicated observation payload."""
        if not isinstance(parameters, dict) or not isinstance(summary, dict):
            return None

        compact_query = self._compact_query(tool_name, parameters)
        compact_summary = self._compact_summary(tool_name, summary)
        if compact_summary is None:
            return None
        if "file_path" in compact_summary and "file_path" in compact_query:
            compact_query["file_path"] = compact_summary["file_path"]
        if "folder_path" in compact_summary and "folder_path" in compact_query:
            compact_query["folder_path"] = compact_summary["folder_path"]

        return {
            "schema_version": _SCHEMA_VERSION,
            "repo_name": self.repo_name,
            "repo_commit": self.repo_commit,
            "repo_scope_key": self.repo_scope_key,
            "producer_id": self.producer_id,
            "producer_ids": [self.producer_id] if self.producer_id else [],
            "scan_scope_id": self.visibility_scope_id or self.producer_id,
            "scan_scope_ids": [self.visibility_scope_id or self.producer_id] if (self.visibility_scope_id or self.producer_id) else [],
            "tool_name": tool_name,
            "query": compact_query,
            "summary": compact_summary,
        }

    def _compact_query(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Keep only the query fields that help future retrieval."""
        allowed_query_fields = {
            "search_in_file": ("file_path", "pattern"),
            "search_in_folder": ("folder_path", "pattern", "max_results"),
            "get_imports": ("file_path",),
            "analyze_data_flow": ("file_path", "function_name"),
            "run_codeql_query": ("query_name",),
        }
        return {
            field: parameters[field]
            for field in allowed_query_fields.get(tool_name, ())
            if field in parameters
        }

    def _compact_summary(self, tool_name: str, summary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Compact structured tool output into reusable shared memory."""
        if tool_name == "search_in_file":
            match_count = int(summary.get("match_count", 0))
            if match_count <= 0:
                return None
            matches = [
                {
                    "line_number": int(match.get("line_number", 0)),
                    "line_text": _compact_text(match.get("line_text", "")),
                }
                for match in summary.get("matches", [])[:10]
                if isinstance(match, dict)
            ]
            return {
                "file_path": str(summary.get("file_path", "")).strip(),
                "pattern": str(summary.get("pattern", "")).strip(),
                "match_count": match_count,
                "matches": matches,
            }
        if tool_name == "search_in_folder":
            match_count = int(summary.get("match_count", 0))
            if match_count <= 0:
                return None
            matches = [
                {
                    "file_path": str(match.get("file_path", "")).strip(),
                    "line_number": int(match.get("line_number", 0)),
                    "line_text": _compact_text(match.get("line_text", "")),
                }
                for match in summary.get("matches", [])[:20]
                if isinstance(match, dict)
            ]
            return {
                "folder_path": str(summary.get("folder_path", "")).strip(),
                "pattern": str(summary.get("pattern", "")).strip(),
                "match_count": match_count,
                "files": [
                    str(file_path).strip()
                    for file_path in summary.get("files", [])[:20]
                    if str(file_path).strip()
                ],
                "matches": matches,
            }
        if tool_name == "get_imports":
            imports = [
                _compact_text(import_line)
                for import_line in summary.get("imports", [])[:20]
                if str(import_line).strip()
            ]
            if not imports:
                return None
            return {
                "file_path": str(summary.get("file_path", "")).strip(),
                "imports": imports,
            }
        if tool_name == "analyze_data_flow":
            function_calls = [
                _compact_text(call.get("full_call", ""))
                for call in summary.get("function_calls", [])[:20]
                if isinstance(call, dict) and str(call.get("full_call", "")).strip()
            ]
            string_operations = [
                _compact_text(operation.get("expression", ""))
                for operation in summary.get("string_operations", [])[:10]
                if isinstance(operation, dict) and str(operation.get("expression", "")).strip()
            ]
            return {
                "file_path": str(summary.get("file_path", "")).strip(),
                "function_name": str(summary.get("function_name", "")).strip(),
                "parameters": [
                    str(parameter).strip()
                    for parameter in summary.get("parameters", [])[:10]
                    if str(parameter).strip()
                ],
                "function_calls": function_calls,
                "string_operations": string_operations,
            }
        if tool_name == "run_codeql_query":
            finding_count = int(summary.get("finding_count", 0))
            if finding_count <= 0:
                return None
            findings = [
                {
                    "rule_id": str(finding.get("rule_id", "")).strip(),
                    "file": str(finding.get("file", "")).strip(),
                    "start_line": int(finding.get("start_line", 0)),
                    "message": _compact_text(finding.get("message", "")),
                }
                for finding in summary.get("findings", [])[:20]
                if isinstance(finding, dict)
            ]
            return {
                "query_name": str(summary.get("query_name", "")).strip(),
                "query_language": str(summary.get("query_language", "")).strip(),
                "database_name": str(summary.get("database_name", "")).strip(),
                "finding_count": finding_count,
                "findings": findings,
            }
        return None

    def _is_visible_observation(self, observation: Dict[str, Any]) -> bool:
        """Return whether one observation is visible to the current scan."""
        if not isinstance(observation, dict):
            return False
        current_scope_id = self.visibility_scope_id or self.producer_id
        if not current_scope_id:
            return True
        scope_ids = [
            str(scope_id).strip()
            for scope_id in observation.get("scan_scope_ids", [])
            if str(scope_id).strip()
        ]
        legacy_scope_id = str(observation.get("scan_scope_id", "")).strip()
        if legacy_scope_id and legacy_scope_id not in scope_ids:
            scope_ids.append(legacy_scope_id)
        legacy_producer_ids = [
            str(producer_id).strip()
            for producer_id in observation.get("producer_ids", [])
            if str(producer_id).strip()
        ]
        legacy_producer_id = str(observation.get("producer_id", "")).strip()
        if legacy_producer_id and legacy_producer_id not in legacy_producer_ids:
            legacy_producer_ids.append(legacy_producer_id)
        if not scope_ids:
            scope_ids = legacy_producer_ids
        if not scope_ids:
            return True
        return any(scope_id != current_scope_id for scope_id in scope_ids)
