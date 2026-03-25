"""Reporting and scan-status helpers for the agent toolkit."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from scanner.agent.toolkit_fs import ToolResult
from utils.logger import get_logger

logger = get_logger(__name__)


class ToolkitReportingMixin:
    """Reporting and scan-status helpers mixed into ``AgenticToolkit``."""

    def _normalize_reported_vulnerability(
        self,
        finding: Dict[str, Any],
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Validate and normalize one reported vulnerability payload."""
        normalized: Dict[str, Any] = {}
        required_string_fields = (
            "vulnerability_type",
            "description",
            "evidence",
            "similarity_to_known",
            "confidence",
        )

        normalized_file_path, error = self._resolve_repo_relative_path(
            finding.get("file_path", ""),
            kind="file",
        )
        if error or not normalized_file_path:
            return None, error or "file_path is required"
        normalized["file_path"] = normalized_file_path

        function_name = str(finding.get("function_name", "") or "").strip()
        if function_name:
            normalized["function_name"] = function_name

        for field_name in required_string_fields:
            field_value = str(finding.get(field_name, "") or "").strip()
            if not field_value:
                return None, f"{field_name} is required"
            normalized[field_name] = field_value

        attack_scenario = str(finding.get("attack_scenario", "") or "").strip()
        if attack_scenario:
            normalized["attack_scenario"] = attack_scenario

        raw_line_number = finding.get("line_number")
        if raw_line_number is not None:
            try:
                normalized_line_number = int(raw_line_number)
            except (TypeError, ValueError):
                return None, f"line_number must be an integer, got {raw_line_number!r}"
            if normalized_line_number <= 0:
                return None, "line_number must be >= 1"
            normalized["line_number"] = normalized_line_number

        return normalized, None

    def _report_vulnerability(self, **kwargs) -> ToolResult:
        normalized_finding, error = self._normalize_reported_vulnerability(kwargs)
        if error or normalized_finding is None:
            return ToolResult(success=False, content="", error=error or "Invalid vulnerability payload")
        return ToolResult(
            success=True,
            content=json.dumps(normalized_finding, indent=2, ensure_ascii=False),
        )

    def _check_file_status(self, file_paths: List[str]) -> ToolResult:
        """Check the scan status of files from memory."""
        if not self._memory_manager:
            normalized_files = {}
            for fp in file_paths:
                normalized_path, _ = self._resolve_repo_relative_path(fp, kind="file")
                normalized_files[normalized_path if normalized_path else fp] = "pending"
            return ToolResult(
                success=True,
                content=json.dumps({
                    "note": "Memory not available. All files are considered pending.",
                    "files": normalized_files
                }, indent=2)
            )

        result = {}
        for fp in file_paths:
            normalized_path, error = self._resolve_repo_relative_path(fp, kind="file")
            lookup_path = normalized_path if normalized_path else fp
            status = self._memory_manager.memory.file_status.get(lookup_path, "not_tracked")
            result[lookup_path] = status if not error else "not_tracked"

        # Add summary
        summary_text = self._memory_manager.summarize_statuses(result)

        return ToolResult(
            success=True,
            content=json.dumps({
                "summary": summary_text,
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
        normalized_path, error = self._resolve_repo_relative_path(file_path, kind="file")
        if error:
            return ToolResult(success=False, content="", error=error)
        full_path = self.repo_path / normalized_path
        if not full_path.exists():
            return ToolResult(
                success=False,
                content="",
                error=f"File not found: {normalized_path}"
            )

        tracked_statuses = getattr(getattr(self._memory_manager, "memory", None), "file_status", None)
        if not isinstance(tracked_statuses, dict):
            return ToolResult(
                success=False,
                content="",
                error="Memory manager does not expose tracked file status."
            )
        if normalized_path not in tracked_statuses:
            return ToolResult(
                success=False,
                content="",
                error=f"File is not tracked in scan memory: {normalized_path}"
            )

        mark_completed_fn = getattr(self._memory_manager, "mark_file_completed", None)
        if callable(mark_completed_fn):
            mark_completed_fn(normalized_path, reason=reason)
        else:
            tracked_statuses[normalized_path] = "completed"
            if reason:
                self._memory_manager.memory.file_completion_reasons[normalized_path] = reason
            save_fn = getattr(self._memory_manager, "save", None)
            if callable(save_fn):
                save_fn()
        if tracked_statuses.get(normalized_path) != "completed":
            return ToolResult(
                success=False,
                content="",
                error=f"Failed to persist completed status for tracked file: {normalized_path}"
            )
        if reason:
            logger.info(f"File marked completed: {normalized_path} - {reason}")
        else:
            logger.info(f"File marked completed: {normalized_path}")

        return ToolResult(
            success=True,
            content=json.dumps({
                "file_path": normalized_path,
                "status": "completed",
                "reason": reason or "No reason provided"
            }, indent=2, ensure_ascii=False)
        )
