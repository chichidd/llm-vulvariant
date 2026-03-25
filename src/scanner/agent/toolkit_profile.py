"""Software-profile and relationship helpers for the agent toolkit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Set

from scanner.agent.toolkit_fs import ToolResult
from scanner.agent.utils import _to_dict


class ToolkitProfileMixin:
    """Software-profile and relationship helpers mixed into ``AgenticToolkit``."""

    def _resolve_cached_profile_file(
        self,
        file_path: str,
        *,
        available_paths: Set[str],
    ) -> tuple[Optional[str], Optional[str]]:
        """Resolve one profile-backed file path without substring matching."""
        raw_path = str(file_path or "").strip()
        if not raw_path:
            return None, "file_path is required"

        normalized_path, error = self._resolve_repo_relative_path(raw_path, kind="file")
        if error and (Path(raw_path).is_absolute() or ".." in Path(raw_path).parts):
            return None, error

        for candidate in (normalized_path, raw_path):
            if candidate and candidate in available_paths:
                return candidate, None

        basename = Path(normalized_path or raw_path).name
        if not basename:
            return None, error or f"Could not resolve file path: {raw_path}"

        basename_matches = sorted(
            cached_path for cached_path in available_paths
            if Path(cached_path).name == basename
        )
        if len(basename_matches) == 1:
            return basename_matches[0], None
        if len(basename_matches) > 1:
            return None, (
                f"Ambiguous file path '{raw_path}'. Matches: "
                + ", ".join(basename_matches[:10])
            )
        return None, error or f"Could not find file in software profile: {raw_path}"

    def _build_module_cache(self) -> None:
        """Build lookup caches from software profile."""
        self._module_cache.clear()
        self._file_to_module_cache.clear()

        if not self._software_profile:
            self._build_call_graph_cache()
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

    def _build_call_graph_cache(self) -> None:
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

    def set_software_profile(self, software_profile: object | None) -> None:
        """Set or update the software profile reference."""
        self._software_profile = software_profile
        self._build_module_cache()

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
            resolved_file, error = self._resolve_cached_profile_file(
                file_path,
                available_paths=set(self._file_to_module_cache.keys()),
            )
            if error:
                return ToolResult(success=False, content="", error=error)
            target_module = self._file_to_module_cache.get(resolved_file)

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

        target_file, error = self._resolve_cached_profile_file(
            file_path,
            available_paths=set(self._file_callers.keys()) | set(self._file_callees.keys()),
        )
        if error:
            return ToolResult(success=False, content="", error=error)

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
