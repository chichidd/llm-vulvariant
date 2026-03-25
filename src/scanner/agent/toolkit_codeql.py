"""CodeQL helpers for the agent toolkit."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

import yaml

from profiler.fingerprint import stable_data_hash
from utils.language import get_codeql_pack
from utils.logger import get_logger

from .toolkit_fs import ToolResult

logger = get_logger(__name__)


class ToolkitCodeQLMixin:
    """CodeQL query workspace, database, and result helpers."""

    def _init_codeql(self) -> None:
        """Initialize CodeQL analyzer and query directory state."""
        try:
            self._codeql_analyzer = self._build_codeql_analyzer()
            if not self._codeql_analyzer.is_available:
                logger.warning("CodeQL CLI is not available. CodeQL tools will be disabled.")
                self._codeql_analyzer = None
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Failed to initialize CodeQL analyzer: %s", exc)
            self._codeql_analyzer = None

        self._codeql_query_template_dirs = {
            lang: self._codeql_template_root / lang
            for lang in self._languages
        }
        self._codeql_query_dirs = {}
        self._codeql_query_dirs_ready = set()

    def _resolve_query_language(self, language: Optional[str] = None) -> str:
        """Resolve the language used for CodeQL routing."""
        normalized = str(language or "").strip().lower()
        if normalized:
            return normalized
        return self._primary_language()

    def _setup_query_dir(self, language: Optional[str] = None) -> bool:
        """Lazily set up the CodeQL query directory under the output folder."""
        query_language = self._resolve_query_language(language)
        if not self._memory_manager:
            logger.warning("Memory manager not available. Cannot set up query directory.")
            return False

        output_dir: Path = self._memory_manager.output_dir
        query_dir = output_dir / "codeql-queries" / query_language
        if (
            query_language in self._codeql_query_dirs_ready
            and self._codeql_query_dirs.get(query_language) == query_dir
        ):
            return True

        existing_query_dir = self._codeql_query_dirs.get(query_language)
        if existing_query_dir and existing_query_dir != query_dir:
            logger.info(
                "CodeQL query directory changed for %s from %s to %s; rebuilding query workspace.",
                query_language,
                existing_query_dir,
                query_dir,
            )

        query_dir.mkdir(parents=True, exist_ok=True)

        template_dir = self._codeql_query_template_dirs.get(query_language)
        if template_dir and template_dir.exists():
            for yml_file in template_dir.glob("*.yml"):
                destination = query_dir / yml_file.name
                if not destination.exists():
                    shutil.copy2(yml_file, destination)
                    logger.info("Copied %s to %s", yml_file.name, query_dir)

        self._codeql_query_dirs[query_language] = query_dir
        self._codeql_query_dirs_ready.add(query_language)
        logger.info("CodeQL query directory set up at: %s", query_dir)
        return True

    def _ensure_query_pack(self, language: Optional[str] = None) -> bool:
        """Ensure the CodeQL query pack is prepared with dependencies installed."""
        query_language = self._resolve_query_language(language)
        if not self._setup_query_dir(query_language):
            return False

        query_dir = self._codeql_query_dirs.get(query_language)
        if not query_dir:
            return False

        qlpack_file = query_dir / "qlpack.yml"
        qlpack_lock_file = query_dir / "codeql-pack.lock.yml"
        if qlpack_lock_file.exists():
            return True

        if not qlpack_file.exists():
            try:
                codeql_pack = get_codeql_pack(query_language)
            except ValueError:
                logger.warning("No CodeQL pack available for language: %s", query_language)
                return False
            if not codeql_pack:
                logger.warning("No CodeQL pack available for language: %s", query_language)
                return False
            pack_name = f"llm-vulvariant-queries-{query_language}"
            qlpack_content = f"""name: {pack_name}
version: 1.0.0
description: CodeQL queries for LLM vulnerability variant analysis
dependencies:
  {codeql_pack}: "*"
"""
            qlpack_file.write_text(qlpack_content, encoding="utf-8")

        logger.info("Installing CodeQL pack dependencies...")
        try:
            result = subprocess.run(
                ["codeql", "pack", "install", str(query_dir)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.error("CodeQL pack install failed: %s", result.stderr)
                return False
            logger.info("CodeQL pack dependencies installed successfully")
            return True
        except subprocess.TimeoutExpired:
            logger.error("CodeQL pack install timed out")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to install CodeQL pack: %s", exc)
            return False

    def _get_codeql_database_name(self, language: Optional[str] = None) -> Optional[str]:
        """Return the configured or inferred CodeQL database name."""
        query_language = self._resolve_query_language(language)
        if query_language in self._codeql_database_names:
            return self._codeql_database_names[query_language]
        primary_language = self._primary_language()
        if primary_language in self._codeql_database_names:
            return self._codeql_database_names[primary_language]
        if self._codeql_database_names:
            return next(iter(self._codeql_database_names.values()))
        return self._build_profile_generated_codeql_database_name(language=query_language)

    def _get_profile_metadata(self) -> Dict[str, Any]:
        """Return normalized software-profile metadata when available."""
        metadata: Dict[str, Any] = {}
        if hasattr(self._software_profile, "metadata"):
            raw_metadata = getattr(self._software_profile, "metadata", {})
            if isinstance(raw_metadata, dict):
                metadata = raw_metadata
        elif isinstance(self._software_profile, dict):
            raw_metadata = self._software_profile.get("metadata", {})
            if isinstance(raw_metadata, dict):
                metadata = raw_metadata
        return metadata

    def _get_profile_version(self) -> str:
        """Return the software profile version/commit string."""
        profile_version = ""
        if hasattr(self._software_profile, "version"):
            profile_version = str(getattr(self._software_profile, "version", "") or "").strip()
        elif isinstance(self._software_profile, dict):
            profile_version = str(
                self._software_profile.get("version")
                or self._software_profile.get("basic_info", {}).get("version", "")
                or ""
            ).strip()
        return profile_version

    def _get_profile_source_repo_path(self) -> Optional[Path]:
        """Return the repository path recorded when the software profile was generated."""
        metadata = self._get_profile_metadata()
        raw_repo_path = str(metadata.get("profile_repo_path", "") or "").strip()
        if not raw_repo_path:
            return None
        return Path(raw_repo_path).expanduser().resolve(strict=False)

    def _get_profile_generated_repo_path(self) -> Path:
        """Return the repo path identity that should own profile-generated CodeQL DBs."""
        return self._get_profile_source_repo_path() or self.repo_path

    def _load_codeql_database_identity(self, database_path: Path) -> Dict[str, str]:
        """Read the source repo path and commit metadata embedded in one CodeQL DB."""
        metadata_path = database_path / "codeql-database.yml"
        if not metadata_path.is_file():
            return {}
        try:
            info = yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("Failed to read CodeQL DB metadata from %s: %s", metadata_path, exc)
            return {}
        if not isinstance(info, dict):
            return {}
        creation_metadata = info.get("creationMetadata", {})
        creation_sha = ""
        if isinstance(creation_metadata, dict):
            creation_sha = str(creation_metadata.get("sha", "") or "").strip()
        return {
            "source_repo_path": str(info.get("sourceLocationPrefix", "") or "").strip(),
            "creation_sha": creation_sha,
        }

    def _codeql_database_matches_profile_identity(
        self,
        database_path: Path,
        *,
        profile_version: str,
        expected_source_repo_path: Optional[Path],
    ) -> bool:
        """Return whether one CodeQL DB matches the software profile identity."""
        database_identity = self._load_codeql_database_identity(database_path)
        candidate_sha = str(database_identity.get("creation_sha", "") or "").strip()
        if not candidate_sha or candidate_sha != profile_version:
            return False
        if expected_source_repo_path is None:
            return True

        candidate_source_repo_path = str(database_identity.get("source_repo_path", "") or "").strip()
        if not candidate_source_repo_path:
            return False
        resolved_candidate_source = Path(candidate_source_repo_path).expanduser().resolve(
            strict=False
        )
        return resolved_candidate_source == expected_source_repo_path

    def _build_profile_generated_codeql_database_name(
        self,
        language: Optional[str] = None,
    ) -> Optional[str]:
        """Rebuild the profile-time CodeQL DB name from repo path + profile version."""
        profile_version = self._get_profile_version()
        if not profile_version:
            return None
        query_language = self._resolve_query_language(language)
        profile_generated_repo_path = self._get_profile_generated_repo_path()
        repo_path_hash = stable_data_hash(str(profile_generated_repo_path))[:12]
        return (
            f"{profile_generated_repo_path.name}-{repo_path_hash}-"
            f"{profile_version[:8]}-{query_language}"
        )

    def _find_profile_generated_codeql_database_name(
        self,
        language: Optional[str] = None,
    ) -> Optional[str]:
        """Find the profile-generated CodeQL DB name, even after repo relocation."""
        profile_version = self._get_profile_version()
        if not profile_version:
            return None
        expected_source_repo_path = self._get_profile_source_repo_path()
        exact_name = self._build_profile_generated_codeql_database_name(language=language)
        if exact_name:
            exact_path = self._codeql_db_base_path / exact_name
            if exact_path.is_dir() and self._codeql_database_matches_profile_identity(
                exact_path,
                profile_version=profile_version,
                expected_source_repo_path=expected_source_repo_path,
            ):
                return exact_name

        query_language = self._resolve_query_language(language)
        candidates: List[tuple[int, str]] = []
        for path in self._codeql_db_base_path.glob(
            f"{self.repo_path.name}-*-{profile_version[:8]}-{query_language}"
        ):
            if not path.is_dir():
                continue
            if not self._codeql_database_matches_profile_identity(
                path,
                profile_version=profile_version,
                expected_source_repo_path=expected_source_repo_path,
            ):
                continue
            candidates.append((path.stat().st_mtime_ns, path.name))

        if not candidates:
            return None
        if expected_source_repo_path is None and len(candidates) > 1:
            logger.warning(
                "Ambiguous relocated CodeQL DB fallback for %s@%s (%s); refusing reuse "
                "without stored profile_repo_path metadata",
                self.repo_path.name,
                profile_version[:8],
                ", ".join(name for _, name in candidates[:5]),
            )
            return None

        candidates.sort()
        return candidates[-1][1] if candidates else None

    def _get_codeql_database_path(self, language: Optional[str] = None) -> Optional[Path]:
        """Get the full path to the CodeQL database."""
        candidate_names: List[str] = []
        fallback_name = self._find_profile_generated_codeql_database_name(language=language)
        if fallback_name and fallback_name not in candidate_names:
            candidate_names.append(fallback_name)
        db_name = self._get_codeql_database_name(language=language)
        if db_name and db_name not in candidate_names:
            candidate_names.append(db_name)
        for candidate_name in candidate_names:
            db_path = self._codeql_db_base_path / candidate_name
            if db_path.exists():
                return db_path
        return None

    @staticmethod
    def _infer_query_language(query: str) -> Optional[str]:
        """Infer CodeQL query language from ``import <lang>``."""
        import_match = re.search(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)", query, re.MULTILINE)
        if not import_match:
            return None
        import_key = import_match.group(1).strip().lower()
        alias_map = {
            "python": "python",
            "cpp": "cpp",
            "c": "cpp",
            "go": "go",
            "java": "java",
            "javascript": "javascript",
            "js": "javascript",
            "ruby": "ruby",
        }
        return alias_map.get(import_key)

    def _choose_query_language(self, query: str) -> str:
        """Choose the most suitable language for query pack/database routing."""
        inferred = self._infer_query_language(query)
        if inferred and inferred in self._languages:
            return inferred
        if inferred and inferred in self._codeql_database_names:
            return inferred
        for lang in self._languages:
            if self._get_codeql_database_path(lang):
                return lang
        return self._primary_language()

    def _run_codeql_query(self, query: str, query_name: str) -> ToolResult:
        """Run a CodeQL query on the pre-loaded database."""
        if not self._codeql_analyzer:
            return ToolResult(
                success=False,
                content="",
                error="CodeQL analyzer is not available. Please ensure CodeQL CLI is installed.",
            )

        query_language = self._choose_query_language(query)
        db_name = self._get_codeql_database_name(language=query_language)
        db_path = self._get_codeql_database_path(language=query_language)
        if not db_path:
            return ToolResult(
                success=False,
                content="",
                error=(
                    f"CodeQL database not found. Database name: {db_name}, "
                    f"Search path: {self._codeql_db_base_path}"
                ),
            )

        if not self._ensure_query_pack(query_language):
            return ToolResult(
                success=False,
                content="",
                error="Failed to prepare CodeQL query pack. Check logs for details.",
            )

        query_dir = self._codeql_query_dirs.get(query_language)
        if not query_dir:
            return ToolResult(
                success=False,
                content="",
                error=f"CodeQL query directory not initialized for language: {query_language}",
            )

        safe_name = re.sub(r"[^\w\-]", "_", query_name)
        query_path = query_dir / f"{safe_name}.ql"
        query_path.write_text(query, encoding="utf-8")

        try:
            logger.info(
                "Running CodeQL query '%s' [language=%s, database=%s]",
                query_name,
                query_language,
                db_path,
            )
            success, result = self._codeql_analyzer.run_query(
                database_path=str(db_path),
                query=str(query_path),
                output_format="sarif-latest",
            )

            if not success:
                error_msg = str(result) if result else "Unknown error"
                return ToolResult(
                    success=False,
                    content="",
                    error=f"CodeQL query execution failed: {error_msg}",
                )

            findings = self._extract_codeql_findings(result)
            self._save_codeql_results(
                query_name,
                result,
                findings,
                query_language=query_language,
                database_name=db_name,
            )
            self._record_codeql_findings_in_memory(query_name, findings)
            summary = self._format_codeql_summary(query_name, findings)
            return ToolResult(success=True, content=summary)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("CodeQL query execution error: %s", exc)
            return ToolResult(
                success=False,
                content="",
                error=f"CodeQL query error: {str(exc)}",
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
                for location in locations:
                    physical_location = location.get("physicalLocation", {})
                    artifact_location = physical_location.get("artifactLocation", {})
                    uri = artifact_location.get("uri", "")
                    region = physical_location.get("region", {})
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine", start_line)
                    snippet = region.get("snippet", {}).get("text", "")

                    findings.append(
                        {
                            "rule_id": rule_id,
                            "message": message,
                            "level": level,
                            "file": uri,
                            "start_line": start_line,
                            "end_line": end_line,
                            "snippet": snippet[:200] if snippet else "",
                        }
                    )

        return findings

    def _save_codeql_results(
        self,
        query_name: str,
        sarif_result: Dict[str, Any],
        findings: List[Dict[str, Any]],
        query_language: Optional[str] = None,
        database_name: Optional[str] = None,
    ) -> None:
        """Save CodeQL results to ``output_dir/codeql-results``."""
        if not self._memory_manager:
            logger.warning("Memory manager not available, cannot save CodeQL results to output_dir")
            return

        output_dir = self._memory_manager.output_dir
        results_dir = output_dir / "codeql-results"
        results_dir.mkdir(parents=True, exist_ok=True)

        safe_name = re.sub(r"[^\w\-]", "_", query_name)
        sarif_file = results_dir / f"{safe_name}.sarif"
        sarif_file.write_text(
            json.dumps(sarif_result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        summary_file = results_dir / f"{safe_name}_findings.json"
        summary_data = {
            "query_name": query_name,
            "timestamp": datetime.now().isoformat(),
            "query_language": query_language or self._primary_language(),
            "database": database_name or self._get_codeql_database_name(query_language),
            "total_findings": len(findings),
            "findings": findings,
        }
        summary_file.write_text(
            json.dumps(summary_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        logger.info("CodeQL results saved to %s/%s.*", results_dir, safe_name)

    def _record_codeql_findings_in_memory(self, query_name: str, findings: List[Dict[str, Any]]) -> None:
        """Record CodeQL findings in agent memory."""
        if not self._memory_manager:
            return

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
                "similarity_to_known": f"Detected by CodeQL query: {query_name}",
            }
            self._memory_manager.add_finding(finding_record)

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
            "",
        ]

        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for finding in findings:
            file_path = finding.get("file", "unknown")
            by_file.setdefault(file_path, []).append(finding)

        for file_path, file_findings in sorted(by_file.items()):
            lines.append(f"### {file_path}")
            for finding in file_findings[:5]:
                line = finding.get("start_line", "?")
                rule = finding.get("rule_id", "unknown")
                message = finding.get("message", "")[:100]
                lines.append(f"- **L{line}** [{rule}]: {message}")
            if len(file_findings) > 5:
                lines.append(f"  ... and {len(file_findings) - 5} more in this file")
            lines.append("")

        if len(by_file) > 10:
            lines.append(f"... and issues in {len(by_file) - 10} more files")

        lines.append("")
        lines.append(
            "Results saved to `codeql-results/`. Use `read_codeql_results` tool to see full findings if truncated."
        )

        return "\n".join(lines)

    def _read_codeql_results(self, query_name: str, offset: int = 0, limit: int = 50) -> ToolResult:
        """Read full CodeQL query results from a previous query."""
        if not self._memory_manager:
            return ToolResult(
                success=False,
                content="",
                error="Memory manager not available. Cannot read CodeQL results.",
            )

        safe_name = re.sub(r"[^\w\-]", "_", query_name)
        results_dir = self._memory_manager.output_dir / "codeql-results"
        findings_file = results_dir / f"{safe_name}_findings.json"

        if not findings_file.exists():
            available = []
            if results_dir.exists():
                available = [file.stem.replace("_findings", "") for file in results_dir.glob("*_findings.json")]
            return ToolResult(
                success=False,
                content="",
                error=f"Results not found for query: {query_name}. Available queries: {available}",
            )

        try:
            data = json.loads(findings_file.read_text(encoding="utf-8"))
            findings = data.get("findings", [])
            total = len(findings)
            paginated = findings[offset:offset + limit]

            result = {
                "query_name": query_name,
                "total_findings": total,
                "offset": offset,
                "limit": limit,
                "returned": len(paginated),
                "has_more": offset + limit < total,
                "findings": paginated,
            }

            return ToolResult(
                success=True,
                content=json.dumps(result, indent=2, ensure_ascii=False),
            )
        except Exception as exc:  # pylint: disable=broad-except
            return ToolResult(
                success=False,
                content="",
                error=f"Failed to read CodeQL results: {str(exc)}",
            )
