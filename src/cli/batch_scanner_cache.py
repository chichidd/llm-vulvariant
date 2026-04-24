#!/usr/bin/env python3
"""Cache and fingerprint helpers for the batch scanning pipeline."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import _path_config
from profiler import SoftwareProfiler
from profiler.fingerprint import (
    build_vulnerability_profile_fingerprint,
    profile_fingerprint_field_matches,
    profile_fingerprint_matches,
)
from profiler.vulnerability.analyzer import EXTRACTION_TEMPERATURE
from scanner.agent import load_software_profile
from utils.git_utils import get_git_commit
from utils.llm_utils import extract_function_snippet_based_on_name_with_ast
from utils.logger import get_logger
from utils.vuln_utils import normalize_cve_id

try:
    from cli.common import resolve_cli_path
    from cli.profile_generation import build_vulnerability_entry
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import resolve_cli_path
    from profile_generation import build_vulnerability_entry

logger = get_logger(__name__)


def _is_git_worktree_root(path: Path) -> bool:
    """Return whether ``path`` is the top-level directory of a git worktree."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return Path(result.stdout.strip()).resolve() == path.resolve()


def _normalize_cve_id(entry: Dict[str, object], index: int) -> str:
    """Normalize one vulnerability identifier for cache validation."""
    return normalize_cve_id(entry.get("cve_id"), index)


def _load_vuln_entries(vuln_json: Path, limit: Optional[int] = None) -> List[Tuple[int, Dict[str, object]]]:
    """Load indexed vulnerability entries from ``vuln.json``."""
    raw_entries = json.loads(vuln_json.read_text(encoding="utf-8"))
    indexed = list(enumerate(raw_entries))
    if limit is not None:
        indexed = indexed[:limit]
    return indexed


def _normalize_vuln_call_chain_for_cache_check(call_chain: Any) -> List[Dict[str, str]]:
    """Normalize call chains for cache validation without depending on code snippets."""
    normalized: List[Dict[str, str]] = []
    if not isinstance(call_chain, list):
        return normalized

    for step in call_chain:
        if isinstance(step, str):
            stripped = step.strip()
            if not stripped:
                continue
            if "#" in stripped:
                file_path, function_name = stripped.split("#", 1)
                normalized.append({"file_path": file_path, "function_name": function_name})
            else:
                normalized.append({"vuln_sink": stripped})
            continue

        if not isinstance(step, dict):
            continue

        file_path = str(step.get("file_path", "")).strip()
        function_name = str(step.get("function_name", "")).strip()
        vuln_sink = str(step.get("vuln_sink", "")).strip()
        if file_path or function_name:
            normalized_step: Dict[str, str] = {}
            if file_path:
                normalized_step["file_path"] = file_path
            if function_name:
                normalized_step["function_name"] = function_name
            if vuln_sink:
                normalized_step["vuln_sink"] = vuln_sink
            normalized.append(normalized_step)
        elif vuln_sink:
            normalized.append({"vuln_sink": vuln_sink})

    return normalized


def _build_current_vuln_data_for_cache_check(
    *,
    repo_path: Path,
    raw_entry: Dict[str, Any],
    commit_hash: str,
    cve_id: str,
) -> Dict[str, Any]:
    """Materialize target-commit call-chain snippets for cache validation."""
    resolved_repo_path = repo_path.resolve(strict=False)
    current_commit = get_git_commit(str(repo_path))
    materialized_call_chain: List[Dict[str, Any]] = []

    for step in raw_entry.get("call_chain", []):
        if isinstance(step, str):
            stripped = step.strip()
            if not stripped:
                continue
            if "#" not in stripped:
                materialized_call_chain.append({"vuln_sink": stripped})
                continue
            file_path, function_name = stripped.split("#", 1)
            vuln_sink = ""
        elif isinstance(step, dict):
            file_path = str(step.get("file_path", "")).strip()
            function_name = str(step.get("function_name", "")).strip()
            vuln_sink = str(step.get("vuln_sink", "")).strip()
            if not file_path and not function_name:
                if vuln_sink:
                    materialized_call_chain.append({"vuln_sink": vuln_sink})
                continue
            if not file_path or not function_name:
                materialized_step: Dict[str, Any] = {}
                if file_path:
                    materialized_step["file_path"] = file_path
                if function_name:
                    materialized_step["function_name"] = function_name
                if vuln_sink:
                    materialized_step["vuln_sink"] = vuln_sink
                materialized_call_chain.append(materialized_step)
                continue
        else:
            continue

        relative_file_path = Path(file_path).expanduser()
        source_path = (resolved_repo_path / relative_file_path).resolve(strict=False)
        try:
            source_path.relative_to(resolved_repo_path)
        except ValueError as exc:
            raise RuntimeError(
                f"Call chain file path escapes repository root: {file_path}"
            ) from exc

        if current_commit and current_commit != commit_hash:
            git_show_target = f"{commit_hash}:{relative_file_path.as_posix()}"
            git_show = subprocess.run(
                ["git", "-C", str(repo_path), "show", git_show_target],
                capture_output=True,
                check=False,
            )
            if git_show.returncode != 0:
                stderr = git_show.stderr.decode("utf-8", errors="ignore").strip()
                raise RuntimeError(
                    f"Failed to read call chain file from target commit {git_show_target}: {stderr}"
                )
            code_content = git_show.stdout.decode("utf-8", errors="ignore")
        else:
            code_content = source_path.read_text(encoding="utf-8", errors="ignore")
        code_snippet = extract_function_snippet_based_on_name_with_ast(
            code_content,
            function_name,
            with_line_numbers=True,
            line_number_format="standard",
        )
        materialized_step = {
            "file_path": file_path,
            "function_name": function_name,
            "file_content": code_content,
            "code_snippet": code_snippet,
        }
        if vuln_sink:
            materialized_step["vuln_sink"] = vuln_sink
        materialized_call_chain.append(materialized_step)

    return {
        "repo_name": str(raw_entry.get("repo_name", "")).strip(),
        "commit": str(raw_entry.get("commit", "")).strip(),
        "call_chain": materialized_call_chain,
        "payload": raw_entry.get("payload"),
        "cve_id": cve_id,
    }


def _cached_vulnerability_profile_matches_current_inputs(
    *,
    cached_profile: Any,
    source_profile: Any,
    repo_path: Path,
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    vuln_index: int,
    vuln_json_path: Optional[str],
    llm_client: Any,
) -> bool:
    """Validate whether a dirty-repo cached vulnerability profile is still current."""
    if vuln_json_path is None:
        return False

    resolved_vuln_json = resolve_cli_path(vuln_json_path, base_dir=_path_config["repo_root"])
    raw_entries = _load_vuln_entries(resolved_vuln_json)
    if vuln_index < 0 or vuln_index >= len(raw_entries):
        return False

    _, raw_entry = raw_entries[vuln_index]
    expected_cve_id = _normalize_cve_id(raw_entry, vuln_index)
    cached_call_chain = _normalize_vuln_call_chain_for_cache_check(getattr(cached_profile, "call_chain", []))
    current_call_chain = _normalize_vuln_call_chain_for_cache_check(raw_entry.get("call_chain", []))
    if (
        str(raw_entry.get("repo_name", "")) != repo_name
        or str(raw_entry.get("commit", "")) != commit_hash
        or expected_cve_id != cve_id
        or raw_entry.get("payload") != getattr(cached_profile, "payload", None)
        or current_call_chain != cached_call_chain
        or getattr(cached_profile, "repo_name", "") != repo_name
        or getattr(cached_profile, "affected_version", None) != commit_hash
        or getattr(cached_profile, "cve_id", None) != cve_id
    ):
        return False

    try:
        current_vuln_data = _build_current_vuln_data_for_cache_check(
            repo_path=repo_path,
            raw_entry=raw_entry,
            commit_hash=commit_hash,
            cve_id=cve_id,
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "Failed to materialize current vulnerability snippets for cache validation: %s",
            exc,
        )
        return False

    expected_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(current_vuln_data),
        llm_client=llm_client,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    return profile_fingerprint_matches(cached_profile, expected_fingerprint)


def _cached_vulnerability_profile_matches_missing_repo_inputs(
    *,
    cached_profile: Any,
    source_profile: Any,
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    vuln_index: int,
    vuln_json_path: Optional[str],
    llm_client: Any,
) -> bool:
    """Validate cached vulnerability profiles without accessing the source repo.

    Args:
        cached_profile: Persisted vulnerability profile candidate.
        source_profile: Current cached software profile used by this vulnerability.
        repo_name: Repository name from the current vuln entry.
        commit_hash: Commit hash from the current vuln entry.
        cve_id: Normalized vulnerability identifier.
        vuln_index: Index into ``vuln.json``.
        vuln_json_path: Path to the current vulnerability list.
        llm_client: LLM client whose config participates in the profile fingerprint.

    Returns:
        Whether the cached vulnerability profile still matches the persisted
        vuln entry and current source software profile fingerprint.
    """
    if vuln_json_path is None:
        return False

    resolved_vuln_json = resolve_cli_path(vuln_json_path, base_dir=_path_config["repo_root"])
    raw_entries = _load_vuln_entries(resolved_vuln_json)
    if vuln_index < 0 or vuln_index >= len(raw_entries):
        return False

    _, raw_entry = raw_entries[vuln_index]
    expected_cve_id = _normalize_cve_id(raw_entry, vuln_index)
    cached_call_chain = _normalize_vuln_call_chain_for_cache_check(getattr(cached_profile, "call_chain", []))
    current_call_chain = _normalize_vuln_call_chain_for_cache_check(raw_entry.get("call_chain", []))
    if (
        str(raw_entry.get("repo_name", "")) != repo_name
        or str(raw_entry.get("commit", "")) != commit_hash
        or expected_cve_id != cve_id
        or raw_entry.get("payload") != getattr(cached_profile, "payload", None)
        or current_call_chain != cached_call_chain
        or getattr(cached_profile, "repo_name", "") != repo_name
        or getattr(cached_profile, "affected_version", None) != commit_hash
        or getattr(cached_profile, "cve_id", None) != cve_id
    ):
        return False

    materialized_call_chain = getattr(cached_profile, "call_chain", [])
    if not isinstance(materialized_call_chain, list):
        return False

    expected_fingerprint = build_vulnerability_profile_fingerprint(
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(
            {
                "repo_name": repo_name,
                "commit": commit_hash,
                "call_chain": materialized_call_chain,
                "payload": raw_entry.get("payload"),
                "cve_id": cve_id,
            }
        ),
        llm_client=llm_client,
        extraction_temperature=EXTRACTION_TEMPERATURE,
    )
    return profile_fingerprint_matches(cached_profile, expected_fingerprint)


def _load_cached_software_profile_if_compatible(
    *,
    repo_name: str,
    commit_hash: str,
    repo_profiles_dir: Path,
    llm_client: Any,
    repo_path: Optional[Path] = None,
) -> Optional[object]:
    """Load one cached software profile only when its fingerprint is current.

    Args:
        repo_name: Repository name used in the profile path layout.
        commit_hash: Commit hash subdirectory name.
        repo_profiles_dir: Root directory containing persisted software profiles.
        llm_client: LLM client whose config participates in the profile fingerprint.
        repo_path: Optional working tree path used for dirty-repo validation.

    Returns:
        The cached software profile when it matches the current profiler inputs,
        otherwise ``None``.
    """
    cached_profile = load_software_profile(
        repo_name,
        commit_hash,
        base_dir=repo_profiles_dir,
    )
    if not cached_profile:
        return None

    profiler = SoftwareProfiler(
        llm_client=llm_client,
        output_dir=str(repo_profiles_dir),
    )
    profiler._current_fingerprint_repo_path = repo_path  # pylint: disable=protected-access
    if repo_path is not None and _is_git_worktree_root(repo_path):
        profiler._current_fingerprint_repo_version = (
            get_git_commit(str(repo_path)) or commit_hash
        )  # pylint: disable=protected-access
    else:
        profiler._current_fingerprint_repo_version = commit_hash  # pylint: disable=protected-access
    expected_fingerprint = profiler._build_profile_fingerprint()  # pylint: disable=protected-access
    fingerprint_field = "hash" if repo_path is not None else "inputs_hash"
    if profile_fingerprint_field_matches(
        cached_profile,
        expected_fingerprint,
        fingerprint_field,
    ):
        return cached_profile
    logger.info(
        "Cached software profile fingerprint field %s is missing or stale for %s@%s",
        fingerprint_field,
        repo_name,
        commit_hash[:12],
    )
    return None
