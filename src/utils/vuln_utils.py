"""Helpers for loading vulnerability entries and resolving repository state."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from config import _path_config
from .git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from .logger import get_logger
from utils.llm_utils import extract_function_snippet_based_on_name_with_ast

logger = get_logger(__name__)


def normalize_cve_id(cve_id: Any, index: int | None = None) -> str:
    """Return a stable profile identifier for a vulnerability entry.

    Args:
        cve_id: Original CVE identifier from input data.
        index: Entry index used as a deterministic fallback.

    Returns:
        Normalized CVE-like identifier suitable for directory naming.
    """
    normalized = str(cve_id or "").strip()
    if normalized:
        return normalized
    if index is not None:
        return f"vuln-{index}"
    return "no_cve"


def read_vuln_data(
    index: int | None = None,
    verbose: bool = False,
    vuln_json_path: str | Path | None = None,
    repo_base_path: str | Path | None = None,
) -> List[Dict[str, Any]]:
    """Load vulnerability entries and enrich call-chain locations with code.

    The helper temporarily checks out each repository to the vulnerable commit
    when necessary so call-chain snippets are extracted from the correct source
    tree. Repository position is restored before moving to the next entry.

    Args:
        index: Optional single-entry selector.
        verbose: Whether to emit progress logs.
        vuln_json_path: Optional path to the vulnerability JSON file.
        repo_base_path: Optional repository root override.

    Returns:
        List of normalized vulnerability dictionaries used by the profilers.
    """
    if verbose:
        logger.info("Reading vulnerability data...")
    source_path = (
        Path(vuln_json_path).expanduser()
        if vuln_json_path
        else _path_config["vuln_data_path"]
    )
    resolved_repo_base_path = (
        Path(repo_base_path).expanduser()
        if repo_base_path
        else _path_config["repo_base_path"]
    )
    raw_data = json.loads(source_path.read_text(encoding="utf-8"))
    resolved_entries: List[Dict[str, Any]] = []
    entries = list(enumerate(raw_data))
    if index is not None:
        entries = [entries[index]]

    for entry_index, entry in entries:
        data: Dict[str, Any] = {}
        data['repo_name'] = entry['repo_name']
        data['commit'] = entry['commit']
        data['cve_id'] = normalize_cve_id(entry.get('cve_id'), entry_index)
        repo_path = resolved_repo_base_path / data['repo_name']
        restore_target = get_git_restore_target(str(repo_path))
        switched_commit = False
        if verbose:
            logger.info(f"Processing repository: {data['repo_name']} at commit {data['commit']}")
        try:
            current_commit = get_git_commit(repo_path)
            if current_commit != data['commit']:
                if has_uncommitted_changes(repo_path):
                    raise RuntimeError(
                        f"Repository {data['repo_name']} has local changes; "
                        f"refuse commit switch to {data['commit']}"
                    )
                if verbose:
                    logger.info(
                        f"Checking out {data['repo_name']} to commit {data['commit']} "
                        f"(current: {current_commit})"
                    )
                if not checkout_commit(repo_path, data['commit']):
                    raise RuntimeError(
                        f"Failed to checkout {data['repo_name']} to commit {data['commit']}"
                    )
                switched_commit = True
            else:
                if verbose:
                    logger.info(f"{data['repo_name']} is already at commit {data['commit']}")

            call_chain_records: List[Dict[str, Any]] = []
            for callsite in entry['call_chain']:
                if '#' in callsite:
                    file_relative_path, function_name = callsite.split('#', 1)

                    code_content = (repo_path / file_relative_path).read_text(encoding='utf-8', errors='ignore')
                    snippet = extract_function_snippet_based_on_name_with_ast(
                            code_content,
                            function_name,
                            with_line_numbers=True,
                            line_number_format="standard"
                        )
                    if verbose:
                        logger.info(f"\n{'-'*40}\nFile: {file_relative_path}, Function: {function_name}\n{'-'*40}")
                        logger.info(snippet)
                    call_chain_records.append(
                        {
                            'file_path': file_relative_path,
                            'function_name': function_name,
                            'file_content': code_content,
                            'code_snippet': snippet,
                        }
                    )
                else:
                    call_chain_records.append({'vuln_sink': callsite})
            data['call_chain'] = call_chain_records
            data['payload'] = entry['payload']
            resolved_entries.append(data)
        finally:
            # Restore the repository even when snippet extraction fails so later
            # pipeline stages do not inherit a detached or stale checkout.
            if switched_commit and restore_target:
                restore_git_position(repo_path, restore_target)
    return resolved_entries
