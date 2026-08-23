#!/usr/bin/env python3
"""Batch vulnerability scanning pipeline for all entries in vuln.json."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from config import DEFAULT_SOFTWARE_PROFILE_DIRNAME, DEFAULT_VULN_PROFILE_DIRNAME, _path_config
from llm import create_llm_client
from scanner.agent import load_software_profile, load_vulnerability_profile
from scanner.output_commit import (
    ScanOutputCommitError,
    canonical_scan_commit,
    canonical_scan_reference_id,
    canonical_scan_repo_name,
)
from scanner.similarity.embedding import DEFAULT_EMBEDDING_MODEL_NAME, embedding_model_artifact_signature
from scanner.similarity import (
    ProfileRef,
    SimilarProfileCandidate,
    EmbeddingUnavailableError,
    build_text_retriever,
    compute_profile_similarity,
    load_all_software_profiles,
    resolve_profile_commit,
)
from utils.concurrency import RepoPathLockManager, run_thread_pool_tasks
from utils.git_utils import (
    get_git_commit,
    has_uncommitted_changes,
)
from utils.io_utils import write_atomic_text
from utils.logger import get_logger
from utils.number_utils import to_int
from utils.repo_lock import hold_repo_lock
from utils.vuln_utils import normalize_cve_id, read_vuln_data

try:
    from cli import agent_scanner
    from cli.common import resolve_cli_path, resolve_profile_dirs, setup_logging
    from cli.profile_generation import (
        build_vulnerability_entry,
        create_profile_llm_client,
        run_software_profile_generation,
        run_vulnerability_profile_generation,
    )
except ImportError:  # pragma: no cover - direct script execution fallback
    import agent_scanner
    from common import resolve_cli_path, resolve_profile_dirs, setup_logging
    from profile_generation import (
        build_vulnerability_entry,
        create_profile_llm_client,
        run_software_profile_generation,
        run_vulnerability_profile_generation,
    )

try:
    from cli import batch_scanner_execution as batch_scanner_execution_module
    from cli.batch_scanner_cache import (
        _cached_vulnerability_profile_matches_current_inputs,
        _cached_vulnerability_profile_matches_missing_repo_inputs,
        _is_git_worktree_root,
        _load_cached_software_profile_if_compatible,
        _load_vuln_entries,
    )
    from cli.batch_scanner_execution import (
        _build_expected_scan_fingerprint_for_skip,
        _build_profile_based_scan_fingerprint_for_skip,
        _load_saved_scan_quality,
        _run_selected_target_scans,
        _run_target_scan,
        scan_output_binding_key,
    )
except ImportError:  # pragma: no cover - direct script execution fallback
    import batch_scanner_execution as batch_scanner_execution_module
    from batch_scanner_cache import (
        _cached_vulnerability_profile_matches_current_inputs,
        _cached_vulnerability_profile_matches_missing_repo_inputs,
        _is_git_worktree_root,
        _load_cached_software_profile_if_compatible,
        _load_vuln_entries,
    )
    from batch_scanner_execution import (
        _build_expected_scan_fingerprint_for_skip,
        _build_profile_based_scan_fingerprint_for_skip,
        _load_saved_scan_quality,
        _run_selected_target_scans,
        _run_target_scan,
        scan_output_binding_key,
    )

logger = get_logger(__name__)
_IMPORTED_CREATE_LLM_CLIENT = create_llm_client
_IMPORTED_RUN_TARGET_SCAN = _run_target_scan

__all__ = [
    "agent_scanner",
    "_build_expected_scan_fingerprint_for_skip",
    "_build_profile_based_scan_fingerprint_for_skip",
    "_cached_vulnerability_profile_matches_current_inputs",
    "_cached_vulnerability_profile_matches_missing_repo_inputs",
    "_load_cached_software_profile_if_compatible",
    "_load_saved_scan_quality",
    "_load_vuln_entries",
    "_run_selected_target_scans",
    "_run_target_scan",
]


@dataclass(frozen=True)
class BatchScanPaths:
    """Resolved filesystem inputs for one batch scan run."""

    vuln_json: Path
    source_repos_root: Path
    target_repos_root: Path
    source_repo_profiles_dir: Path
    target_repo_profiles_dir: Path
    vuln_profiles_dir: Path
    scan_output_dir: Path


@dataclass
class BatchScanCaches:
    """Cached profile state reused across vulnerability entries."""

    source_software_cache: Dict[Tuple[str, str], object]
    target_software_cache: Dict[Tuple[str, str], object]
    vulnerability_cache: Dict[Tuple[str, str, str], object]
    regenerated_source_software_keys: Set[Tuple[str, str]]
    regenerated_target_software_keys: Set[Tuple[str, str]]


_UNPRIORITIZED_MANIFEST_SCHEMA_VERSION = 1
_UNPRIORITIZED_MANIFEST_ALGORITHM = "sha256-seed-path-v1"
_UNPRIORITIZED_MANIFEST_EXPECTED_ROWS = 60
_UNPRIORITIZED_MANIFEST_EXPECTED_TARGETS = 20
_UNPRIORITIZED_MANIFEST_EXPECTED_REPLICATES = frozenset({1, 2, 3})
_UNPRIORITIZED_MANIFEST_KEYS = {
    "schema_version",
    "freeze_status",
    "algorithm",
    "benchmark_constant",
    "schedules",
}
_UNPRIORITIZED_MANIFEST_ROW_KEYS = {
    "target_id",
    "target_commit",
    "replicate",
    "path",
    "file_sha256",
    "file_count",
    "target_software_profile_path",
    "target_software_profile_sha256",
    "overlap_path_count",
    "overlap_extra_membership_count",
    "multi_module_paths",
    "multi_module_paths_sha256",
    "universe_sha256",
    "order_sha256",
}
_SCAN_OUTPUT_COMMIT_MANIFEST_SCHEMA_VERSION = 2
_SCAN_OUTPUT_COMMIT_MANIFEST_KIND = "scanner_output_commit_bindings"
_SCAN_OUTPUT_COMMIT_MANIFEST_KEYS = {
    "schema_version",
    "kind",
    "batch_summary",
    "bindings",
}
_SCAN_OUTPUT_COMMIT_SUMMARY_KEYS = {"path", "sha256"}
_SCAN_OUTPUT_COMMIT_BINDING_KEYS = {
    "cve_id",
    "repo_name",
    "commit",
    "scan_output_commit_sha256",
}
_BATCH_SUMMARY_COUNT_KEYS = (
    "total_scans",
    "successful_scans",
    "skipped_scans",
    "incomplete_scans",
    "failed_profile_generation",
    "invalid_vuln_entries",
    "zero_target_vulnerabilities",
    "failed_scans",
    "coverage_complete_scans",
    "coverage_partial_scans",
    "coverage_empty_scans",
    "coverage_unknown_scans",
)
_BATCH_SUMMARY_ZERO_COUNT_KEYS = (
    "incomplete_scans",
    "failed_profile_generation",
    "invalid_vuln_entries",
    "zero_target_vulnerabilities",
    "failed_scans",
    "coverage_partial_scans",
    "coverage_empty_scans",
    "coverage_unknown_scans",
)


def _require_sha256(value: Any, *, label: str) -> str:
    """规范化必需的小写 SHA-256。"""
    digest = str(value or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _require_json_sha256(value: Any, *, label: str) -> str:
    """校验 JSON 内未经规范化的精确小写 SHA-256 字符串。"""
    if (
        type(value) is not str
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise ValueError(f"{label} must be an exact lowercase SHA-256 string")
    return value


def _normalize_manifest_relative_path(value: Any, *, label: str) -> str:
    """校验相对于可信 schedule root 的规范 POSIX 路径。"""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty relative path")
    if "\\" in value or "//" in value or value.endswith("/"):
        raise ValueError(f"{label} must be a canonical POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must remain inside the trusted schedule root")
    normalized = path.as_posix()
    if normalized != value:
        raise ValueError(f"{label} must be a canonical POSIX relative path")
    return normalized


def _resolve_trusted_root(
    root_value: str | Path,
    *,
    label: str = "trusted unprioritized file-order root",
) -> Path:
    """解析调用方 schedule root，拒绝符号链接根目录。"""
    root = Path(root_value).expanduser()
    if not root.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    normalized_root = Path(os.path.abspath(root))
    if root != normalized_root:
        raise ValueError(f"{label} must use a canonical absolute path")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} must not use symlink components: {current}")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable: {root}") from exc
    if not resolved.is_dir():
        raise ValueError(f"{label} is not a directory: {resolved}")
    if resolved != normalized_root:
        raise ValueError(f"{label} must not resolve through aliases")
    return resolved


def _resolve_trusted_regular_file(
    trusted_root: Path,
    path_value: str | Path,
    *,
    label: str,
    require_relative: bool = True,
) -> Path:
    """解析可信根内普通文件，拒绝符号链接路径分量。"""
    raw_path = Path(path_value).expanduser()
    if require_relative:
        relative = Path(
            _normalize_manifest_relative_path(str(path_value), label=label)
        )
    else:
        candidate = raw_path if raw_path.is_absolute() else trusted_root / raw_path
        try:
            relative = candidate.relative_to(trusted_root)
        except ValueError as exc:
            raise ValueError(f"{label} must remain inside the trusted schedule root") from exc
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError(f"{label} must remain inside the trusted schedule root")

    current = trusted_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} must not use symlink components: {current}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(trusted_root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} is unavailable or outside the trusted schedule root") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} is not a regular file: {resolved}")
    return resolved


def _parse_json_object_bytes(raw_bytes: bytes, *, label: str) -> Dict[str, Any]:
    """解析已捕获的 UTF-8 JSON 快照并拒绝重复键。"""
    def reject_duplicate_keys(pairs):
        parsed: Dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise ValueError(f"duplicate JSON key in {label}: {key}")
            parsed[key] = value
        return parsed

    try:
        payload = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value in {label}: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _load_hashed_json_object(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
    sha_label: Optional[str] = None,
) -> Tuple[Dict[str, Any], str]:
    """只读一次，再哈希并解析同一不可变字节快照。"""
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(f"{sha_label or f'{label} SHA-256'} mismatch")
    return _parse_json_object_bytes(raw_bytes, label=label), actual_sha256


def _extract_complete_summary_bindings(
    summary: Mapping[str, Any],
) -> Dict[str, Dict[str, str]]:
    """从完整 batch 摘要严格重建全部 scanner 绑定。"""
    entries = summary.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("complete batch summary entries must be a non-empty list")

    bindings: Dict[str, Dict[str, str]] = {}
    seen_marker_hashes: Set[str] = set()
    observed_statuses: Counter[str] = Counter()
    for entry_number, entry in enumerate(entries, start=1):
        if not isinstance(entry, Mapping):
            raise ValueError(
                f"complete batch summary entry {entry_number} must be an object"
            )
        try:
            cve_id = canonical_scan_reference_id(entry.get("cve_id"))
        except ScanOutputCommitError as exc:
            raise ValueError(
                f"complete batch summary entry {entry_number} identity is invalid"
            ) from exc
        scan_results = entry.get("scan_results")
        if not isinstance(scan_results, list) or not scan_results:
            raise ValueError(
                f"complete batch summary entry {entry_number} has no scan results"
            )
        for result_number, result in enumerate(scan_results, start=1):
            label = (
                f"complete batch summary entry {entry_number} "
                f"scan result {result_number}"
            )
            if not isinstance(result, Mapping):
                raise ValueError(f"{label} must be an object")
            status = result.get("status")
            if status not in {"ok", "skipped"}:
                raise ValueError(f"{label} is not terminal-successful")
            if result.get("headline_eligible") is not True:
                raise ValueError(f"{label} is not headline eligible")
            try:
                repo_name = canonical_scan_repo_name(result.get("repo_name"))
                commit = canonical_scan_commit(result.get("commit_hash"))
            except ScanOutputCommitError as exc:
                raise ValueError(f"{label} identity is invalid") from exc
            marker_sha256 = _require_json_sha256(
                result.get("scan_output_commit_sha256"),
                label=f"{label} scan_output_commit_sha256",
            )
            key = scan_output_binding_key(cve_id, repo_name, commit)
            if key in bindings:
                raise ValueError(f"duplicate scan output commit binding: {key}")
            if marker_sha256 in seen_marker_hashes:
                raise ValueError(
                    "scanner output commit marker hash is reused across identities"
                )
            seen_marker_hashes.add(marker_sha256)
            bindings[key] = {
                "cve_id": cve_id,
                "repo_name": repo_name,
                "commit": commit,
                "scan_output_commit_sha256": marker_sha256,
            }
            observed_statuses[status] += 1

    if len(bindings) != summary["total_scans"]:
        raise ValueError(
            "scanner output binding count disagrees with total_scans"
        )
    if observed_statuses["ok"] != summary["successful_scans"]:
        raise ValueError(
            "scanner output success count disagrees with batch summary"
        )
    if observed_statuses["skipped"] != summary["skipped_scans"]:
        raise ValueError(
            "scanner output skipped count disagrees with batch summary"
        )
    return bindings


def _validate_complete_batch_summary(
    summary: Mapping[str, Any],
) -> Dict[str, Dict[str, str]]:
    """校验可发布绑定的完整 batch 摘要并重建绑定。"""
    if (
        summary.get("status") != "complete"
        or summary.get("partial") is not False
        or summary.get("termination") != "batch_finished"
        or summary.get("failure_reason") is not None
    ):
        raise ValueError("bound batch summary is not headline complete")
    for key in _BATCH_SUMMARY_COUNT_KEYS:
        value = summary.get(key)
        if type(value) is not int or value < 0:
            raise ValueError(
                f"bound batch summary {key} must be a non-negative integer"
            )
    total_scans = summary["total_scans"]
    if (
        total_scans <= 0
        or summary["successful_scans"] + summary["skipped_scans"]
        != total_scans
        or summary["coverage_complete_scans"] != total_scans
        or any(summary[key] != 0 for key in _BATCH_SUMMARY_ZERO_COUNT_KEYS)
    ):
        raise ValueError("bound batch summary is not headline complete")
    return _extract_complete_summary_bindings(summary)


def load_scan_output_commit_manifest(
    manifest_path_value: str | Path,
    expected_manifest_sha256: str,
) -> Dict[str, Any]:
    """读取外部哈希绑定的 scanner 终态清单。"""
    requested_manifest_path = Path(manifest_path_value).expanduser()
    if not requested_manifest_path.is_absolute():
        requested_manifest_path = (
            _path_config["repo_root"] / requested_manifest_path
        )
    if requested_manifest_path.is_symlink():
        raise ValueError("scan output commit manifest must not be a symlink")
    manifest_path = requested_manifest_path.resolve(strict=True)
    manifest_sha256 = _require_sha256(
        expected_manifest_sha256,
        label="scan output commit manifest SHA-256",
    )
    payload, _ = _load_hashed_json_object(
        manifest_path,
        manifest_sha256,
        label="scan output commit manifest",
        sha_label="scan output commit manifest SHA-256",
    )
    if set(payload) != _SCAN_OUTPUT_COMMIT_MANIFEST_KEYS:
        raise ValueError("scan output commit manifest has an unexpected key set")
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version")
        != _SCAN_OUTPUT_COMMIT_MANIFEST_SCHEMA_VERSION
    ):
        raise ValueError("scan output commit manifest must use schema_version=2")
    if payload.get("kind") != _SCAN_OUTPUT_COMMIT_MANIFEST_KIND:
        raise ValueError("scan output commit manifest kind mismatch")
    raw_summary = payload.get("batch_summary")
    if (
        not isinstance(raw_summary, dict)
        or set(raw_summary) != _SCAN_OUTPUT_COMMIT_SUMMARY_KEYS
    ):
        raise ValueError("scan output commit manifest batch_summary is invalid")
    summary_name = raw_summary.get("path")
    if (
        type(summary_name) is not str
        or not re.fullmatch(r"batch-summary-[A-Za-z0-9._-]+[.]json", summary_name)
        or Path(summary_name).name != summary_name
    ):
        raise ValueError("scan output commit manifest summary path is invalid")
    expected_manifest_name = summary_name.replace(
        "batch-summary-",
        "scan-output-commit-bindings-",
        1,
    )
    if manifest_path.name != expected_manifest_name:
        raise ValueError(
            "scan output commit manifest path is not the canonical publication marker"
        )
    summary_sha256 = _require_json_sha256(
        raw_summary.get("sha256"),
        label="batch summary SHA-256",
    )
    summary_payload, _ = _load_hashed_json_object(
        manifest_path.parent / summary_name,
        summary_sha256,
        label="bound batch summary",
        sha_label="batch summary SHA-256",
    )
    summary_bindings = _validate_complete_batch_summary(summary_payload)
    raw_bindings = payload.get("bindings")
    if not isinstance(raw_bindings, list):
        raise ValueError("scan output commit manifest bindings must be a list")

    bindings: Dict[str, str] = {}
    for row_number, raw_row in enumerate(raw_bindings, start=1):
        if not isinstance(raw_row, dict) or set(raw_row) != _SCAN_OUTPUT_COMMIT_BINDING_KEYS:
            raise ValueError(
                f"scan output commit manifest row {row_number} has an unexpected key set"
            )
        try:
            cve_id = canonical_scan_reference_id(raw_row.get("cve_id"))
            repo_name = canonical_scan_repo_name(raw_row.get("repo_name"))
            commit = canonical_scan_commit(raw_row.get("commit"))
        except ScanOutputCommitError as exc:
            raise ValueError(
                f"scan output commit manifest row {row_number} identity is invalid"
            ) from exc
        marker_sha256 = _require_json_sha256(
            raw_row.get("scan_output_commit_sha256"),
            label=(
                f"scan output commit manifest row {row_number} "
                "scan_output_commit_sha256"
            ),
        )
        key = scan_output_binding_key(cve_id, repo_name, commit)
        if key in bindings:
            raise ValueError(f"duplicate scan output commit binding: {key}")
        if marker_sha256 in bindings.values():
            raise ValueError(
                "scanner output commit marker hash is reused across identities"
            )
        bindings[key] = marker_sha256
    expected_bindings = {
        key: row["scan_output_commit_sha256"]
        for key, row in summary_bindings.items()
    }
    if bindings != expected_bindings:
        raise ValueError(
            "scanner output commit bindings disagree with batch summary entries"
        )
    return {
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "bindings": bindings,
        "batch_summary_path": str(manifest_path.parent / summary_name),
        "batch_summary_sha256": summary_sha256,
        "batch_summary": summary_payload,
    }


def _frozen_profile_universe(profile: Mapping[str, Any]) -> Dict[str, Any]:
    """展开冻结画像的模块文件并保留重叠 provenance。"""
    basic_info = profile.get("basic_info")
    if not isinstance(basic_info, Mapping):
        raise ValueError("target software profile basic_info must be an object")
    target_repo_name = str(basic_info.get("name", "") or "").strip()
    target_commit = str(basic_info.get("version", "") or "").strip()
    if not target_repo_name:
        raise ValueError("target software profile basic_info.name is missing")
    if not re.fullmatch(r"[0-9a-f]{40}", target_commit):
        raise ValueError(
            "target software profile basic_info.version must be a full lowercase commit"
        )
    modules = profile.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ValueError("target software profile modules must be a non-empty list")
    occurrences: Counter[str] = Counter()
    for module in modules:
        if not isinstance(module, Mapping):
            raise ValueError("target software profile modules must be objects")
        files = module.get("files")
        if not isinstance(files, list):
            raise ValueError("target software profile module files must be lists")
        for raw_path in files:
            normalized = _normalize_manifest_relative_path(
                raw_path,
                label="target software profile file",
            )
            occurrences[normalized] += 1
    if not occurrences:
        raise ValueError("target software profile file universe must not be empty")
    files = sorted(occurrences, key=lambda path: path.encode("utf-8"))
    multi_module_paths = [path for path in files if occurrences[path] > 1]
    return {
        "target_repo_name": target_repo_name,
        "target_commit": target_commit,
        "files": files,
        "overlap_path_count": len(multi_module_paths),
        "overlap_extra_membership_count": sum(
            occurrences[path] - 1 for path in multi_module_paths
        ),
        "multi_module_paths": multi_module_paths,
        "multi_module_paths_sha256": agent_scanner.stable_data_hash(multi_module_paths),
    }


def _normalize_runtime_software_profile(profile: Any) -> Dict[str, Any]:
    """规范化内存 ProfileRef 画像以精确比较 JSON payload。"""
    payload = profile.to_dict() if hasattr(profile, "to_dict") else profile
    if not isinstance(payload, Mapping):
        raise ValueError("runtime software profile object cannot be normalized")
    try:
        normalized = json.loads(
            json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("runtime software profile object is not JSON serializable") from exc
    if not isinstance(normalized, dict):
        raise ValueError("runtime software profile object must normalize to a JSON object")
    return normalized


def load_batch_unprioritized_schedule_manifest(
    manifest_path_value: str | Path,
    expected_manifest_sha256: str,
    trusted_root_value: str | Path,
) -> Dict[str, Any]:
    """加载并完整校验冻结的 20 目标三重复 schedule manifest。"""
    trusted_root = _resolve_trusted_root(trusted_root_value)
    manifest_path = _resolve_trusted_regular_file(
        trusted_root,
        manifest_path_value,
        label="unprioritized file-order manifest",
        require_relative=False,
    )
    manifest_sha256 = _require_sha256(
        expected_manifest_sha256,
        label="unprioritized file-order manifest SHA-256",
    )
    manifest_relative_path = manifest_path.relative_to(trusted_root).as_posix()
    payload, _ = _load_hashed_json_object(
        manifest_path,
        manifest_sha256,
        label="unprioritized file-order manifest",
        sha_label="unprioritized file-order manifest SHA-256",
    )
    if set(payload) != _UNPRIORITIZED_MANIFEST_KEYS:
        raise ValueError("unprioritized file-order manifest has an unexpected key set")
    if payload.get("schema_version") != _UNPRIORITIZED_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unprioritized file-order manifest must use schema_version=1")
    if payload.get("freeze_status") != "frozen":
        raise ValueError("unprioritized file-order manifest must be frozen")
    if payload.get("algorithm") != _UNPRIORITIZED_MANIFEST_ALGORITHM:
        raise ValueError(
            "unprioritized file-order manifest algorithm must be sha256-seed-path-v1"
        )
    benchmark_constant = str(payload.get("benchmark_constant", "") or "").strip()
    if not benchmark_constant:
        raise ValueError("unprioritized file-order manifest benchmark_constant is missing")
    raw_schedules = payload.get("schedules")
    if (
        not isinstance(raw_schedules, list)
        or len(raw_schedules) != _UNPRIORITIZED_MANIFEST_EXPECTED_ROWS
    ):
        raise ValueError("unprioritized file-order manifest must contain exactly 60 schedules")

    schedule_index: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    repo_schedule_index: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
    target_replicates: Dict[str, Set[int]] = {}
    target_identities: Dict[str, Tuple[str, str, str, str, str]] = {}
    repository_identity_replicates: Dict[Tuple[str, str], Set[int]] = {}
    seen_schedule_paths: Set[Path] = set()
    profile_cache: Dict[
        Path,
        Tuple[str, Dict[str, Any], Dict[str, Any]],
    ] = {}
    for row_number, raw_row in enumerate(raw_schedules, start=1):
        if not isinstance(raw_row, dict) or set(raw_row) != _UNPRIORITIZED_MANIFEST_ROW_KEYS:
            raise ValueError(f"schedule manifest row {row_number} has an unexpected key set")
        target_id = str(raw_row.get("target_id", "") or "").strip()
        target_commit = str(raw_row.get("target_commit", "") or "").strip()
        replicate = raw_row.get("replicate")
        if not target_id:
            raise ValueError(f"schedule manifest row {row_number} target_id is missing")
        if not re.fullmatch(r"[0-9a-f]{40}", target_commit):
            raise ValueError(
                f"schedule manifest row {row_number} target_commit must be a full lowercase commit"
            )
        if isinstance(replicate, bool) or not isinstance(replicate, int) or replicate < 1:
            raise ValueError(
                f"schedule manifest row {row_number} replicate must be a positive integer"
            )
        key = (target_id, target_commit, replicate)
        if key in schedule_index:
            raise ValueError(f"ambiguous duplicate schedule manifest key: {key}")

        schedule_relative_path = _normalize_manifest_relative_path(
            raw_row["path"],
            label=f"schedule manifest row {row_number} path",
        )
        schedule_path = _resolve_trusted_regular_file(
            trusted_root,
            schedule_relative_path,
            label=f"schedule manifest row {row_number} path",
        )
        if schedule_path in seen_schedule_paths:
            raise ValueError(
                "unprioritized file-order manifest reuses a schedule artifact path: "
                f"{schedule_relative_path}"
            )
        seen_schedule_paths.add(schedule_path)
        file_sha256 = _require_sha256(
            raw_row.get("file_sha256"),
            label=f"schedule manifest row {row_number} file_sha256",
        )
        schedule_payload, _ = _load_hashed_json_object(
            schedule_path,
            file_sha256,
            label=f"schedule manifest row {row_number} schedule",
            sha_label=f"schedule manifest row {row_number} file_sha256",
        )
        schedule = agent_scanner.validate_unprioritized_file_schedule_payload(
            schedule_payload,
            file_sha256,
            target_commit=target_commit,
            artifact_locator=schedule_relative_path,
        )
        provenance = schedule.get("provenance", {})
        if provenance.get("algorithm") != payload["algorithm"]:
            raise ValueError(f"schedule manifest row {row_number} algorithm mismatch")
        if provenance.get("benchmark_constant") != benchmark_constant:
            raise ValueError(f"schedule manifest row {row_number} benchmark_constant mismatch")
        if provenance.get("replicate") != str(replicate):
            raise ValueError(f"schedule manifest row {row_number} replicate mismatch")
        if provenance.get("universe_sha256") != _require_sha256(
            raw_row.get("universe_sha256"),
            label=f"schedule manifest row {row_number} universe_sha256",
        ):
            raise ValueError(f"schedule manifest row {row_number} universe_sha256 mismatch")
        if provenance.get("order_sha256") != _require_sha256(
            raw_row.get("order_sha256"),
            label=f"schedule manifest row {row_number} order_sha256",
        ):
            raise ValueError(f"schedule manifest row {row_number} order_sha256 mismatch")
        file_count = raw_row.get("file_count")
        if isinstance(file_count, bool) or not isinstance(file_count, int) or file_count < 1:
            raise ValueError(f"schedule manifest row {row_number} file_count is invalid")
        if file_count != len(schedule["files"]):
            raise ValueError(f"schedule manifest row {row_number} file_count mismatch")

        profile_path = _resolve_trusted_regular_file(
            trusted_root,
            raw_row["target_software_profile_path"],
            label=f"schedule manifest row {row_number} target software profile",
        )
        profile_sha256 = _require_sha256(
            raw_row.get("target_software_profile_sha256"),
            label=f"schedule manifest row {row_number} target_software_profile_sha256",
        )
        cached_profile = profile_cache.get(profile_path)
        if cached_profile is None:
            frozen_profile, actual_profile_sha256 = _load_hashed_json_object(
                profile_path,
                profile_sha256,
                label=f"schedule manifest row {row_number} target software profile",
                sha_label=(
                    f"schedule manifest row {row_number} "
                    "target_software_profile_sha256"
                ),
            )
            frozen_profile_contract = _frozen_profile_universe(frozen_profile)
            profile_cache[profile_path] = (
                actual_profile_sha256,
                frozen_profile,
                frozen_profile_contract,
            )
        else:
            actual_profile_sha256, frozen_profile, frozen_profile_contract = (
                cached_profile
            )
            if actual_profile_sha256 != profile_sha256:
                raise ValueError(
                    f"schedule manifest row {row_number} "
                    "target_software_profile_sha256 mismatch"
                )
        if frozen_profile_contract["target_commit"] != target_commit:
            raise ValueError(
                f"schedule manifest row {row_number} target profile commit mismatch"
            )
        if sorted(schedule["files"], key=lambda path: path.encode("utf-8")) != frozen_profile_contract["files"]:
            raise ValueError(
                f"schedule manifest row {row_number} universe does not match target software profile"
            )
        for field in (
            "overlap_path_count",
            "overlap_extra_membership_count",
            "multi_module_paths",
            "multi_module_paths_sha256",
        ):
            if raw_row.get(field) != frozen_profile_contract[field]:
                raise ValueError(f"schedule manifest row {row_number} {field} mismatch")

        profile_relative_path = _normalize_manifest_relative_path(
            raw_row["target_software_profile_path"],
            label=f"schedule manifest row {row_number} target software profile",
        )
        target_identity = (
            frozen_profile_contract["target_repo_name"],
            target_commit,
            profile_relative_path,
            profile_sha256,
            str(provenance["universe_sha256"]),
        )
        existing_target_identity = target_identities.setdefault(
            target_id,
            target_identity,
        )
        if existing_target_identity != target_identity:
            raise ValueError(
                "unprioritized file-order manifest target identity changes across "
                f"replicates: {target_id}"
            )
        repository_identity_replicates.setdefault(
            (frozen_profile_contract["target_repo_name"], target_commit),
            set(),
        ).add(replicate)

        schedule = {
            "files": list(schedule["files"]),
            "provenance": {
                **{
                    key: value
                    for key, value in dict(provenance).items()
                    if key != "artifact_path"
                },
                "artifact_path": schedule_relative_path,
                "manifest_path": manifest_relative_path,
                "manifest_sha256": manifest_sha256,
                "manifest_target_id": target_id,
                "manifest_target_repo_name": frozen_profile_contract[
                    "target_repo_name"
                ],
                "manifest_target_commit": target_commit,
                "manifest_replicate": replicate,
                "target_software_profile_path": profile_relative_path,
                "target_software_profile_sha256": profile_sha256,
                "overlap_path_count": frozen_profile_contract["overlap_path_count"],
                "overlap_extra_membership_count": frozen_profile_contract[
                    "overlap_extra_membership_count"
                ],
                "multi_module_paths_sha256": frozen_profile_contract[
                    "multi_module_paths_sha256"
                ],
            },
        }
        schedule_index[key] = schedule
        repo_key = (
            frozen_profile_contract["target_repo_name"],
            target_commit,
            replicate,
        )
        if repo_key in repo_schedule_index:
            raise ValueError(
                "ambiguous duplicate frozen repository schedule identity: "
                f"{repo_key}"
            )
        repo_schedule_index[repo_key] = schedule
        target_replicates.setdefault(target_id, set()).add(replicate)

    if len(target_replicates) != _UNPRIORITIZED_MANIFEST_EXPECTED_TARGETS:
        raise ValueError("unprioritized file-order manifest must contain exactly 20 targets")
    for target_id, replicates in target_replicates.items():
        if replicates != _UNPRIORITIZED_MANIFEST_EXPECTED_REPLICATES:
            raise ValueError(
                f"unprioritized file-order manifest target {target_id} must have replicates 1, 2, and 3"
            )
    if len(repository_identity_replicates) != _UNPRIORITIZED_MANIFEST_EXPECTED_TARGETS:
        raise ValueError(
            "unprioritized file-order manifest must contain exactly 20 unique "
            "repository/commit identities"
        )
    for repository_identity, replicates in repository_identity_replicates.items():
        if replicates != _UNPRIORITIZED_MANIFEST_EXPECTED_REPLICATES:
            raise ValueError(
                "unprioritized file-order manifest repository identity must have "
                f"replicates 1, 2, and 3: {repository_identity}"
            )
    return {
        "manifest_path": manifest_relative_path,
        "manifest_sha256": manifest_sha256,
        "algorithm": payload["algorithm"],
        "benchmark_constant": benchmark_constant,
        "schedule_index": schedule_index,
        "repo_schedule_index": repo_schedule_index,
    }


def resolve_batch_unprioritized_file_schedule(
    manifest: Mapping[str, Any],
    *,
    target_commit: str,
    replicate: int,
    target_id: Optional[str] = None,
    target_repo_name: Optional[str] = None,
    software_profile: Any = None,
    software_profile_path: Optional[str | Path] = None,
    software_profile_root: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """按规范 id 或唯一完整 commit 解析精确 schedule。"""
    normalized_target_id = str(target_id or "").strip()
    normalized_repo_name = str(target_repo_name or "").strip()
    normalized_commit = str(target_commit or "").strip()
    if not normalized_target_id and not normalized_repo_name:
        raise ValueError(
            "target_id or target_repo_name is required for unprioritized schedule resolution"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", normalized_commit):
        raise ValueError("target_commit must be a full lowercase commit")
    if isinstance(replicate, bool) or not isinstance(replicate, int) or replicate < 1:
        raise ValueError("replicate must be a positive integer")
    schedule_index = manifest.get("schedule_index")
    repo_schedule_index = manifest.get("repo_schedule_index")
    if not isinstance(schedule_index, Mapping) or not isinstance(
        repo_schedule_index, Mapping
    ):
        raise ValueError("validated unprioritized schedule manifest index is missing")
    keys = [candidate for candidate in schedule_index if isinstance(candidate, tuple)]
    schedule: Any = None
    if normalized_target_id:
        key = (normalized_target_id, normalized_commit, replicate)
        schedule = schedule_index.get(key)
    else:
        schedule = repo_schedule_index.get(
            (normalized_repo_name, normalized_commit, replicate)
        )

    if not isinstance(schedule, dict):
        if not normalized_target_id:
            repo_keys = [
                candidate
                for candidate in repo_schedule_index
                if isinstance(candidate, tuple)
            ]
            if any(candidate[0] == normalized_repo_name for candidate in repo_keys):
                if any(
                    candidate[0] == normalized_repo_name
                    and candidate[1] == normalized_commit
                    for candidate in repo_keys
                ):
                    raise ValueError(
                        "unprioritized schedule replicate is missing for exact repository/commit: "
                        f"{normalized_repo_name}@{normalized_commit} replicate={replicate}"
                    )
                raise ValueError(
                    "unprioritized schedule target commit mismatch for exact repository: "
                    f"{normalized_repo_name}@{normalized_commit}"
                )
            if any(candidate[1] == normalized_commit for candidate in repo_keys):
                raise ValueError(
                    "unprioritized schedule repository identity mismatch for exact full commit: "
                    f"{normalized_repo_name}@{normalized_commit}"
                )
            raise ValueError(
                f"unprioritized schedule repository is missing: {normalized_repo_name}"
            )
        if not any(candidate[0] == normalized_target_id for candidate in keys):
            raise ValueError(
                f"unprioritized schedule target is missing: {normalized_target_id}"
            )
        if any(
            candidate[0] == normalized_target_id and candidate[2] == replicate
            for candidate in keys
        ):
            raise ValueError(
                "unprioritized schedule target commit mismatch: "
                f"{normalized_target_id}@{normalized_commit}"
            )
        raise ValueError(
            "unprioritized schedule replicate is missing: "
            f"{normalized_target_id}@{normalized_commit} replicate={replicate}"
        )
    resolved = {
        "files": list(schedule.get("files", [])),
        "provenance": {
            **dict(schedule.get("provenance", {})),
            "batch_target_repo_name": normalized_repo_name or None,
            "batch_target_commit": normalized_commit,
        },
    }
    frozen_repo_name = str(
        resolved["provenance"].get("manifest_target_repo_name", "") or ""
    )
    if normalized_repo_name and frozen_repo_name != normalized_repo_name:
        raise ValueError(
            "runtime repository name does not exactly match the frozen target profile identity"
        )
    has_profile_path = software_profile_path is not None
    has_profile_root = software_profile_root is not None
    if has_profile_path != has_profile_root:
        raise ValueError(
            "runtime software_profile_path and software_profile_root must be provided together"
        )
    if normalized_repo_name and software_profile is not None and not has_profile_path:
        raise ValueError(
            "batch repository schedule binding requires the exact runtime software profile path"
        )
    if has_profile_path and software_profile is None:
        raise ValueError(
            "runtime software profile path requires the in-memory ProfileRef profile object"
        )
    if has_profile_path and has_profile_root:
        runtime_profile_root = _resolve_trusted_root(
            software_profile_root,
            label="runtime software-profile root",
        )
        runtime_profile_path = _resolve_trusted_regular_file(
            runtime_profile_root,
            software_profile_path,
            label="runtime target software profile",
            require_relative=False,
        )
        expected_runtime_relative = _normalize_manifest_relative_path(
            f"{normalized_repo_name}/{normalized_commit}/software_profile.json",
            label="expected runtime target software profile path",
        )
        runtime_relative = runtime_profile_path.relative_to(
            runtime_profile_root
        ).as_posix()
        if runtime_relative != expected_runtime_relative:
            raise ValueError(
                "runtime target software profile path does not match the exact "
                "repository/commit profile binding"
            )
        expected_profile_sha256 = _require_sha256(
            resolved["provenance"].get("target_software_profile_sha256"),
            label="frozen target software profile SHA-256",
        )
        runtime_profile_payload, _ = _load_hashed_json_object(
            runtime_profile_path,
            expected_profile_sha256,
            label="runtime target software profile",
            sha_label="runtime target software profile SHA-256",
        )
        runtime_profile_contract = _frozen_profile_universe(runtime_profile_payload)
        if (
            runtime_profile_contract["target_repo_name"] != normalized_repo_name
            or runtime_profile_contract["target_commit"] != normalized_commit
        ):
            raise ValueError(
                "runtime target software profile identity does not match the repository/commit binding"
            )
        if sorted(
            resolved["files"],
            key=lambda path: path.encode("utf-8"),
        ) != runtime_profile_contract["files"]:
            raise ValueError(
                "runtime target software profile universe does not match the frozen schedule"
            )
        caller_profile_payload = _normalize_runtime_software_profile(software_profile)
        if caller_profile_payload != runtime_profile_payload:
            raise ValueError(
                "runtime ProfileRef profile object does not exactly match its hash-bound bytes"
            )
        resolved["provenance"].update(
            {
                "runtime_software_profile_path": runtime_relative,
                "runtime_software_profile_sha256": expected_profile_sha256,
            }
        )
    if software_profile is not None:
        agent_scanner.validate_frozen_scan_controls(
            software_profile,
            None,
            resolved,
        )
    return resolved


def _sanitize_run_component(value: str) -> str:
    """Sanitize one run-id component for filesystem use."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip())
    return sanitized.strip("-") or "run"


def resolve_run_id(explicit_run_id: Optional[str]) -> str:
    """Resolve the logical batch run id.

    Args:
        explicit_run_id: Optional caller-provided run id.

    Returns:
        Stable run id string for this batch invocation.
    """
    if explicit_run_id and explicit_run_id.strip():
        return explicit_run_id.strip()
    return f"run-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"


def resolve_shared_public_memory_dir(scan_output_dir: str | Path, run_id: str) -> Path:
    """Resolve the run-scoped shared public memory root.

    Args:
        scan_output_dir: Batch scan output root.
        run_id: Logical batch run id.

    Returns:
        Absolute shared public memory directory.
    """
    base_dir = Path(scan_output_dir).expanduser()
    if not base_dir.is_absolute():
        base_dir = _path_config["repo_root"] / base_dir
    return base_dir / "_runs" / _sanitize_run_component(run_id) / "shared-public-memory"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Batch pipeline: ensure profiles, select similar latest repos by similarity threshold, "
            "and scan all vuln entries from vuln.json."
        )
    )
    parser.add_argument(
        "--vuln-json",
        type=str,
        default=str(_path_config["vuln_data_path"]),
        help="Path to vuln.json (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--source-repos-root",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Root directory of source repositories referenced by vuln.json (default: data/repos)",
    )
    parser.add_argument(
        "--target-repos-root",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Root directory of target repositories to scan (default: data/repos)",
    )
    parser.add_argument(
        "--profile-base-path",
        type=str,
        default=str(_path_config["profile_base_path"]),
        help="Base directory containing profile folders (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--source-soft-profiles-dir",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help=(
            "Source software profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--target-soft-profiles-dir",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help=(
            "Target software profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--vuln-profiles-dir",
        type=str,
        default=DEFAULT_VULN_PROFILE_DIRNAME,
        help=(
            "Vulnerability profile directory name under --profile-base-path, "
            "or an absolute path"
        ),
    )
    parser.add_argument(
        "--scan-output-dir",
        type=str,
        default=str(_path_config["results_base_path"] / "scan-results-batch"),
        help="Base output directory for scan results (default: revision-root results)",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Optional batch run identifier used for run-scoped shared public memory",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.7,
        help="Minimum overall profile similarity to keep a target repo (default: 0.7)",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=None,
        help="Optional max number of targets to scan per vulnerability after threshold filtering",
    )
    parser.add_argument(
        "--min-threshold-hits",
        type=int,
        default=3,
        help=(
            "Minimum threshold hits required to keep threshold mode; fewer hits use "
            "--fallback-top-n from the full ranking (default: 3)"
        ),
    )
    parser.add_argument(
        "--fallback-top-n",
        type=int,
        default=5,
        help=(
            "If fewer than --min-threshold-hits repositories meet the threshold, scan "
            "the top-N repositories from the full ranking (default: 5)"
        ),
    )
    parser.add_argument(
        "--include-same-repo",
        action="store_true",
        help="Include same repository as source vulnerability during target selection",
    )
    parser.add_argument(
        "--scan-all-profiled-targets",
        action="store_true",
        help=(
            "Scan every target repository that already has a usable latest software profile, "
            "bypassing similarity ranking and threshold selection."
        ),
    )
    parser.add_argument(
        "--similarity-model-name",
        type=str,
        default=DEFAULT_EMBEDDING_MODEL_NAME,
        help="Embedding model name for text similarity",
    )
    parser.add_argument(
        "--similarity-device",
        type=str,
        default="cpu",
        help="Device used by similarity embedding model",
    )
    parser.add_argument(
        "--evaluation-mode",
        "--benchmark-mode",
        dest="evaluation_mode",
        action="store_true",
        help="Require embedding-backed similarity and fail closed if unavailable",
    )
    parser.add_argument(
        "--ablate-repo-semantics",
        action="store_true",
        help="Exclude repository semantic text from target ranking",
    )
    parser.add_argument(
        "--ablate-candidate-priority",
        "--ablate-repo-priority",
        dest="ablate_candidate_priority",
        action="store_true",
        help="Use a caller-supplied frozen global file schedule instead of candidate priority",
    )
    parser.add_argument(
        "--unprioritized-file-order-manifest",
        type=str,
        default=None,
        help=(
            "Frozen schedule manifest used by --ablate-candidate-priority; must be inside "
            "--unprioritized-file-order-root"
        ),
    )
    parser.add_argument(
        "--unprioritized-file-order-manifest-sha256",
        type=str,
        default=None,
        help="Required raw SHA-256 of --unprioritized-file-order-manifest",
    )
    parser.add_argument(
        "--unprioritized-file-order-root",
        type=str,
        default=None,
        help="Absolute trusted root containing the frozen schedule manifest and artifacts",
    )
    parser.add_argument(
        "--unprioritized-file-order-replicate",
        type=int,
        default=None,
        help="Required frozen schedule replicate selector for --ablate-candidate-priority",
    )
    parser.add_argument(
        "--ablate-memory",
        action="store_true",
        help="Disable shared/resume/LLM-facing memory; retain private coverage ledger",
    )
    parser.add_argument(
        "--ablate-verifier",
        action="store_true",
        help="Disable scanner claim-contract and same-type report gate",
    )
    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider used for profile generation and scanning (deepseek, openai, lab)",
    )
    parser.add_argument(
        "--llm-name",
        type=str,
        default=None,
        help="Optional model name override",
    )
    parser.add_argument(
        "--max-iterations-cap",
        type=int,
        default=10,
        help="Iteration cap used with critical-stop mode (default: 10)",
    )
    parser.add_argument(
        "--disable-critical-stop",
        action="store_true",
        help=(
            "Disable priority-1 completion aware stopping behavior."
        ),
    )
    parser.add_argument(
        "--critical-stop-mode",
        type=str,
        choices=["min", "max"],
        default="max",
        help=(
            "When critical stop is enabled: "
            "min => stop at min(max-iterations-cap, X); "
            "max => stop at max(max-iterations-cap, X). Default: max"
        ),
    )
    parser.add_argument(
        "--critical-stop-max-priority",
        type=int,
        choices=[1, 2],
        default=2,
        help=(
            "Highest module priority included in critical-stop completion checks. "
            "1 => affected only; 2 => affected + related. Default: 2"
        ),
    )
    parser.add_argument(
        "--require-full-universe-completion",
        action="store_true",
        help=(
            "Require every item in each frozen host universe to be durably completed; "
            "--max-iterations-cap remains an independent safety ceiling"
        ),
    )
    parser.add_argument(
        "--force-regenerate-profiles",
        action="store_true",
        help="Regenerate software/vulnerability profiles even when cached profile files exist",
    )
    parser.add_argument(
        "--reuse-existing-profiles-without-validation",
        action="store_true",
        help=(
            "Reuse persisted software/vulnerability profiles without fingerprint validation "
            "or regeneration. Intended for scan-only continuation runs."
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        help="Maximum worker count for scan stage (default: 1)",
    )
    parser.add_argument(
        "--scan-workers",
        type=int,
        default=None,
        help=(
            "Worker count for target scan stage; if omitted, inherits --max-workers "
            "(default: inherit)"
        ),
    )
    parser.add_argument(
        "--target-scan-timeout",
        type=int,
        default=7200,
        help=(
            "Maximum seconds to wait for one vulnerability's target scan wave to make "
            "progress before marking unfinished targets incomplete (default: 7200)"
        ),
    )
    parser.add_argument(
        "--skip-existing-scans",
        action="store_true",
        help=(
            "Skip target scan only when existing agentic_vuln_findings.json has "
            "complete coverage metadata and a matching fingerprint"
        ),
    )
    parser.add_argument(
        "--scan-output-commit-manifest",
        type=str,
        default=None,
        help="续跑时使用的 scanner 终态绑定清单",
    )
    parser.add_argument(
        "--scan-output-commit-manifest-sha256",
        type=str,
        default=None,
        help="终态绑定清单的外部 SHA-256",
    )
    parser.add_argument(
        "--skip-any-existing-scan-result",
        action="store_true",
        help=(
            "When --skip-existing-scans is set, skip any target folder that already "
            "has agentic_vuln_findings.json, without validating fingerprint or "
            "coverage. Partial scan_memory.json-only folders are resumed."
        ),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of concurrent target scans per vulnerability (default: 1)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit on number of vuln entries from vuln.json",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logs")
    return parser.parse_args()


def _validate_args(args: argparse.Namespace) -> bool:
    max_workers = getattr(args, "max_workers", 1)
    scan_workers = getattr(args, "scan_workers", None)
    if bool(getattr(args, "evaluation_mode", False)):
        logger.error(
            "batch evaluation mode is unavailable until every target has a "
            "complete externally bound evaluation control bundle; use agent-scanner"
        )
        return False
    if not (0.0 <= args.similarity_threshold <= 1.0):
        logger.error("--similarity-threshold must be between 0 and 1")
        return False
    if args.max_targets is not None and args.max_targets <= 0:
        logger.error("--max-targets must be >= 1 when provided")
        return False
    if max_workers <= 0:
        logger.error("--max-workers must be >= 1")
        return False
    if scan_workers is not None and scan_workers <= 0:
        logger.error("--scan-workers must be >= 1")
        return False
    if getattr(args, "min_threshold_hits", 3) <= 0:
        logger.error("--min-threshold-hits must be >= 1")
        return False
    if args.fallback_top_n <= 0:
        logger.error("--fallback-top-n must be >= 1")
        return False
    if args.max_iterations_cap <= 0:
        logger.error("--max-iterations-cap must be >= 1")
        return False
    if getattr(args, "target_scan_timeout", 7200) <= 0:
        logger.error("--target-scan-timeout must be >= 1")
        return False
    if getattr(args, "jobs", 1) <= 0:
        logger.error("--jobs must be >= 1")
        return False
    if args.limit is not None and args.limit < 0:
        logger.error("--limit must be >= 0 when provided")
        return False
    if not str(args.source_soft_profiles_dir).strip():
        logger.error("--source-soft-profiles-dir must not be empty")
        return False
    if not str(args.target_soft_profiles_dir).strip():
        logger.error("--target-soft-profiles-dir must not be empty")
        return False
    if not str(args.vuln_profiles_dir).strip():
        logger.error("--vuln-profiles-dir must not be empty")
        return False
    candidate_priority_ablation = bool(
        getattr(args, "ablate_candidate_priority", False)
    )
    schedule_manifest = str(
        getattr(args, "unprioritized_file_order_manifest", "") or ""
    ).strip()
    schedule_manifest_sha256 = str(
        getattr(args, "unprioritized_file_order_manifest_sha256", "") or ""
    ).strip()
    schedule_root = str(
        getattr(args, "unprioritized_file_order_root", "") or ""
    ).strip()
    schedule_replicate = getattr(args, "unprioritized_file_order_replicate", None)
    if candidate_priority_ablation:
        if (
            not schedule_manifest
            or not schedule_manifest_sha256
            or not schedule_root
            or schedule_replicate is None
        ):
            logger.error(
                "--ablate-candidate-priority requires "
                "--unprioritized-file-order-manifest, "
                "--unprioritized-file-order-manifest-sha256, "
                "--unprioritized-file-order-root, and --unprioritized-file-order-replicate"
            )
            return False
        if not re.fullmatch(r"[0-9a-f]{64}", schedule_manifest_sha256):
            logger.error(
                "--unprioritized-file-order-manifest-sha256 must be a lowercase SHA-256 digest"
            )
            return False
        if (
            isinstance(schedule_replicate, bool)
            or not isinstance(schedule_replicate, int)
            or schedule_replicate < 1
        ):
            logger.error("--unprioritized-file-order-replicate must be >= 1")
            return False
    elif (
        schedule_manifest
        or schedule_manifest_sha256
        or schedule_root
        or schedule_replicate is not None
    ):
        logger.error(
            "unprioritized file-order controls require --ablate-candidate-priority"
        )
        return False
    commit_manifest = str(
        getattr(args, "scan_output_commit_manifest", "") or ""
    ).strip()
    commit_manifest_sha256 = str(
        getattr(args, "scan_output_commit_manifest_sha256", "") or ""
    ).strip()
    if bool(commit_manifest) != bool(commit_manifest_sha256):
        logger.error(
            "--scan-output-commit-manifest and "
            "--scan-output-commit-manifest-sha256 must be provided together"
        )
        return False
    if commit_manifest and not bool(getattr(args, "skip_existing_scans", False)):
        logger.error("scan output commit manifest requires --skip-existing-scans")
        return False
    if commit_manifest_sha256 and not re.fullmatch(
        r"[0-9a-f]{64}", commit_manifest_sha256
    ):
        logger.error(
            "--scan-output-commit-manifest-sha256 must be a lowercase SHA-256 digest"
        )
        return False
    if bool(getattr(args, "skip_any_existing_scan_result", False)) and (
        bool(getattr(args, "evaluation_mode", False))
        or candidate_priority_ablation
    ):
        logger.error(
            "--skip-any-existing-scan-result cannot be used for evaluation or "
            "candidate-priority ablation because it bypasses scan-fingerprint validation"
        )
        return False
    return True


def _resolve_scan_workers(args: argparse.Namespace) -> int:
    """Resolve scan worker count with default inheritance from --max-workers."""
    raw_scan_workers = getattr(args, "scan_workers", None)
    scan_workers = to_int(raw_scan_workers)
    max_workers = max(1, to_int(getattr(args, "max_workers", 1)))
    if raw_scan_workers is None:
        if max_workers != 1:
            return max_workers
        return max(1, to_int(getattr(args, "jobs", 1)))
    return max(1, scan_workers)


def _resolve_source_software_profile_dir_from_args(args: argparse.Namespace) -> Path:
    return resolve_profile_dirs(
        profile_base_path=args.profile_base_path,
        software_profile_dirname=args.source_soft_profiles_dir,
        vuln_profile_dirname=None,
    )[0]


def _resolve_target_and_vuln_profile_dirs_from_args(args: argparse.Namespace) -> tuple[Path, Path]:
    return resolve_profile_dirs(
        profile_base_path=args.profile_base_path,
        software_profile_dirname=args.target_soft_profiles_dir,
        vuln_profile_dirname=args.vuln_profiles_dir,
    )


def _resolve_batch_scan_paths(args: argparse.Namespace) -> Optional[BatchScanPaths]:
    """Resolve and validate batch-scan paths from CLI args."""
    target_repo_profiles_dir, vuln_profiles_dir = _resolve_target_and_vuln_profile_dirs_from_args(args)
    repo_root = _path_config["repo_root"]
    paths = BatchScanPaths(
        vuln_json=resolve_cli_path(args.vuln_json, base_dir=repo_root),
        source_repos_root=resolve_cli_path(args.source_repos_root, base_dir=repo_root),
        target_repos_root=resolve_cli_path(args.target_repos_root, base_dir=repo_root),
        source_repo_profiles_dir=_resolve_source_software_profile_dir_from_args(args),
        target_repo_profiles_dir=target_repo_profiles_dir,
        vuln_profiles_dir=vuln_profiles_dir,
        scan_output_dir=resolve_cli_path(args.scan_output_dir, base_dir=repo_root),
    )
    if not paths.vuln_json.is_file():
        logger.error(f"vuln.json not found or is not a file: {paths.vuln_json}")
        return None
    if not paths.target_repos_root.is_dir():
        logger.error(f"target repos root not found or is not a directory: {paths.target_repos_root}")
        return None
    if paths.scan_output_dir.exists() and not paths.scan_output_dir.is_dir():
        logger.error(f"scan output dir exists but is not a directory: {paths.scan_output_dir}")
        return None
    return paths


def _ensure_source_inputs_available(
    *,
    args: argparse.Namespace,
    paths: BatchScanPaths,
    entries: Sequence[Tuple[int, Dict[str, object]]],
) -> bool:
    """Validate source-root access or cached profile availability."""
    if paths.source_repos_root.exists() and not paths.source_repos_root.is_dir():
        logger.error(
            "source repos root exists but is not a directory: %s",
            paths.source_repos_root,
        )
        return False
    if paths.source_repos_root.exists():
        return True
    if args.force_regenerate_profiles:
        logger.error(
            "source repos root not found for forced regeneration: %s",
            paths.source_repos_root,
        )
        return False

    missing_cached_inputs = _find_missing_cached_source_inputs(
        entries=entries,
        source_repo_profiles_dir=paths.source_repo_profiles_dir,
        vuln_profiles_dir=paths.vuln_profiles_dir,
    )
    if missing_cached_inputs:
        preview = ", ".join(missing_cached_inputs[:3])
        suffix = " ..." if len(missing_cached_inputs) > 3 else ""
        logger.error(
            "source repos root not found: %s; missing cached source/vulnerability profiles: %s%s",
            paths.source_repos_root,
            preview,
            suffix,
        )
        return False

    logger.warning(
        "source repos root not found: %s; reusing cached source/vulnerability profiles only",
        paths.source_repos_root,
    )
    return True


def _initialize_profile_caches(paths: BatchScanPaths) -> BatchScanCaches:
    """Build shared or independent source/target caches based on resolved paths."""
    target_software_cache: Dict[Tuple[str, str], object] = {}
    regenerated_target_software_keys: Set[Tuple[str, str]] = set()
    shared_source_target_profile_state = (
        _paths_resolve_equal(paths.source_repos_root, paths.target_repos_root)
        and _paths_resolve_equal(paths.source_repo_profiles_dir, paths.target_repo_profiles_dir)
    )
    if shared_source_target_profile_state:
        source_software_cache = target_software_cache
        regenerated_source_software_keys = regenerated_target_software_keys
    else:
        source_software_cache = {}
        regenerated_source_software_keys = set()

    return BatchScanCaches(
        source_software_cache=source_software_cache,
        target_software_cache=target_software_cache,
        vulnerability_cache={},
        regenerated_source_software_keys=regenerated_source_software_keys,
        regenerated_target_software_keys=regenerated_target_software_keys,
    )


def _build_batch_summary(args: argparse.Namespace, paths: BatchScanPaths) -> Dict[str, object]:
    """Build the batch summary document header."""
    return {
        "started_at": datetime.now().isoformat(),
        "run_id": getattr(args, "run_id", None),
        "shared_public_memory_dir": (
            None
            if getattr(args, "ablate_memory", False)
            else str(
                resolve_shared_public_memory_dir(
                    paths.scan_output_dir,
                    getattr(args, "run_id", None) or "run",
                )
            )
        ),
        "vuln_json": str(paths.vuln_json),
        "source_repos_root": str(paths.source_repos_root),
        "target_repos_root": str(paths.target_repos_root),
        "source_soft_profiles_dir": str(paths.source_repo_profiles_dir),
        "target_soft_profiles_dir": str(paths.target_repo_profiles_dir),
        "vuln_profiles_dir": str(paths.vuln_profiles_dir),
        "similarity_threshold": args.similarity_threshold,
        "max_targets": args.max_targets,
        "min_threshold_hits": getattr(args, "min_threshold_hits", 3),
        "fallback_top_n": args.fallback_top_n,
        "include_same_repo": args.include_same_repo,
        "limit": args.limit,
        "max_iterations_cap": args.max_iterations_cap,
        "critical_stop_enabled": not args.disable_critical_stop,
        "critical_stop_mode": args.critical_stop_mode,
        "critical_stop_max_priority": getattr(args, "critical_stop_max_priority", 2),
        "require_full_universe_completion": bool(
            getattr(args, "require_full_universe_completion", False)
        ),
        "force_regenerate_profiles": args.force_regenerate_profiles,
        "reuse_existing_profiles_without_validation": getattr(
            args,
            "reuse_existing_profiles_without_validation",
            False,
        ),
        "skip_existing_scans": args.skip_existing_scans,
        "scan_output_commit_manifest": getattr(
            args, "validated_scan_output_commit_manifest", None
        ),
        "skip_any_existing_scan_result": getattr(args, "skip_any_existing_scan_result", False),
        "jobs": getattr(args, "jobs", 1),
        "llm_provider": args.llm_provider,
        "llm_name": args.llm_name,
        "evaluation_mode": bool(getattr(args, "evaluation_mode", False)),
        "unprioritized_file_order_manifest": getattr(
            args, "validated_unprioritized_file_order_manifest", None
        ),
        "unprioritized_file_order_replicate": getattr(
            args, "unprioritized_file_order_replicate", None
        ),
        "ablations": agent_scanner.ablation_config_from_args(args),
        "selection_similarity": getattr(args, "selection_similarity_provenance", None),
        "entries": [],
    }


def _write_batch_summary(summary: Dict[str, Any], scan_output_dir: Path) -> Path:
    """保存带时间戳的机器可读 batch 摘要。"""
    scan_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = scan_output_dir / (
        f"batch-summary-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
    )
    write_atomic_text(
        summary_path,
        json.dumps(summary, indent=2, ensure_ascii=False),
    )
    return summary_path


def _fsync_directory(path: Path) -> None:
    """持久化同目录内的发布与删除操作。"""
    directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_scan_output_commit_manifest(
    summary: Mapping[str, Any],
    summary_path: Path,
    *,
    summary_bytes: Optional[bytes] = None,
    manifest_path: Optional[Path] = None,
) -> Tuple[Path, str]:
    """导出下次续跑可外部绑定的终态清单。"""
    bindings = _validate_complete_batch_summary(summary)
    if summary_bytes is None:
        try:
            summary_bytes = summary_path.read_bytes()
        except OSError as exc:
            raise ValueError("batch summary is unavailable for binding") from exc
    if not isinstance(summary_bytes, bytes):
        raise ValueError("batch summary binding requires exact bytes")
    summary_sha256 = hashlib.sha256(summary_bytes).hexdigest()
    if _parse_json_object_bytes(
        summary_bytes,
        label="batch summary",
    ) != dict(summary):
        raise ValueError("batch summary bytes disagree with in-memory summary")
    manifest = {
        "schema_version": _SCAN_OUTPUT_COMMIT_MANIFEST_SCHEMA_VERSION,
        "kind": _SCAN_OUTPUT_COMMIT_MANIFEST_KIND,
        "batch_summary": {
            "path": summary_path.name,
            "sha256": summary_sha256,
        },
        "bindings": [bindings[key] for key in sorted(bindings)],
    }
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    final_manifest_path = manifest_path or summary_path.with_name(
        summary_path.name.replace(
            "batch-summary-", "scan-output-commit-bindings-", 1
        )
    )
    write_atomic_text(final_manifest_path, manifest_text)
    return (
        final_manifest_path,
        hashlib.sha256(manifest_text.encode("utf-8")).hexdigest(),
    )


def _build_scan_task_id(cve_id: str, candidate: SimilarProfileCandidate) -> str:
    """Build stable task id for one scan target."""
    return f"{cve_id}:{candidate.profile_ref.repo_name}:{candidate.profile_ref.commit_hash}"


def _run_target_scan_task(
    task: Dict[str, Any],
    *,
    batch_args: argparse.Namespace,
    target_repos_root: Path,
    repo_lock_manager: RepoPathLockManager,
) -> Dict[str, Any]:
    """Run one scan task via the execution module's process-level watchdog."""
    _ = target_repos_root
    _ = repo_lock_manager
    target = task["target"]
    task_id = str(task["task_id"])
    cve_id = str(task["cve_id"])
    vulnerability_profile = task["vulnerability_profile"]
    if create_llm_client is not _IMPORTED_CREATE_LLM_CLIENT:
        batch_scanner_execution_module.create_llm_client = create_llm_client
    if _run_target_scan is not _IMPORTED_RUN_TARGET_SCAN:
        batch_scanner_execution_module._run_target_scan = _run_target_scan
    execution_kwargs = {
        "batch_args": batch_args,
        "cve_id": cve_id,
        "vulnerability_profile": vulnerability_profile,
        "target": target,
    }
    unprioritized_file_schedule = task.get("unprioritized_file_schedule")
    if unprioritized_file_schedule is not None:
        execution_kwargs["unprioritized_file_schedule"] = unprioritized_file_schedule
    task_result = batch_scanner_execution_module._run_target_scan_task(**execution_kwargs)

    return {
        "task_id": task_id,
        "repo_name": target.profile_ref.repo_name,
        "commit_hash": target.profile_ref.commit_hash,
        "overall_similarity": target.metrics.overall_sim if target.metrics is not None else None,
        "similarity_computed": target.metrics is not None,
        **task_result,
    }


def _build_scan_tasks(
    cve_id: str,
    similar_targets: Sequence[SimilarProfileCandidate],
    vulnerability_profile: object,
    unprioritized_file_schedules: Optional[
        Mapping[Tuple[str, str], Dict[str, Any]]
    ] = None,
) -> List[Dict[str, Any]]:
    """Build deduplicated scan tasks for one vulnerability entry."""
    tasks: List[Dict[str, Any]] = []
    seen_task_ids: Set[str] = set()
    for candidate in similar_targets:
        task_id = _build_scan_task_id(cve_id, candidate)
        if task_id in seen_task_ids:
            continue
        seen_task_ids.add(task_id)
        task = {
            "task_id": task_id,
            "cve_id": cve_id,
            "vulnerability_profile": vulnerability_profile,
            "target": candidate,
        }
        if unprioritized_file_schedules is not None:
            schedule_key = (
                candidate.profile_ref.repo_name,
                candidate.profile_ref.commit_hash,
            )
            schedule = unprioritized_file_schedules.get(schedule_key)
            if schedule is None:
                raise ValueError(
                    "prevalidated unprioritized schedule is missing for "
                    f"{schedule_key[0]}@{schedule_key[1]}"
                )
            task["unprioritized_file_schedule"] = schedule
        tasks.append(task)
    return tasks


def _paths_resolve_equal(left: Path, right: Path) -> bool:
    """Compare paths after normalization so shared source/target inputs can reuse state."""
    return left.resolve() == right.resolve()


def _normalize_cve_id(entry: Dict[str, object], index: int) -> str:
    return normalize_cve_id(entry.get("cve_id"), index)


def _validated_vuln_entry_identity(
    entry: Mapping[str, object],
) -> Tuple[str, str, str]:
    """校验冻结输入的引用 ID、仓库名和完整提交。"""
    try:
        return (
            canonical_scan_repo_name(entry.get("repo_name")),
            canonical_scan_commit(entry.get("commit")),
            canonical_scan_reference_id(entry.get("cve_id")),
        )
    except ScanOutputCommitError as exc:
        raise ValueError(str(exc)) from exc


def _find_missing_cached_source_inputs(
    *,
    entries: Sequence[Tuple[int, Dict[str, object]]],
    source_repo_profiles_dir: Path,
    vuln_profiles_dir: Path,
) -> List[str]:
    """Return missing cached source profile artefacts required for source-root-free runs."""
    missing: List[str] = []
    seen: Set[str] = set()

    for vuln_index, entry in entries:
        try:
            repo_name, commit_hash, cve_id = (
                _validated_vuln_entry_identity(entry)
            )
        except ValueError:
            continue
        required_paths = [
            (
                source_repo_profiles_dir / repo_name / commit_hash / "software_profile.json",
                f"software profile {repo_name}@{commit_hash[:12]}",
            ),
            (
                vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json",
                f"vulnerability profile {repo_name}@{cve_id}",
            ),
        ]
        for path, label in required_paths:
            if path.exists() or label in seen:
                continue
            seen.add(label)
            missing.append(label)

    return missing


def _ensure_software_profile(
    *,
    repo_name: str,
    commit_hash: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    cache: Dict[Tuple[str, str], object],
    regenerated_keys: Set[Tuple[str, str]],
    reuse_existing_profiles_without_validation: bool = False,
) -> Optional[object]:
    key = (repo_name, commit_hash)
    if force_regenerate and key in regenerated_keys and key in cache:
        return cache[key]
    if key in cache and not force_regenerate:
        return cache[key]
    if force_regenerate:
        cache.pop(key, None)

    if not force_regenerate and reuse_existing_profiles_without_validation:
        cached_profile = load_software_profile(
            repo_name,
            commit_hash,
            base_dir=repo_profiles_dir,
        )
        if cached_profile:
            cache[key] = cached_profile
            return cached_profile
        logger.error(
            "Existing software profile required but not found: %s@%s",
            repo_name,
            commit_hash[:12],
        )
        return None

    repo_path = repos_root / repo_name
    if not repo_path.exists():
        # Cached-only batch runs can still reuse an already persisted profile even
        # when the original source repository is unavailable, but the cached
        # profile still has to pass the normal fingerprint validation.
        if not force_regenerate:
            cached_profile = _load_cached_software_profile_if_compatible(
                repo_name=repo_name,
                commit_hash=commit_hash,
                repo_profiles_dir=repo_profiles_dir,
                llm_client=llm_client,
            )
            if cached_profile:
                cache[key] = cached_profile
                return cached_profile
        logger.error(f"Repository not found for software profile generation: {repo_path}")
        return None

    if not force_regenerate and _is_git_worktree_root(repo_path) and has_uncommitted_changes(str(repo_path)):
        # Dirty worktrees cannot go through the profiler's clean-worktree guard,
        # but batch resume should still reuse only a fingerprint-compatible
        # persisted profile. When the dirty checkout is already on the target
        # commit, validate against the full repo-state-aware hash; otherwise
        # fall back to commit-scoped cached-only validation because the current
        # dirty tree is unrelated to the requested profile commit.
        current_commit = get_git_commit(str(repo_path))
        cached_profile = _load_cached_software_profile_if_compatible(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            repo_path=repo_path if current_commit == commit_hash else None,
        )
        if cached_profile:
            cache[key] = cached_profile
            return cached_profile
        logger.error(
            "Repository %s has local changes and no cached software profile is available for %s",
            repo_name,
            commit_hash[:12],
        )
        return None

    logger.info(f"[Profile] Ensuring software profile: {repo_name}@{commit_hash[:12]}")
    run_software_profile_generation(
        repo_path=repo_path,
        output_dir=repo_profiles_dir,
        llm_client=llm_client,
        force_regenerate=force_regenerate,
        target_version=commit_hash,
    )

    profile = load_software_profile(repo_name, commit_hash, base_dir=repo_profiles_dir)
    if profile:
        cache[key] = profile
        if force_regenerate:
            regenerated_keys.add(key)
    return profile


def _ensure_vulnerability_profile(
    *,
    vuln_index: int,
    repo_name: str,
    commit_hash: str,
    cve_id: str,
    repos_root: Path,
    repo_profiles_dir: Path,
    vuln_profiles_dir: Path,
    llm_client,
    force_regenerate: bool,
    software_cache: Dict[Tuple[str, str], object],
    regenerated_software_keys: Set[Tuple[str, str]],
    cache: Dict[Tuple[str, str, str], object],
    verbose: bool,
    vuln_json_path: Optional[str] = None,
    reuse_existing_profiles_without_validation: bool = False,
) -> Optional[object]:
    key = (repo_name, commit_hash, cve_id)
    if key in cache and not force_regenerate:
        return cache[key]
    if force_regenerate:
        cache.pop(key, None)

    repo_path = repos_root / repo_name
    cached_profile_path = vuln_profiles_dir / repo_name / cve_id / "vulnerability_profile.json"
    cached_profile = None
    if not force_regenerate and cached_profile_path.exists():
        cached_profile = load_vulnerability_profile(
            repo_name,
            cve_id,
            base_dir=vuln_profiles_dir,
        )

    if not repo_path.exists():
        source_profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            force_regenerate=force_regenerate,
            reuse_existing_profiles_without_validation=reuse_existing_profiles_without_validation,
            cache=software_cache,
            regenerated_keys=regenerated_software_keys,
        )
        if reuse_existing_profiles_without_validation and cached_profile and source_profile:
            cache[key] = cached_profile
            return cached_profile
        if (
            cached_profile
            and source_profile
            and _cached_vulnerability_profile_matches_missing_repo_inputs(
                cached_profile=cached_profile,
                source_profile=source_profile,
                repo_name=repo_name,
                commit_hash=commit_hash,
                cve_id=cve_id,
                vuln_index=vuln_index,
                vuln_json_path=vuln_json_path,
                llm_client=llm_client,
            )
        ):
            cache[key] = cached_profile
            return cached_profile
        logger.error(f"Repository not found for vulnerability profile generation: {repo_path}")
        return None

    source_profile = _ensure_software_profile(
        repo_name=repo_name,
        commit_hash=commit_hash,
        repos_root=repos_root,
        repo_profiles_dir=repo_profiles_dir,
        llm_client=llm_client,
        force_regenerate=force_regenerate,
        reuse_existing_profiles_without_validation=reuse_existing_profiles_without_validation,
        cache=software_cache,
        regenerated_keys=regenerated_software_keys,
    )
    if not source_profile:
        return None
    if reuse_existing_profiles_without_validation and cached_profile:
        cache[key] = cached_profile
        return cached_profile
    source_repo_dirty = False
    with hold_repo_lock(repo_path, purpose=f"vulnerability_profile_cache_probe:{cve_id}"):
        source_repo_dirty = _is_git_worktree_root(repo_path) and has_uncommitted_changes(str(repo_path))
        if source_repo_dirty and cached_profile:
            if _cached_vulnerability_profile_matches_current_inputs(
                cached_profile=cached_profile,
                source_profile=source_profile,
                repo_path=repo_path,
                repo_name=repo_name,
                commit_hash=commit_hash,
                cve_id=cve_id,
                vuln_index=vuln_index,
                vuln_json_path=vuln_json_path,
                llm_client=llm_client,
            ):
                logger.warning(
                    "Repository has local changes; reusing compatible cached vulnerability profile: %s@%s",
                    repo_name,
                    cve_id,
                )
                cache[key] = cached_profile
                return cached_profile
            logger.error(
                "Repository has local changes and cached vulnerability profile is stale: %s@%s",
                repo_name,
                cve_id,
            )
    if source_repo_dirty:
        logger.error(
            "Repository has local changes and no reusable vulnerability profile: %s@%s",
            repo_name,
            cve_id,
        )
        return None

    selected = read_vuln_data(
        vuln_index,
        verbose=verbose,
        vuln_json_path=vuln_json_path,
        repo_base_path=repos_root,
    )
    if not selected:
        logger.error(f"Failed to read vulnerability entry index={vuln_index}")
        return None
    vuln_data = selected[0]
    logger.info(f"[Profile] Ensuring vulnerability profile: {repo_name}@{cve_id}")
    run_vulnerability_profile_generation(
        repo_path=repo_path,
        output_dir=vuln_profiles_dir,
        llm_client=llm_client,
        repo_profile=source_profile,
        vuln_entry=build_vulnerability_entry(vuln_data),
        force_regenerate=force_regenerate,
    )

    profile = load_vulnerability_profile(repo_name, cve_id, base_dir=vuln_profiles_dir)
    if profile:
        cache[key] = profile
    return profile


def _discover_latest_repo_refs(
    *,
    repos_root: Path,
    repo_profiles_dir: Path,
    llm_client,
    force_regenerate_profiles: bool,
    software_cache: Dict[Tuple[str, str], object],
    regenerated_software_keys: Set[Tuple[str, str]],
) -> Dict[str, ProfileRef]:
    refs: Dict[str, ProfileRef] = {}
    for repo_dir in sorted(repos_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        with hold_repo_lock(repo_dir, purpose="discover_latest_repo_ref"):
            commit_hash = get_git_commit(str(repo_dir))
        if not commit_hash:
            logger.warning(f"Skip non-git or unreadable repo: {repo_name}")
            continue
        profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=repos_root,
            repo_profiles_dir=repo_profiles_dir,
            llm_client=llm_client,
            force_regenerate=force_regenerate_profiles,
            reuse_existing_profiles_without_validation=False,
            cache=software_cache,
            regenerated_keys=regenerated_software_keys,
        )
        if not profile:
            logger.warning(f"Skip repo without software profile: {repo_name}@{commit_hash[:12]}")
            continue
        refs[repo_name] = ProfileRef(
            repo_name=repo_name,
            commit_hash=commit_hash,
            profile=profile,
            profile_path=(
                repo_profiles_dir / repo_name / commit_hash / "software_profile.json"
            ),
        )
    return refs


def _discover_existing_profiled_repo_refs(
    *,
    repos_root: Path,
    repo_profiles_dir: Path,
) -> Dict[str, ProfileRef]:
    """Load the latest parseable persisted target software profile for each repo.

    This mode trusts already-generated target profiles and does not regenerate or
    validate them against the live repo checkout. Repos without a persisted profile
    are skipped.
    """
    loaded_refs = load_all_software_profiles(repo_profiles_dir)
    refs_by_repo: Dict[str, List[ProfileRef]] = {}
    for ref in loaded_refs:
        refs_by_repo.setdefault(ref.repo_name, []).append(ref)

    selected_refs: Dict[str, ProfileRef] = {}
    for repo_dir in sorted(repos_root.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        repo_refs = refs_by_repo.get(repo_name, [])
        if not repo_refs:
            resolved_commit = resolve_profile_commit(repo_profiles_dir, repo_name)
            if resolved_commit:
                reloaded_profile = load_software_profile(
                    repo_name,
                    resolved_commit,
                    base_dir=repo_profiles_dir,
                )
                if reloaded_profile is not None:
                    selected_refs[repo_name] = ProfileRef(
                        repo_name=repo_name,
                        commit_hash=resolved_commit,
                        profile=reloaded_profile,
                        profile_path=repo_profiles_dir / repo_name / resolved_commit / "software_profile.json",
                    )
                    continue
            logger.warning("Skip repo without persisted software profile: %s", repo_name)
            continue
        latest_ref: Optional[ProfileRef] = None
        latest_key: Tuple[int, str] = (-1, "")
        for ref in repo_refs:
            try:
                mtime_ns = ref.profile_path.stat().st_mtime_ns if ref.profile_path else -1
            except OSError:
                mtime_ns = -1
            candidate_key = (mtime_ns, ref.commit_hash)
            if latest_ref is None or candidate_key > latest_key:
                latest_ref = ref
                latest_key = candidate_key
        resolved_commit = resolve_profile_commit(repo_profiles_dir, repo_name)
        if resolved_commit and (latest_ref is None or resolved_commit != latest_ref.commit_hash):
            reloaded_profile = load_software_profile(
                repo_name,
                resolved_commit,
                base_dir=repo_profiles_dir,
            )
            if reloaded_profile is not None:
                selected_refs[repo_name] = ProfileRef(
                    repo_name=repo_name,
                    commit_hash=resolved_commit,
                    profile=reloaded_profile,
                    profile_path=repo_profiles_dir / repo_name / resolved_commit / "software_profile.json",
                )
                continue
        if latest_ref is not None:
            reloaded_profile = load_software_profile(
                latest_ref.repo_name,
                latest_ref.commit_hash,
                base_dir=repo_profiles_dir,
            )
            if reloaded_profile is not None:
                selected_refs[repo_name] = ProfileRef(
                    repo_name=latest_ref.repo_name,
                    commit_hash=latest_ref.commit_hash,
                    profile=reloaded_profile,
                    profile_path=latest_ref.profile_path,
                )
            else:
                selected_refs[repo_name] = latest_ref
    return selected_refs


def _rank_similar_candidates(
    *,
    source_ref: ProfileRef,
    candidate_refs: Sequence[ProfileRef],
    text_retriever,
    weights: Optional[Dict[str, float]] = None,
    require_embedding: bool = False,
    embedding_provenance: Optional[Dict[str, Any]] = None,
) -> List[SimilarProfileCandidate]:
    ranked: List[SimilarProfileCandidate] = []
    total_candidates = len(candidate_refs)
    for index, candidate in enumerate(candidate_refs, start=1):
        similarity_kwargs: Dict[str, Any] = {
            "source_profile": source_ref.profile,
            "target_profile": candidate.profile,
            "text_retriever": text_retriever,
        }
        if weights is not None:
            similarity_kwargs["weights"] = weights
        if require_embedding:
            similarity_kwargs["require_embedding"] = True
        if embedding_provenance is not None:
            similarity_kwargs["embedding_provenance"] = embedding_provenance
        try:
            metrics = compute_profile_similarity(**similarity_kwargs)
        except TypeError as exc:
            if require_embedding or "unexpected keyword argument" not in str(exc):
                raise
            similarity_kwargs.pop("require_embedding", None)
            similarity_kwargs.pop("embedding_provenance", None)
            metrics = compute_profile_similarity(**similarity_kwargs)
        ranked.append(SimilarProfileCandidate(profile_ref=candidate, metrics=metrics))
        if total_candidates > 10 and (index % 10 == 0 or index == total_candidates):
            logger.info(
                "Similarity ranking progress: %s/%s candidates processed",
                index,
                total_candidates,
            )

    ranked.sort(
        key=lambda item: (
            item.metrics.overall_sim,
            item.metrics.module_dependency_import_sim,
            item.metrics.module_jaccard_sim,
        ),
        reverse=True,
    )
    return ranked


def _select_similar_targets(
    *,
    ranked_candidates: Sequence[SimilarProfileCandidate],
    similarity_threshold: float,
    max_targets: Optional[int],
    fallback_top_n: int,
    min_threshold_hits: int = 3,
) -> Tuple[List[SimilarProfileCandidate], bool]:
    """保留全部阈值命中；少于 min_threshold_hits 时才补充。

    结果稀疏时保留全部通过目标，并从完整排序补足至少 fallback_top_n 个。
    两种模式都受 max_targets 硬上限约束。
    """
    passed = [
        candidate
        for candidate in ranked_candidates
        if candidate.metrics.overall_sim >= similarity_threshold
    ]
    hard_limit = min(
        len(ranked_candidates),
        max_targets if max_targets is not None else len(ranked_candidates),
    )
    if len(passed) >= min_threshold_hits:
        return list(passed[:hard_limit]), False

    fallback_limit = min(max(fallback_top_n, len(passed)), hard_limit)
    return list(ranked_candidates[:fallback_limit]), True


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    if not _validate_args(args):
        return 1

    args.scan_output_commit_hashes = {}
    commit_manifest_path = str(
        getattr(args, "scan_output_commit_manifest", "") or ""
    ).strip()
    if commit_manifest_path:
        try:
            commit_manifest = load_scan_output_commit_manifest(
                commit_manifest_path,
                args.scan_output_commit_manifest_sha256,
            )
            args.scan_output_commit_hashes = commit_manifest["bindings"]
            args.validated_scan_output_commit_manifest = {
                "path": commit_manifest["manifest_path"],
                "sha256": commit_manifest["manifest_sha256"],
                "binding_count": len(commit_manifest["bindings"]),
            }
        except (OSError, ValueError) as exc:
            logger.error("Scanner terminal binding manifest validation failed: %s", exc)
            return 1

    unprioritized_schedule_manifest: Optional[Dict[str, Any]] = None
    if bool(getattr(args, "ablate_candidate_priority", False)):
        try:
            unprioritized_schedule_manifest = load_batch_unprioritized_schedule_manifest(
                args.unprioritized_file_order_manifest,
                args.unprioritized_file_order_manifest_sha256,
                args.unprioritized_file_order_root,
            )
            args.validated_unprioritized_file_order_manifest = {
                "path": unprioritized_schedule_manifest["manifest_path"],
                "sha256": unprioritized_schedule_manifest["manifest_sha256"],
            }
        except (OSError, ValueError) as exc:
            logger.error("Frozen batch schedule manifest validation failed: %s", exc)
            return 1

    paths = _resolve_batch_scan_paths(args)
    if paths is None:
        return 1
    args.scan_output_dir = str(paths.scan_output_dir)
    args.run_id = resolve_run_id(getattr(args, "run_id", None))
    ablations = agent_scanner.ablation_config_from_args(args)
    args.shared_public_memory_dir = (
        None
        if ablations["memory"]
        else str(resolve_shared_public_memory_dir(paths.scan_output_dir, args.run_id))
    )

    try:
        entries = _load_vuln_entries(paths.vuln_json, limit=args.limit)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        failure_summary = _build_batch_summary(args, paths)
        failure_summary.update(
            {
                "finished_at": datetime.now().isoformat(),
                "total_scans": 0,
                "status": "failed",
                "partial": False,
                "termination": "invalid_frozen_input",
                "failure_reason": f"invalid vuln.json: {exc}",
            }
        )
        _write_batch_summary(failure_summary, paths.scan_output_dir)
        logger.error("Invalid frozen vulnerability input: %s", exc)
        return 1
    if not entries:
        logger.warning("No vulnerability entries found")
        empty_summary = _build_batch_summary(args, paths)
        empty_summary.update(
            {
                "finished_at": datetime.now().isoformat(),
                "total_scans": 0,
                "status": "failed",
                "partial": False,
                "termination": "batch_finished",
                "failure_reason": "no vulnerability entries; no target scans were scheduled",
            }
        )
        _write_batch_summary(empty_summary, paths.scan_output_dir)
        return 1

    invalid_input_records = []
    for vuln_index, entry in entries:
        try:
            _validated_vuln_entry_identity(entry)
        except ValueError as exc:
            invalid_input_records.append(
                {
                    "index": vuln_index,
                    "repo_name": entry.get("repo_name"),
                    "commit_hash": entry.get("commit"),
                    "cve_id": entry.get("cve_id"),
                    "status": "failed_invalid_input",
                    "failure_reason": str(exc),
                    "selected_targets": [],
                    "scan_results": [],
                }
            )
    if invalid_input_records:
        failure_summary = _build_batch_summary(args, paths)
        failure_summary.update(
            {
                "finished_at": datetime.now().isoformat(),
                "total_scans": 0,
                "invalid_vuln_entries": len(invalid_input_records),
                "status": "failed",
                "partial": False,
                "termination": "invalid_frozen_input",
                "failure_reason": (
                    f"invalid_vuln_entries={len(invalid_input_records)}"
                ),
                "entries": invalid_input_records,
            }
        )
        _write_batch_summary(failure_summary, paths.scan_output_dir)
        logger.error(
            "Frozen vulnerability input contains %s invalid entries",
            len(invalid_input_records),
        )
        return 1

    if not _ensure_source_inputs_available(args=args, paths=paths, entries=entries):
        return 1

    logger.info(f"Loaded {len(entries)} vulnerabilities from {paths.vuln_json}")
    logger.info("Batch run ID: %s", args.run_id)
    profile_llm = create_profile_llm_client(args.llm_provider, args.llm_name)
    scan_all_profiled_targets = bool(getattr(args, "scan_all_profiled_targets", False))
    evaluation_mode = bool(getattr(args, "evaluation_mode", False))
    embedding_provenance: Dict[str, Any] = {}
    ranking_weights: Optional[Dict[str, float]] = None
    text_retriever = None
    if scan_all_profiled_targets:
        embedding_provenance.update(
            {
                "backend": None,
                "model": args.similarity_model_name,
                "required": False,
                "fallback_used": False,
                "fallback_reason": None,
                "disabled_reason": "scan_all_profiled_targets",
            }
        )
    elif ablations["repo_semantics"]:
        signature = embedding_model_artifact_signature(args.similarity_model_name)
        artifact_hash = str(signature.get("artifact_hash", "") or "").strip()
        embedding_provenance.update(
            {
                "backend": None,
                "model": args.similarity_model_name,
                "revision": artifact_hash or None,
                "revision_source": signature.get("fingerprint_type") if artifact_hash else None,
                "resolved_model_path": signature.get("resolved_model_path") or None,
                "device": args.similarity_device,
                "required": False,
                "fallback_used": False,
                "fallback_reason": None,
                "disabled_reason": "repo_semantics_ablation",
            }
        )
        ranking_weights = agent_scanner.REPO_STRUCTURE_ONLY_WEIGHTS
    else:
        try:
            text_retriever = build_text_retriever(
                model_name=args.similarity_model_name,
                device=args.similarity_device,
                require_embedding=evaluation_mode,
                provenance=embedding_provenance,
            )
        except TypeError as exc:
            if evaluation_mode or "unexpected keyword argument" not in str(exc):
                raise
            text_retriever = build_text_retriever(
                model_name=args.similarity_model_name,
                device=args.similarity_device,
            )
            signature = embedding_model_artifact_signature(args.similarity_model_name)
            artifact_hash = str(signature.get("artifact_hash", "") or "").strip()
            embedding_provenance.update(
                {
                    "backend": getattr(text_retriever, "backend", None),
                    "model": args.similarity_model_name,
                    "revision": artifact_hash or None,
                    "revision_source": signature.get("fingerprint_type") if artifact_hash else None,
                    "resolved_model_path": signature.get("resolved_model_path") or None,
                    "device": args.similarity_device,
                    "required": False,
                    "fallback_used": text_retriever is None,
                    "fallback_reason": (
                        "embedding retriever unavailable; lexical fallback permitted"
                        if text_retriever is None
                        else None
                    ),
                }
            )
        except EmbeddingUnavailableError as exc:
            args.selection_similarity_provenance = {
                "embedding": dict(embedding_provenance),
                "evaluation_mode": evaluation_mode,
                "ablations": dict(ablations),
            }
            failure_summary = _build_batch_summary(args, paths)
            failure_summary.update(
                {
                    "finished_at": datetime.now().isoformat(),
                    "status": "failed",
                    "partial": False,
                    "termination": "embedding_unavailable",
                    "failure_reason": f"{type(exc).__name__}: {exc}",
                }
            )
            paths.scan_output_dir.mkdir(parents=True, exist_ok=True)
            failure_path = paths.scan_output_dir / (
                f"batch-summary-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
            )
            write_atomic_text(
                failure_path,
                json.dumps(failure_summary, indent=2, ensure_ascii=False),
            )
            logger.error("Evaluation similarity setup failed closed: %s", exc)
            logger.error("Failure provenance saved to: %s", failure_path)
            return 1
    embedding_setup_provenance = dict(embedding_provenance)
    args.selection_similarity_provenance = {
        "embedding": dict(embedding_provenance),
        "evaluation_mode": evaluation_mode,
        "ablations": dict(ablations),
    }

    caches = _initialize_profile_caches(paths)

    if scan_all_profiled_targets:
        logger.info("Loading persisted software profiles for all target repositories...")
        latest_repo_refs = _discover_existing_profiled_repo_refs(
            repos_root=paths.target_repos_root,
            repo_profiles_dir=paths.target_repo_profiles_dir,
        )
        logger.info("Target repositories with persisted profiles: %s", len(latest_repo_refs))
    elif getattr(args, "reuse_existing_profiles_without_validation", False):
        logger.info(
            "Loading persisted software profiles for target similarity ranking without regeneration..."
        )
        latest_repo_refs = _discover_existing_profiled_repo_refs(
            repos_root=paths.target_repos_root,
            repo_profiles_dir=paths.target_repo_profiles_dir,
        )
        logger.info("Target repositories with persisted profiles: %s", len(latest_repo_refs))
    else:
        logger.info("Ensuring latest software profiles for candidate repositories...")
        latest_repo_refs = _discover_latest_repo_refs(
            repos_root=paths.target_repos_root,
            repo_profiles_dir=paths.target_repo_profiles_dir,
            llm_client=profile_llm,
            force_regenerate_profiles=args.force_regenerate_profiles,
            software_cache=caches.target_software_cache,
            regenerated_software_keys=caches.regenerated_target_software_keys,
        )
        logger.info(f"Candidate repositories with latest profiles: {len(latest_repo_refs)}")

    unprioritized_schedules_by_target: Optional[
        Dict[Tuple[str, str], Dict[str, Any]]
    ] = None
    if unprioritized_schedule_manifest is not None:
        unprioritized_schedules_by_target = {}
        replicate = args.unprioritized_file_order_replicate
        try:
            for profile_ref in latest_repo_refs.values():
                schedule = resolve_batch_unprioritized_file_schedule(
                    unprioritized_schedule_manifest,
                    target_repo_name=profile_ref.repo_name,
                    target_commit=profile_ref.commit_hash,
                    replicate=replicate,
                    software_profile=profile_ref.profile,
                    software_profile_path=profile_ref.profile_path,
                    software_profile_root=paths.target_repo_profiles_dir,
                )
                unprioritized_schedules_by_target[
                    (profile_ref.repo_name, profile_ref.commit_hash)
                ] = schedule
        except ValueError as exc:
            logger.error(
                "Frozen batch schedule target preflight failed before scan execution: %s",
                exc,
            )
            return 1
        logger.info(
            "Preflight validated frozen replicate %s schedules for %s target repositories",
            replicate,
            len(unprioritized_schedules_by_target),
        )
    scan_workers = _resolve_scan_workers(args)
    scan_task_lock_manager = RepoPathLockManager()

    # Keep local monkeypatches of _run_target_scan effective when tests or callers
    # replace the re-export on this module instead of the split execution module.
    if _run_target_scan is not _IMPORTED_RUN_TARGET_SCAN:
        batch_scanner_execution_module._run_target_scan = _run_target_scan

    summary = _build_batch_summary(args, paths)

    total_scans = 0
    success_scans = 0
    skipped_scans = 0
    incomplete_scans = 0
    failed_scans = 0
    failed_profile_generation = 0
    invalid_vuln_entries = 0
    zero_target_vulns = 0
    coverage_complete_scans = 0
    coverage_partial_scans = 0
    coverage_empty_scans = 0
    coverage_unknown_scans = 0

    for vuln_index, entry in entries:
        embedding_provenance = dict(embedding_setup_provenance)
        try:
            repo_name, commit_hash, cve_id = (
                _validated_vuln_entry_identity(entry)
            )
        except ValueError as exc:
            invalid_vuln_entries += 1
            reason = str(exc)
            logger.error("[%s] Malformed vuln entry: %s", vuln_index, reason)
            summary["entries"].append(
                {
                    "index": vuln_index,
                    "repo_name": entry.get("repo_name"),
                    "commit_hash": entry.get("commit"),
                    "cve_id": entry.get("cve_id"),
                    "status": "failed_invalid_input",
                    "failure_reason": reason,
                    "selected_targets": [],
                    "scan_results": [],
                }
            )
            continue

        logger.info("")
        logger.info("=" * 100)
        logger.info(f"[Vuln {vuln_index}] {repo_name}@{commit_hash[:12]} {cve_id}")
        logger.info("=" * 100)

        source_profile = _ensure_software_profile(
            repo_name=repo_name,
            commit_hash=commit_hash,
            repos_root=paths.source_repos_root,
            repo_profiles_dir=paths.source_repo_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            reuse_existing_profiles_without_validation=getattr(
                args,
                "reuse_existing_profiles_without_validation",
                False,
            ),
            cache=caches.source_software_cache,
            regenerated_keys=caches.regenerated_source_software_keys,
        )
        vulnerability_profile = _ensure_vulnerability_profile(
            vuln_index=vuln_index,
            repo_name=repo_name,
            commit_hash=commit_hash,
            cve_id=cve_id,
            repos_root=paths.source_repos_root,
            repo_profiles_dir=paths.source_repo_profiles_dir,
            vuln_profiles_dir=paths.vuln_profiles_dir,
            llm_client=profile_llm,
            force_regenerate=args.force_regenerate_profiles,
            reuse_existing_profiles_without_validation=getattr(
                args,
                "reuse_existing_profiles_without_validation",
                False,
            ),
            software_cache=caches.source_software_cache,
            regenerated_software_keys=caches.regenerated_source_software_keys,
            cache=caches.vulnerability_cache,
            verbose=args.verbose,
            vuln_json_path=str(paths.vuln_json),
        )

        if not source_profile or not vulnerability_profile:
            logger.error(f"[Vuln {vuln_index}] Missing required profiles, skip")
            failed_profile_generation += 1
            summary["entries"].append(
                {
                    "index": vuln_index,
                    "repo_name": repo_name,
                    "commit_hash": commit_hash,
                    "cve_id": cve_id,
                    "status": "failed_profile_generation",
                }
            )
            continue

        source_ref = ProfileRef(repo_name=repo_name, commit_hash=commit_hash, profile=source_profile)
        candidate_refs = list(latest_repo_refs.values())
        if not args.include_same_repo:
            # Batch auto-targeting should exclude same-repo candidates by repo identity
            # even when source and target roots come from different directories.
            candidate_refs = [
                ref
                for ref in candidate_refs
                if ref.repo_name != source_ref.repo_name
            ]
        fallback_used = False
        passed_threshold_count: Optional[int] = None
        supplemented_target_ids: List[str] = []
        selection_mode = "all_profiled" if scan_all_profiled_targets else "threshold"
        if scan_all_profiled_targets:
            similar_targets = [
                SimilarProfileCandidate(
                    profile_ref=ref,
                    metrics=None,
                )
                for ref in candidate_refs
            ]
            logger.info(
                "[Vuln %s] Selected all profiled targets: %s repositories",
                vuln_index,
                len(similar_targets),
            )
        else:
            logger.info(
                "[Vuln %s] Ranking similarity against %s candidate repositories",
                vuln_index,
                len(candidate_refs),
            )
            try:
                ranked_candidates = _rank_similar_candidates(
                    source_ref=source_ref,
                    candidate_refs=candidate_refs,
                    text_retriever=text_retriever,
                    weights=ranking_weights,
                    require_embedding=evaluation_mode and not ablations["repo_semantics"],
                    embedding_provenance=embedding_provenance,
                )
            except TypeError as exc:
                if (
                    evaluation_mode
                    or ranking_weights is not None
                    or "unexpected keyword argument" not in str(exc)
                ):
                    raise
                ranked_candidates = _rank_similar_candidates(
                    source_ref=source_ref,
                    candidate_refs=candidate_refs,
                    text_retriever=text_retriever,
                )
            except EmbeddingUnavailableError as exc:
                args.selection_similarity_provenance = {
                    "embedding": dict(embedding_provenance),
                    "evaluation_mode": evaluation_mode,
                    "ablations": dict(ablations),
                }
                summary["selection_similarity"] = args.selection_similarity_provenance
                summary["entries"].append(
                    {
                        "index": vuln_index,
                        "repo_name": repo_name,
                        "commit_hash": commit_hash,
                        "cve_id": cve_id,
                        "status": "failed_similarity",
                        "failure_reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                summary.update(
                    {
                        "finished_at": datetime.now().isoformat(),
                        "status": "failed",
                        "partial": False,
                        "termination": "embedding_unavailable",
                        "failure_reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                failure_path = _write_batch_summary(summary, paths.scan_output_dir)
                logger.error("Evaluation similarity failed closed: %s", exc)
                logger.error("Failure provenance saved to: %s", failure_path)
                return 1
            logger.info(
                "[Vuln %s] Similarity ranking completed for %s candidate repositories",
                vuln_index,
                len(ranked_candidates),
            )
            logger.info(f"[Vuln {vuln_index}] Similarity details ({len(ranked_candidates)} candidates):")
            for i, candidate in enumerate(ranked_candidates, 1):
                metrics = candidate.metrics
                threshold_flag = "PASS" if metrics.overall_sim >= args.similarity_threshold else "BELOW"
                logger.info(
                    f"  {i}. {candidate.profile_ref.label} "
                    f"overall={metrics.overall_sim:.4f} [{threshold_flag}] "
                    f"(desc={metrics.description_sim:.4f}, apps={metrics.target_application_sim:.4f}, "
                    f"users={metrics.target_user_sim:.4f}, module={metrics.module_jaccard_sim:.4f}, "
                    f"dep/import={metrics.module_dependency_import_sim:.4f})"
                )
            passed_threshold_count = sum(
                1
                for candidate in ranked_candidates
                if candidate.metrics.overall_sim >= args.similarity_threshold
            )
            similar_targets, fallback_used = _select_similar_targets(
                ranked_candidates=ranked_candidates,
                similarity_threshold=args.similarity_threshold,
                max_targets=args.max_targets,
                fallback_top_n=args.fallback_top_n,
                min_threshold_hits=getattr(args, "min_threshold_hits", 3),
            )
            selection_mode = "fallback_top_n" if fallback_used else "threshold"
            passed_target_ids = {
                f"{candidate.profile_ref.repo_name}@{candidate.profile_ref.commit_hash}"
                for candidate in ranked_candidates
                if candidate.metrics.overall_sim >= args.similarity_threshold
            }
            supplemented_target_ids = [
                f"{candidate.profile_ref.repo_name}@{candidate.profile_ref.commit_hash}"
                for candidate in similar_targets
                if f"{candidate.profile_ref.repo_name}@{candidate.profile_ref.commit_hash}"
                not in passed_target_ids
            ]

            logger.info(
                f"[Vuln {vuln_index}] Selected {len(similar_targets)} targets "
                f"(threshold={args.similarity_threshold:.3f})"
            )
            if fallback_used:
                if passed_threshold_count == 0:
                    logger.warning(
                        f"[Vuln {vuln_index}] Fewer than {getattr(args, 'min_threshold_hits', 3)} targets reached threshold {args.similarity_threshold:.3f}; "
                        f"fallback to top-{args.fallback_top_n}"
                    )
                else:
                    logger.warning(
                        f"[Vuln {vuln_index}] Only {passed_threshold_count} targets reached threshold "
                        f"{args.similarity_threshold:.3f}; preserving threshold hits and supplementing to at least top-{args.fallback_top_n}"
                    )
            for i, candidate in enumerate(similar_targets, 1):
                logger.info(
                    f"  {i}. {candidate.profile_ref.label} overall={candidate.metrics.overall_sim:.4f} "
                    f"(module={candidate.metrics.module_jaccard_sim:.4f}, "
                    f"dep/import={candidate.metrics.module_dependency_import_sim:.4f})"
                )

        deduplicated_targets: List[SimilarProfileCandidate] = []
        seen_scan_task_ids: Set[str] = set()
        for candidate in similar_targets:
            task_id = _build_scan_task_id(cve_id, candidate)
            if task_id in seen_scan_task_ids:
                continue
            seen_scan_task_ids.add(task_id)
            deduplicated_targets.append(candidate)

        selection_details = {
            "similarity_threshold": args.similarity_threshold,
            "min_threshold_hits": getattr(args, "min_threshold_hits", 3),
            "fallback_top_n": args.fallback_top_n,
            "max_targets": args.max_targets,
            "passed_threshold_count": passed_threshold_count,
            "supplemented_target_ids": supplemented_target_ids,
            "selection_mode": selection_mode,
        }
        args.selection_similarity_provenance = {
            "embedding": dict(embedding_provenance),
            "evaluation_mode": evaluation_mode,
            "ablations": dict(ablations),
            "selection": selection_details,
        }
        summary["selection_similarity"] = {
            "embedding": dict(embedding_provenance),
            "evaluation_mode": evaluation_mode,
            "ablations": dict(ablations),
        }
        vuln_record = {
            "index": vuln_index,
            "repo_name": repo_name,
            "commit_hash": commit_hash,
            "cve_id": cve_id,
            "selection_mode": selection_mode,
            "passed_threshold_count": passed_threshold_count,
            "supplemented_target_ids": supplemented_target_ids,
            "selection": selection_details,
            "selection_similarity": dict(args.selection_similarity_provenance),
            "selected_targets": [candidate.to_dict() for candidate in deduplicated_targets],
            "scan_results": [],
        }

        scan_tasks = _build_scan_tasks(
            cve_id=cve_id,
            similar_targets=deduplicated_targets,
            vulnerability_profile=vulnerability_profile,
            unprioritized_file_schedules=unprioritized_schedules_by_target,
        )
        if not scan_tasks:
            zero_target_vulns += 1
            vuln_record["status"] = "failed_no_targets"
            vuln_record["failure_reason"] = (
                "no target scans were scheduled for this vulnerability"
            )
            summary["entries"].append(vuln_record)
            continue
        total_scans += len(scan_tasks)
        scan_results = run_thread_pool_tasks(
            tasks=scan_tasks,
            worker_fn=lambda task: _run_target_scan_task(
                task=task,
                batch_args=args,
                target_repos_root=paths.target_repos_root,
                repo_lock_manager=scan_task_lock_manager,
            ),
            max_workers=scan_workers,
        )

        for scan_result in scan_results:
            payload = scan_result.payload or {}
            if scan_result.status == "error":
                logger.error(
                    "Scan task failed: %s (%s)",
                    payload.get("task_id", "unknown"),
                    scan_result.error_message,
                )
            scan_status = (
                str(payload.get("status", "failed"))
                if scan_result.status == "success"
                else "failed"
            )
            marker_sha256 = str(
                payload.get("scan_output_commit_sha256", "") or ""
            ).strip()
            headline_eligible = bool(
                payload.get("headline_eligible", False)
            )
            skip_any_result = (
                scan_status == "skipped"
                and bool(getattr(args, "skip_any_existing_scan_result", False))
            )
            if skip_any_result:
                payload = dict(payload)
                payload["coverage_status"] = "unknown"
                payload["headline_eligible"] = False
                payload["scan_output_commit_sha256"] = None
                marker_sha256 = ""
                headline_eligible = False
            if (
                scan_status in {"ok", "skipped"}
                and not skip_any_result
                and (
                    not headline_eligible
                    or not re.fullmatch(r"[0-9a-f]{64}", marker_sha256)
                )
            ):
                scan_status = "failed"
                payload = dict(payload)
                payload["failure_reason"] = (
                    "scanner success lacks a complete externally bound terminal commit"
                )
            if scan_status == "ok":
                success_scans += 1
            elif scan_status == "skipped":
                skipped_scans += 1
            elif scan_status == "incomplete":
                incomplete_scans += 1
            else:
                failed_scans += 1

            coverage_status = str(payload.get("coverage_status", "unknown"))
            if coverage_status == "complete":
                coverage_complete_scans += 1
            elif coverage_status == "partial":
                coverage_partial_scans += 1
            elif coverage_status == "empty":
                coverage_empty_scans += 1
            else:
                coverage_unknown_scans += 1

            vuln_record["scan_results"].append(
                {
                    "repo_name": payload.get("repo_name", ""),
                    "commit_hash": payload.get("commit_hash", ""),
                    "overall_similarity": payload.get("overall_similarity"),
                    "similarity_computed": payload.get(
                        "similarity_computed",
                        payload.get("overall_similarity") is not None,
                    ),
                    "status": scan_status,
                    "coverage_status": coverage_status,
                    "critical_scope_present": payload.get("critical_scope_present"),
                    "critical_complete": payload.get("critical_complete"),
                    "critical_scope_total_files": payload.get("critical_scope_total_files"),
                    "critical_scope_completed_files": payload.get("critical_scope_completed_files"),
                    "full_universe_required": payload.get("full_universe_required"),
                    "full_universe_complete": payload.get("full_universe_complete"),
                    "full_universe_total_files": payload.get("full_universe_total_files"),
                    "full_universe_completed_files": payload.get("full_universe_completed_files"),
                    "scan_progress": payload.get("scan_progress"),
                    "failure_reason": payload.get("failure_reason") or scan_result.error_message,
                    "termination": payload.get("termination"),
                    "usage": payload.get("usage"),
                    "run_provenance": payload.get("run_provenance"),
                    "scan_output_commit_sha256": payload.get(
                        "scan_output_commit_sha256"
                    ),
                    "headline_eligible": bool(
                        payload.get("headline_eligible", False)
                    ),
                    "started_at": payload.get("started_at"),
                    "finished_at": payload.get("finished_at"),
                    "duration_seconds": payload.get("duration_seconds"),
                }
            )

        summary["entries"].append(vuln_record)

    summary["finished_at"] = datetime.now().isoformat()
    summary["total_scans"] = total_scans
    summary["successful_scans"] = success_scans
    summary["skipped_scans"] = skipped_scans
    summary["incomplete_scans"] = incomplete_scans
    summary["failed_profile_generation"] = failed_profile_generation
    summary["invalid_vuln_entries"] = invalid_vuln_entries
    summary["zero_target_vulnerabilities"] = zero_target_vulns
    summary["failed_scans"] = failed_scans
    summary["coverage_complete_scans"] = coverage_complete_scans
    summary["coverage_partial_scans"] = coverage_partial_scans
    summary["coverage_empty_scans"] = coverage_empty_scans
    summary["coverage_unknown_scans"] = coverage_unknown_scans

    zero_scan_failure = total_scans == 0
    has_failures = (
        failed_scans > 0
        or failed_profile_generation > 0
        or invalid_vuln_entries > 0
        or zero_target_vulns > 0
        or zero_scan_failure
    )
    has_partial = (
        incomplete_scans > 0
        or coverage_partial_scans > 0
        or coverage_empty_scans > 0
        or coverage_unknown_scans > 0
    )
    summary["status"] = "failed" if has_failures else ("partial" if has_partial else "complete")
    summary["partial"] = has_partial
    summary["termination"] = "batch_finished"
    status_reasons = []
    if zero_scan_failure:
        status_reasons.append("no target scans were scheduled")
    if failed_scans > 0 or failed_profile_generation > 0:
        status_reasons.append(
            f"failed_scans={failed_scans}, profile_failures={failed_profile_generation}"
        )
    if invalid_vuln_entries > 0:
        status_reasons.append(
            f"invalid_vuln_entries={invalid_vuln_entries}"
        )
    if zero_target_vulns > 0:
        status_reasons.append(
            f"zero_target_vulnerabilities={zero_target_vulns}"
        )
    if incomplete_scans > 0:
        status_reasons.append(f"incomplete_scans={incomplete_scans}")
    if coverage_partial_scans > 0:
        status_reasons.append(f"coverage_partial_scans={coverage_partial_scans}")
    if coverage_empty_scans > 0:
        status_reasons.append(f"coverage_empty_scans={coverage_empty_scans}")
    if coverage_unknown_scans > 0:
        status_reasons.append(f"coverage_unknown_scans={coverage_unknown_scans}")
    summary["failure_reason"] = "; ".join(status_reasons) or None
    if summary["status"] != "complete":
        summary_path = _write_batch_summary(
            summary,
            paths.scan_output_dir,
        )
        logger.info("Batch summary saved to: %s", summary_path)
        return 1
    paths.scan_output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = paths.scan_output_dir / (
        f"batch-summary-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}.json"
    )
    summary_text = json.dumps(
        summary,
        indent=2,
        ensure_ascii=False,
    )
    summary_bytes = summary_text.encode("utf-8")
    commit_manifest_path = summary_path.with_name(
        summary_path.name.replace(
            "batch-summary-", "scan-output-commit-bindings-", 1
        )
    )
    pending_summary_path = summary_path.with_name(
        f".{summary_path.name}.pending"
    )
    pending_manifest_path = commit_manifest_path.with_name(
        f".{commit_manifest_path.name}.pending"
    )
    try:
        write_atomic_text(pending_summary_path, summary_text)
        _fsync_directory(paths.scan_output_dir)
        _, commit_manifest_sha256 = _write_scan_output_commit_manifest(
            summary,
            summary_path,
            summary_bytes=summary_bytes,
            manifest_path=pending_manifest_path,
        )
        _fsync_directory(paths.scan_output_dir)
        os.replace(pending_summary_path, summary_path)
        _fsync_directory(paths.scan_output_dir)
        os.replace(pending_manifest_path, commit_manifest_path)
        _fsync_directory(paths.scan_output_dir)
    except (OSError, ValueError) as exc:
        for stale_path in (
            pending_summary_path,
            pending_manifest_path,
            commit_manifest_path,
            summary_path,
        ):
            try:
                stale_path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            _fsync_directory(paths.scan_output_dir)
        except OSError:
            pass
        logger.error(
            "Scanner terminal binding publication failed: %s",
            exc,
        )
        return 1

    logger.info(f"Batch summary saved to: {summary_path}")
    logger.info(
        "Scanner terminal binding manifest saved to: %s (sha256=%s)",
        commit_manifest_path,
        commit_manifest_sha256,
    )
    logger.info(
        "Finished: %s ok, %s skipped, %s incomplete, %s failed target scans, %s profile failures "
        "(coverage: %s complete, %s partial, %s empty, %s unknown; target scans total=%s)",
        success_scans,
        skipped_scans,
        incomplete_scans,
        failed_scans,
        failed_profile_generation,
        coverage_complete_scans,
        coverage_partial_scans,
        coverage_empty_scans,
        coverage_unknown_scans,
        total_scans,
    )
    # 终态、退出码和 failure_reason 均由同一汇总状态推导。
    return 0 if summary["status"] == "complete" else 1
if __name__ == "__main__":
    raise SystemExit(main())
