"""扫描终态输出的失败关闭提交记录。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from scanner.evaluation_contract import (
    EvaluationEvidenceUnavailableError,
    require_evaluation_response_identity_usage,
)


SCAN_FINDINGS_FILENAME = "agentic_vuln_findings.json"
SCAN_PROVENANCE_FILENAME = "run_provenance.json"
SCAN_CONVERSATION_FILENAME = "conversation_history.json"
SCAN_SIMILARITY_FILENAME = "target_similarity.json"
SCAN_MEMORY_FILENAME = "scan_memory.json"
SCAN_FINGERPRINT_FILENAME = "scan_fingerprint.json"
SCAN_OUTPUT_COMMIT_FILENAME = "scan_output_commit.json"
SCAN_RUN_STATE_FILENAME = "run_state.json"
SCAN_RUN_FAILURE_FILENAME = "run_failure.json"
SCAN_OUTPUT_COMMIT_SCHEMA_VERSION = 2

_REQUIRED_FINAL_ARTIFACTS = frozenset(
    {
        SCAN_FINDINGS_FILENAME,
        SCAN_PROVENANCE_FILENAME,
        SCAN_CONVERSATION_FILENAME,
    }
)
_OPTIONAL_FINAL_ARTIFACTS = frozenset(
    {
        SCAN_SIMILARITY_FILENAME,
        SCAN_MEMORY_FILENAME,
    }
)
_ALLOWED_FINAL_ARTIFACTS = (
    _REQUIRED_FINAL_ARTIFACTS | _OPTIONAL_FINAL_ARTIFACTS
)
_FORBIDDEN_FINAL_LOCATORS = frozenset({SCAN_FINGERPRINT_FILENAME})
_NONFINAL_LOCATORS = frozenset(
    {SCAN_RUN_STATE_FILENAME, SCAN_RUN_FAILURE_FILENAME}
)
_TERMINAL_STATUSES = frozenset({"complete", "partial"})
_MAX_MARKER_BYTES = 1024 * 1024
_MAX_STRUCTURED_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_OPAQUE_ARTIFACT_BYTES = 256 * 1024 * 1024
_STRUCTURED_ARTIFACTS = frozenset(
    {SCAN_FINDINGS_FILENAME, SCAN_PROVENANCE_FILENAME}
)


class ScanOutputCommitError(ValueError):
    """扫描终态产物不属于同一提交集合。"""


_PORTABLE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def canonical_scan_reference_id(value: Any) -> str:
    """返回大小写保持的安全漏洞引用 ID。"""
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _PORTABLE_ID_PATTERN.fullmatch(value) is None
    ):
        raise ScanOutputCommitError("scanner reference id is invalid")
    return value


def canonical_scan_repo_name(value: Any) -> str:
    """返回可安全用于绑定键和目录名的仓库名。"""
    if (
        not isinstance(value, str)
        or value != value.strip()
        or _PORTABLE_ID_PATTERN.fullmatch(value) is None
    ):
        raise ScanOutputCommitError("scanner repository name is invalid")
    return value


def canonical_scan_commit(value: Any) -> str:
    """返回完整小写 Git 提交哈希。"""
    if not isinstance(value, str) or re.fullmatch(
        r"[0-9a-f]{40}", value
    ) is None:
        raise ScanOutputCommitError("scanner commit is invalid")
    return value


def is_lowercase_sha256(value: Any) -> bool:
    """返回输入是否为 64 位小写十六进制 SHA-256 文本。"""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _stable_data_hash(data: Any) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_json_object(raw_bytes: bytes, *, label: str) -> Dict[str, Any]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if not isinstance(key, str) or key in result:
                raise ScanOutputCommitError(
                    f"{label} contains an invalid or duplicate JSON key"
                )
            result[key] = value
        return result

    try:
        text = raw_bytes.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ScanOutputCommitError(
                    f"{label} contains non-finite JSON value {value}"
                )
            ),
        )
    except ScanOutputCommitError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanOutputCommitError(
            f"{label} is not canonical UTF-8 JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ScanOutputCommitError(f"{label} must be a JSON object")
    return payload


def _stable_stat_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_open_flags(*, directory: bool) -> int:
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise ScanOutputCommitError(
            "safe committed-output validation is unsupported"
        )
    if (
        os.open not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_follow_symlinks", set())
    ):
        raise ScanOutputCommitError(
            "safe committed-output validation is unsupported"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= os.O_NONBLOCK
    return flags


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _open_directory_without_symlinks(path: Path) -> int:
    absolute_path = _absolute_path(path)
    if not absolute_path.is_absolute() or not absolute_path.anchor:
        raise ScanOutputCommitError(
            "scanner run directory path must be absolute"
        )
    flags = _safe_open_flags(directory=True)
    directory_fd: Optional[int] = None
    try:
        directory_fd = os.open(absolute_path.anchor, flags)
        for component in absolute_path.parts[1:]:
            next_fd = os.open(
                component,
                flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        opened = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ScanOutputCommitError(
                "scanner run directory is not a directory"
            )
        result = directory_fd
        directory_fd = None
        return result
    except ScanOutputCommitError:
        raise
    except OSError as exc:
        raise ScanOutputCommitError(
            "scanner run directory contains an unsafe path component"
        ) from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _artifact_size_limit(filename: str) -> int:
    if filename == SCAN_OUTPUT_COMMIT_FILENAME:
        return _MAX_MARKER_BYTES
    if filename in _STRUCTURED_ARTIFACTS:
        return _MAX_STRUCTURED_ARTIFACT_BYTES
    return _MAX_OPAQUE_ARTIFACT_BYTES


def _open_regular_file_at(
    directory_fd: int,
    filename: str,
    *,
    expected_size: Optional[int] = None,
) -> Tuple[int, Tuple[int, ...]]:
    """打开并固定普通文件，调用方负责关闭描述符。"""
    if (
        filename not in _ALLOWED_FINAL_ARTIFACTS
        and filename != SCAN_OUTPUT_COMMIT_FILENAME
    ):
        raise ScanOutputCommitError(
            f"committed output contains an invalid locator: {filename!r}"
        )
    try:
        expected = os.stat(
            filename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise ScanOutputCommitError(
            f"committed output is missing: {filename}"
        ) from exc
    if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(
        expected.st_mode
    ):
        raise ScanOutputCommitError(
            f"committed output is not a regular file: {filename}"
        )
    if expected.st_size > _artifact_size_limit(filename):
        raise ScanOutputCommitError(
            f"committed output exceeds the size limit: {filename}"
        )
    if expected_size is not None and expected.st_size != expected_size:
        raise ScanOutputCommitError(
            f"committed output size does not match marker: {filename}"
        )
    expected_identity = _stable_stat_identity(expected)
    file_fd: Optional[int] = None
    try:
        file_fd = os.open(
            filename,
            _safe_open_flags(directory=False),
            dir_fd=directory_fd,
        )
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_stat_identity(opened) != expected_identity
        ):
            raise ScanOutputCommitError(
                f"committed output changed before reading: {filename}"
            )
        result = file_fd
        file_fd = None
        return result, expected_identity
    except ScanOutputCommitError:
        raise
    except OSError as exc:
        raise ScanOutputCommitError(
            f"committed output cannot be opened safely: {filename}"
        ) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _read_open_regular_file(
    file_fd: int,
    *,
    filename: str,
    expected_identity: Tuple[int, ...],
    materialize: bool,
) -> Tuple[Optional[bytes], int, str]:
    """流式读取固定文件，并可选择保留字节。"""
    digest = hashlib.sha256()
    chunks: Optional[List[bytes]] = [] if materialize else None
    size = 0
    try:
        os.lseek(file_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _artifact_size_limit(filename):
                raise ScanOutputCommitError(
                    f"committed output exceeds the size limit: {filename}"
                )
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(file_fd)
        if _stable_stat_identity(after) != expected_identity:
            raise ScanOutputCommitError(
                f"committed output changed while reading: {filename}"
            )
    except ScanOutputCommitError:
        raise
    except OSError as exc:
        raise ScanOutputCommitError(
            f"committed output cannot be read safely: {filename}"
        ) from exc
    raw = b"".join(chunks) if chunks is not None else None
    return raw, size, digest.hexdigest()


def _revalidate_open_regular_file_at(
    directory_fd: int,
    filename: str,
    file_fd: int,
    expected_identity: Tuple[int, ...],
) -> None:
    """在整组文件读完后复核描述符与目录项身份。"""
    try:
        opened = os.fstat(file_fd)
        current = os.stat(
            filename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise ScanOutputCommitError(
            f"committed output changed during validation: {filename}"
        ) from exc
    if (
        _stable_stat_identity(opened) != expected_identity
        or _stable_stat_identity(current) != expected_identity
    ):
        raise ScanOutputCommitError(
            f"committed output changed during validation: {filename}"
        )


def _read_regular_file_at(
    directory_fd: int,
    filename: str,
) -> bytes:
    file_fd: Optional[int] = None
    try:
        file_fd, expected_identity = _open_regular_file_at(
            directory_fd, filename
        )
        raw, _size, _digest = _read_open_regular_file(
            file_fd,
            filename=filename,
            expected_identity=expected_identity,
            materialize=True,
        )
        _revalidate_open_regular_file_at(
            directory_fd,
            filename,
            file_fd,
            expected_identity,
        )
        if raw is None:  # pragma: no cover - materialize=True
            raise ScanOutputCommitError(
                f"committed output cannot be materialized: {filename}"
            )
        return raw
    finally:
        if file_fd is not None:
            os.close(file_fd)


def _existing_locator_names(
    directory_fd: int,
    filenames: Iterable[str],
) -> set[str]:
    present: set[str] = set()
    for filename in filenames:
        try:
            metadata = os.stat(
                filename,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ScanOutputCommitError(
                f"cannot inspect scanner output locator: {filename}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
            metadata.st_mode
        ):
            raise ScanOutputCommitError(
                f"scanner output locator is unsafe: {filename}"
            )
        present.add(filename)
    return present


def read_stable_scan_artifact(run_dir: Path, filename: str) -> bytes:
    """通过稳定目录描述符读取一个允许的终态文件。"""
    if filename not in _ALLOWED_FINAL_ARTIFACTS:
        raise ScanOutputCommitError(
            f"scanner output artifact is not allowed: {filename!r}"
        )
    directory_fd: Optional[int] = None
    try:
        directory_fd = _open_directory_without_symlinks(run_dir)
        return _read_regular_file_at(directory_fd, filename)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def scan_output_commit_sha256(run_dir: Path) -> str:
    """稳定读取 marker，并返回供上层记录的字节哈希。"""
    directory_fd: Optional[int] = None
    try:
        directory_fd = _open_directory_without_symlinks(run_dir)
        marker_bytes = _read_regular_file_at(
            directory_fd,
            SCAN_OUTPUT_COMMIT_FILENAME,
        )
        return hashlib.sha256(marker_bytes).hexdigest()
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def build_scan_output_commit(
    *,
    reference_id: str,
    terminal_status: str,
    run_id: str,
    scan_fingerprint_hash: str,
    artifact_bytes: Mapping[str, bytes],
) -> Dict[str, Any]:
    """为全部扫描终态产物生成确定性 marker。"""
    reference_id = canonical_scan_reference_id(reference_id)
    if terminal_status not in _TERMINAL_STATUSES:
        raise ScanOutputCommitError(
            "scanner output terminal status must be complete or partial"
        )
    if not isinstance(run_id, str) or not run_id:
        raise ScanOutputCommitError(
            "scanner output run_id must be a non-empty string"
        )
    if not is_lowercase_sha256(scan_fingerprint_hash):
        raise ScanOutputCommitError(
            "scanner output fingerprint hash must be lowercase SHA-256"
        )
    paths = set(artifact_bytes)
    if not _REQUIRED_FINAL_ARTIFACTS.issubset(paths):
        raise ScanOutputCommitError(
            "scanner output commit is missing a required final artifact"
        )
    if not paths.issubset(_ALLOWED_FINAL_ARTIFACTS):
        raise ScanOutputCommitError(
            "scanner output commit contains an unexpected final locator"
        )
    artifacts = []
    for path in sorted(paths, key=lambda value: value.encode("utf-8")):
        raw_bytes = artifact_bytes[path]
        if not isinstance(raw_bytes, bytes):
            raise ScanOutputCommitError(
                f"scanner output artifact is not bytes: {path}"
            )
        artifacts.append(
            {
                "path": path,
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "size": len(raw_bytes),
            }
        )
    return {
        "schema_version": SCAN_OUTPUT_COMMIT_SCHEMA_VERSION,
        "kind": "scanner_output_commit",
        "reference_id": reference_id,
        "terminal_status": terminal_status,
        "run_id": run_id,
        "scan_fingerprint_hash": scan_fingerprint_hash,
        "artifacts": artifacts,
    }


_COVERAGE_FIELDS = (
    "coverage_status",
    "critical_scope_present",
    "critical_complete",
    "critical_scope_total_files",
    "critical_scope_completed_files",
    "full_universe_required",
    "full_universe_complete",
    "full_universe_total_files",
    "full_universe_completed_files",
    "scan_progress",
)


def _nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ScanOutputCommitError(f"{label} must be a non-negative integer")
    return value


def _validate_terminal_semantics(
    *,
    findings: Mapping[str, Any],
    provenance: Mapping[str, Any],
    terminal_status: str,
) -> None:
    """校验 marker、coverage、执行状态与 findings 的同一语义。"""
    coverage = provenance.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != set(
        _COVERAGE_FIELDS
    ):
        raise ScanOutputCommitError(
            "scanner output coverage schema is incomplete or unexpected"
        )
    findings_coverage = {
        field: findings.get(field) for field in _COVERAGE_FIELDS
    }
    if findings_coverage != coverage:
        raise ScanOutputCommitError(
            "scanner output coverage copies disagree"
        )

    vulnerabilities = findings.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ScanOutputCommitError(
            "scanner output vulnerabilities must be a list"
        )
    execution = provenance.get("execution")
    if not isinstance(execution, dict):
        raise ScanOutputCommitError(
            "scanner output execution record is missing"
        )
    if execution.get("status") != terminal_status:
        raise ScanOutputCommitError(
            "scanner output terminal status disagrees"
        )
    expected_partial = terminal_status == "partial"
    if execution.get("partial") is not expected_partial:
        raise ScanOutputCommitError(
            "scanner output partial flag disagrees with terminal status"
        )
    termination = execution.get("termination")
    if not isinstance(termination, str) or not termination.strip():
        raise ScanOutputCommitError(
            "scanner output termination reason is missing"
        )
    if execution.get("failure_reason") is not None:
        raise ScanOutputCommitError(
            "committed scanner output must not contain a failure reason"
        )

    coverage_status = coverage["coverage_status"]
    expected_coverage_statuses = (
        {"complete"} if terminal_status == "complete" else {"partial", "empty"}
    )
    if coverage_status not in expected_coverage_statuses:
        raise ScanOutputCommitError(
            "scanner output coverage status disagrees with terminal status"
        )

    bool_fields = (
        "critical_scope_present",
        "critical_complete",
        "full_universe_required",
        "full_universe_complete",
    )
    if any(not isinstance(coverage[field], bool) for field in bool_fields):
        raise ScanOutputCommitError(
            "scanner output coverage booleans are invalid"
        )
    critical_total = _nonnegative_int(
        coverage["critical_scope_total_files"],
        label="critical scope total",
    )
    critical_completed = _nonnegative_int(
        coverage["critical_scope_completed_files"],
        label="critical scope completed",
    )
    full_total = _nonnegative_int(
        coverage["full_universe_total_files"],
        label="full universe total",
    )
    full_completed = _nonnegative_int(
        coverage["full_universe_completed_files"],
        label="full universe completed",
    )
    if critical_completed > critical_total or full_completed > full_total:
        raise ScanOutputCommitError(
            "scanner output coverage completed count exceeds total"
        )
    if coverage["critical_scope_present"] != (critical_total > 0):
        raise ScanOutputCommitError(
            "scanner output critical-scope presence is inconsistent"
        )
    if coverage["critical_complete"] != (
        critical_total > 0 and critical_completed == critical_total
    ):
        raise ScanOutputCommitError(
            "scanner output critical coverage is inconsistent"
        )
    if coverage["full_universe_complete"] != (
        full_total > 0 and full_completed == full_total
    ):
        raise ScanOutputCommitError(
            "scanner output full-universe coverage is inconsistent"
        )
    if terminal_status == "complete" and not coverage["critical_complete"]:
        raise ScanOutputCommitError(
            "complete scanner output lacks complete critical coverage"
        )
    if (
        terminal_status == "complete"
        and provenance.get("evaluation_mode") is True
    ):
        try:
            require_evaluation_response_identity_usage(
                provenance.get("usage")
            )
        except EvaluationEvidenceUnavailableError as exc:
            raise ScanOutputCommitError(
                "complete evaluation output lacks exact response identity evidence"
            ) from exc
    if (
        terminal_status == "complete"
        and not coverage["critical_scope_present"]
    ):
        raise ScanOutputCommitError(
            "complete scanner output lacks a non-empty critical scope"
        )
    if (
        terminal_status == "complete"
        and coverage["full_universe_required"]
        and not coverage["full_universe_complete"]
    ):
        raise ScanOutputCommitError(
            "complete scanner output lacks required full-universe coverage"
        )

    progress = coverage["scan_progress"]
    if not isinstance(progress, dict):
        raise ScanOutputCommitError(
            "scanner output scan progress must be an object"
        )
    progress_total = _nonnegative_int(
        progress.get("total_files"), label="scan progress total"
    )
    progress_completed = _nonnegative_int(
        progress.get("completed"), label="scan progress completed"
    )
    progress_pending = _nonnegative_int(
        progress.get("pending"), label="scan progress pending"
    )
    progress_findings = _nonnegative_int(
        progress.get("findings"), label="scan progress findings"
    )
    if (
        progress_total != full_total
        or progress_completed != full_completed
        or progress_completed + progress_pending != progress_total
        or progress_findings != len(vulnerabilities)
    ):
        raise ScanOutputCommitError(
            "scanner output scan progress is inconsistent"
        )


def validate_committed_scan_outputs(
    run_dir: Path,
    *,
    expected_commit_sha256: str,
    require_complete: bool = True,
) -> Dict[str, Any]:
    """用外部 marker 哈希校验一组扫描终态输出。"""
    if not is_lowercase_sha256(expected_commit_sha256):
        raise ScanOutputCommitError(
            "expected scanner output commit hash must be lowercase SHA-256"
        )
    absolute_run_dir = _absolute_path(run_dir)
    directory_fd: Optional[int] = None
    live_directory_fd: Optional[int] = None
    pinned_files: Dict[str, Tuple[int, Tuple[int, ...]]] = {}
    try:
        directory_fd = _open_directory_without_symlinks(
            absolute_run_dir
        )
        directory_before = os.fstat(directory_fd)
        marker_fd, marker_identity = _open_regular_file_at(
            directory_fd,
            SCAN_OUTPUT_COMMIT_FILENAME,
        )
        pinned_files[SCAN_OUTPUT_COMMIT_FILENAME] = (
            marker_fd,
            marker_identity,
        )
        marker_bytes = _read_regular_file_at(
            directory_fd,
            SCAN_OUTPUT_COMMIT_FILENAME,
        )
        marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
        if marker_sha256 != expected_commit_sha256:
            raise ScanOutputCommitError(
                "scanner output commit marker does not match its external binding"
            )
        marker = _strict_json_object(
            marker_bytes,
            label=SCAN_OUTPUT_COMMIT_FILENAME,
        )
        if set(marker) != {
            "schema_version",
            "kind",
            "reference_id",
            "terminal_status",
            "run_id",
            "scan_fingerprint_hash",
            "artifacts",
        }:
            raise ScanOutputCommitError(
                "scanner output commit marker has unexpected fields"
            )
        if (
            type(marker["schema_version"]) is not int
            or marker["schema_version"]
            != SCAN_OUTPUT_COMMIT_SCHEMA_VERSION
            or marker["kind"] != "scanner_output_commit"
        ):
            raise ScanOutputCommitError(
                "scanner output commit marker schema is unsupported"
            )
        reference_id = canonical_scan_reference_id(
            marker["reference_id"]
        )
        terminal_status = marker["terminal_status"]
        if terminal_status not in _TERMINAL_STATUSES:
            raise ScanOutputCommitError(
                "scanner output commit marker has invalid terminal status"
            )
        if require_complete and terminal_status != "complete":
            raise ScanOutputCommitError(
                "partial scanner output is not headline eligible"
            )
        run_id = marker["run_id"]
        fingerprint_hash = marker["scan_fingerprint_hash"]
        if not isinstance(run_id, str) or not run_id:
            raise ScanOutputCommitError(
                "scanner output commit marker has invalid run_id"
            )
        if not is_lowercase_sha256(fingerprint_hash):
            raise ScanOutputCommitError(
                "scanner output commit marker has invalid fingerprint hash"
            )
        artifact_entries = marker["artifacts"]
        if not isinstance(artifact_entries, list):
            raise ScanOutputCommitError(
                "scanner output commit artifacts must be a list"
            )
        declared_paths: List[str] = []
        declared_records: Dict[str, Dict[str, Any]] = {}
        for entry in artifact_entries:
            if not isinstance(entry, dict) or set(entry) != {
                "path",
                "sha256",
                "size",
            }:
                raise ScanOutputCommitError(
                    "scanner output commit artifact record is invalid"
                )
            path = entry["path"]
            if (
                not isinstance(path, str)
                or path not in _ALLOWED_FINAL_ARTIFACTS
                or "/" in path
                or chr(92) in path
                or path in declared_records
            ):
                raise ScanOutputCommitError(
                    "scanner output commit contains duplicate or unsafe paths"
                )
            if not is_lowercase_sha256(entry["sha256"]):
                raise ScanOutputCommitError(
                    f"scanner output commit hash is invalid: {path}"
                )
            if (
                isinstance(entry["size"], bool)
                or not isinstance(entry["size"], int)
                or entry["size"] < 0
            ):
                raise ScanOutputCommitError(
                    f"scanner output commit size is invalid: {path}"
                )
            declared_paths.append(path)
            declared_records[path] = entry
        if declared_paths != sorted(
            declared_paths,
            key=lambda value: value.encode("utf-8"),
        ):
            raise ScanOutputCommitError(
                "scanner output commit artifacts are not canonically ordered"
            )
        declared_set = set(declared_paths)
        if not _REQUIRED_FINAL_ARTIFACTS.issubset(declared_set):
            raise ScanOutputCommitError(
                "scanner output commit omits a required final artifact"
            )
        actual_set = _existing_locator_names(
            directory_fd,
            _ALLOWED_FINAL_ARTIFACTS | _FORBIDDEN_FINAL_LOCATORS,
        )
        if actual_set & _FORBIDDEN_FINAL_LOCATORS:
            raise ScanOutputCommitError(
                "standalone scanner fingerprint locators are forbidden"
            )
        if actual_set != declared_set:
            raise ScanOutputCommitError(
                "scanner output commit does not enumerate the exact final artifact set"
            )
        nonfinal_set = _existing_locator_names(
            directory_fd,
            _NONFINAL_LOCATORS,
        )
        if nonfinal_set:
            raise ScanOutputCommitError(
                "terminal scanner output still contains a running/failure record"
            )

        pinned_identities = {
            (marker_identity[0], marker_identity[1])
        }
        for path in declared_paths:
            file_fd, file_identity = _open_regular_file_at(
                directory_fd,
                path,
                expected_size=declared_records[path]["size"],
            )
            inode_identity = (file_identity[0], file_identity[1])
            if inode_identity in pinned_identities:
                os.close(file_fd)
                raise ScanOutputCommitError(
                    "scanner output commit contains hard-linked artifacts"
                )
            pinned_identities.add(inode_identity)
            pinned_files[path] = (file_fd, file_identity)

        raw_artifacts: Dict[str, bytes] = {}
        parsed_artifacts: Dict[str, Any] = {}
        for path in declared_paths:
            record = declared_records[path]
            if path in {
                SCAN_FINDINGS_FILENAME,
                SCAN_PROVENANCE_FILENAME,
            }:
                raw_bytes = _read_regular_file_at(directory_fd, path)
                observed_size = len(raw_bytes)
                observed_sha256 = hashlib.sha256(raw_bytes).hexdigest()
                raw_artifacts[path] = raw_bytes
                parsed_artifacts[path] = _strict_json_object(
                    raw_bytes,
                    label=path,
                )
            else:
                file_fd, file_identity = pinned_files[path]
                _raw, observed_size, observed_sha256 = (
                    _read_open_regular_file(
                        file_fd,
                        filename=path,
                        expected_identity=file_identity,
                        materialize=False,
                    )
                )
            if (
                observed_size != record["size"]
                or observed_sha256 != record["sha256"]
            ):
                raise ScanOutputCommitError(
                    f"scanner output artifact does not match marker: {path}"
                )

        findings = parsed_artifacts[SCAN_FINDINGS_FILENAME]
        provenance = parsed_artifacts[SCAN_PROVENANCE_FILENAME]
        embedded_provenance = findings.get("run_provenance")
        findings_fingerprint = findings.get("scan_fingerprint")
        provenance_fingerprint = provenance.get("scan_fingerprint")
        embedded_fingerprint = (
            embedded_provenance.get("scan_fingerprint")
            if isinstance(embedded_provenance, dict)
            else None
        )
        if (
            not isinstance(findings_fingerprint, dict)
            or not isinstance(provenance_fingerprint, dict)
            or not isinstance(embedded_fingerprint, dict)
            or findings_fingerprint != provenance_fingerprint
            or findings_fingerprint != embedded_fingerprint
            or embedded_provenance != provenance
        ):
            raise ScanOutputCommitError(
                "scanner output fingerprints or provenance copies disagree"
            )
        fingerprint_payload = dict(findings_fingerprint)
        observed_fingerprint_hash = fingerprint_payload.pop("hash", None)
        if (
            observed_fingerprint_hash != fingerprint_hash
            or _stable_data_hash(fingerprint_payload)
            != observed_fingerprint_hash
        ):
            raise ScanOutputCommitError(
                "scanner output fingerprint self-hash is invalid"
            )
        provenance_execution = provenance.get("execution")
        fingerprint_scan_config = findings_fingerprint.get("scan_config")
        if (
            provenance.get("run_id") != run_id
            or provenance.get("reference_id") != reference_id
            or not isinstance(provenance_execution, dict)
            or provenance_execution.get("status") != terminal_status
            or not isinstance(fingerprint_scan_config, dict)
            or fingerprint_scan_config.get("run_id") != run_id
        ):
            raise ScanOutputCommitError(
                "scanner output run identity or terminal status disagrees"
            )
        _validate_terminal_semantics(
            findings=findings,
            provenance=provenance,
            terminal_status=terminal_status,
        )

        for path, (file_fd, file_identity) in pinned_files.items():
            _revalidate_open_regular_file_at(
                directory_fd,
                path,
                file_fd,
                file_identity,
            )

        directory_after = os.fstat(directory_fd)
        live_directory_fd = _open_directory_without_symlinks(
            absolute_run_dir
        )
        live_directory = os.fstat(live_directory_fd)
        if (
            _stable_stat_identity(directory_after)
            != _stable_stat_identity(directory_before)
            or _stable_stat_identity(live_directory)
            != _stable_stat_identity(directory_before)
        ):
            raise ScanOutputCommitError(
                "scanner run directory changed during validation"
            )
        return {
            "marker": marker,
            "marker_sha256": marker_sha256,
            "findings": findings,
            "run_provenance": provenance,
            "artifact_bytes": raw_artifacts,
            "terminal_status": terminal_status,
            "reference_id": reference_id,
            "headline_eligible": terminal_status == "complete",
        }
    except ScanOutputCommitError:
        raise
    except OSError as exc:
        raise ScanOutputCommitError(
            "scanner output set changed during validation"
        ) from exc
    finally:
        for file_fd, _identity in pinned_files.values():
            os.close(file_fd)
        if live_directory_fd is not None:
            os.close(live_directory_fd)
        if directory_fd is not None:
            os.close(directory_fd)
