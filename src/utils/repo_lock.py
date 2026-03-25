"""Repository-level coordination locks for commit-switching workflows."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, Optional, Tuple
from uuid import uuid4

from config import _path_config

from .logger import get_logger

logger = get_logger(__name__)

LOCK_STATUS_ACQUIRED = "acquired"
LOCK_STATUS_BUSY = "busy"
LOCK_STATUS_ERROR = "error"
LOCK_STATUS_INITIALIZING = "initializing"
LOCK_STATUS_MISSING = "missing"
LOCK_READ_RETRY_DELAYS_SECONDS = (0.05, 0.1, 0.2)
LOCK_INITIALIZATION_GRACE_SECONDS = 1.0
LOCK_HEARTBEAT_SECONDS = 30.0
LOCK_UNVERIFIED_STALE_SECONDS = 3600.0
DEFAULT_REPO_LOCK_POLL_SECONDS = 0.2
LOCK_COORDINATION_FILENAME_SUFFIX = ".coord"
LockIdentity = Tuple[int, int]


def _lock_age_seconds(lock_path: Path) -> Optional[float]:
    """Return the age of one lock file in seconds when available.

    Args:
        lock_path: Lock file path.

    Returns:
        Lock age in seconds, or ``None`` when the file does not exist.
    """
    try:
        return max(0.0, time.time() - lock_path.stat().st_mtime)
    except FileNotFoundError:
        return None
    except OSError:
        return None


def _write_lock_owner_tempfile(lock_path: Path, owner: Dict[str, Any]) -> Path:
    """Write lock ownership metadata into a temporary file.

    Args:
        lock_path: Final lock path.
        owner: JSON-serializable ownership payload.

    Returns:
        Temporary file path containing the serialized payload.
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=lock_path.parent,
        prefix=f".{lock_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(json.dumps(owner, indent=2, ensure_ascii=False))
        handle.flush()
        os.fsync(handle.fileno())
        return Path(handle.name)


def _read_lock_snapshot(lock_path: Path) -> Tuple[Optional[str], Optional[LockIdentity], Optional[str]]:
    """Read one lock file plus the inode identity that was inspected.

    Args:
        lock_path: Lock file path.

    Returns:
        Tuple of ``(payload_text, identity, error_message)``.
    """
    try:
        with lock_path.open("r", encoding="utf-8") as handle:
            payload_text = handle.read()
            stat_result = os.fstat(handle.fileno())
    except FileNotFoundError:
        return None, None, None
    except Exception as exc:
        return None, None, str(exc)
    return payload_text, (stat_result.st_dev, stat_result.st_ino), None


def _coordination_lock_path(lock_path: Path) -> Path:
    """Return the sidecar coordination-lock path for one logical lock."""
    return lock_path.with_name(f".{lock_path.name}{LOCK_COORDINATION_FILENAME_SUFFIX}")


@contextmanager
def _hold_lock_coordination_lock(lock_path: Path) -> Generator[None, None, None]:
    """Serialize publish/cleanup operations for one logical lock path.

    Args:
        lock_path: Logical lock file path.
    """
    coordination_path = _coordination_lock_path(lock_path)
    coordination_path.parent.mkdir(parents=True, exist_ok=True)
    with coordination_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _publish_lock_file(lock_path: Path, owner: Dict[str, Any]) -> bool:
    """Publish a fully initialized lock file without overwriting.

    Args:
        lock_path: Final lock path.
        owner: JSON-serializable ownership payload.

    Returns:
        ``True`` when the file was published, otherwise ``False``.
    """
    temp_path: Optional[Path] = None
    try:
        temp_path = _write_lock_owner_tempfile(lock_path, owner)
        try:
            os.link(temp_path, lock_path)
        except FileExistsError:
            return False
        except OSError:
            if lock_path.exists():
                return False
            raise
        temp_path.unlink(missing_ok=True)
        temp_path = None
        return True
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def _load_lock_payload(lock_path: Path) -> Dict[str, Any]:
    """Load JSON payload from one lock file.

    Args:
        lock_path: Lock file path.

    Returns:
        Decoded dictionary payload, or an empty dictionary on failure.
    """
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _remove_lock_path(lock_path: Path) -> None:
    """Delete one lock file when present.

    Args:
        lock_path: Lock file path.
    """
    if lock_path.exists():
        lock_path.unlink()


def _remove_lock_path_if_identity_matches(
    lock_path: Path,
    expected_identity: Optional[LockIdentity],
) -> bool:
    """Remove one lock file only when it is still the inspected inode.

    Args:
        lock_path: Lock file path.
        expected_identity: Device/inode pair captured during inspection.

    Returns:
        ``True`` when the matching file was removed or already disappeared, and
        ``False`` when another process replaced it meanwhile.
    """
    if expected_identity is None:
        return False
    try:
        current_stat = lock_path.stat()
    except FileNotFoundError:
        return True
    current_identity = (current_stat.st_dev, current_stat.st_ino)
    if current_identity != expected_identity:
        return False
    lock_path.unlink()
    return True


def _start_lock_heartbeat(lock_path: Path, token: str) -> Tuple[threading.Event, threading.Thread]:
    """Refresh one owned lock file's mtime while work is running.

    Args:
        lock_path: Lock file path.
        token: Current owner token.

    Returns:
        Stop event and heartbeat thread.
    """
    stop_event = threading.Event()

    def _heartbeat() -> None:
        while not stop_event.wait(LOCK_HEARTBEAT_SECONDS):
            lock_data = _load_lock_payload(lock_path)
            if lock_data.get("token") != token:
                return
            try:
                os.utime(lock_path, None)
            except OSError:
                return

    thread = threading.Thread(
        target=_heartbeat,
        name=f"repo-lock-heartbeat-{lock_path.name}",
        daemon=True,
    )
    thread.start()
    return stop_event, thread


def _inspect_lock(
    lock_path: Path,
) -> Tuple[str, Optional[Dict[str, Any]], Optional[str], Optional[LockIdentity]]:
    """Inspect one lock file without deleting it automatically.

    Args:
        lock_path: Lock file path.

    Returns:
        Tuple of ``(status, payload, detail, identity)``.
    """
    last_error: Optional[str] = None
    last_identity: Optional[LockIdentity] = None

    for delay_seconds in (0.0, *LOCK_READ_RETRY_DELAYS_SECONDS):
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        if not lock_path.exists():
            return LOCK_STATUS_MISSING, None, None, None
        if not lock_path.is_file():
            last_error = "lock path is not a regular file"
            continue
        payload_text, lock_identity, read_error = _read_lock_snapshot(lock_path)
        if payload_text is None and read_error is None:
            continue
        if read_error is not None:
            last_error = read_error
            continue
        last_identity = lock_identity
        if not payload_text.strip():
            last_error = "lock file is empty"
            continue
        try:
            payload = json.loads(payload_text)
        except Exception as exc:
            last_error = str(exc)
            continue
        if isinstance(payload, dict):
            return "ready", payload, None, last_identity
        last_error = "lock payload is not a JSON object"

    lock_age = _lock_age_seconds(lock_path)
    if lock_age is not None and lock_age < LOCK_INITIALIZATION_GRACE_SECONDS:
        return LOCK_STATUS_INITIALIZING, None, last_error or "lock metadata is not ready", last_identity
    return LOCK_STATUS_ERROR, None, last_error, last_identity


def _read_process_command_line(pid: int) -> Optional[str]:
    """Read one process command line when ``/proc`` is available.

    Args:
        pid: Process identifier.

    Returns:
        Command-line string, or ``None`` when unavailable.
    """
    cmdline_path = Path("/proc") / str(pid) / "cmdline"
    try:
        raw = cmdline_path.read_text(encoding="utf-8")
    except Exception:
        return None
    parts = [part for part in raw.split("\x00") if part]
    if not parts:
        return None
    return " ".join(parts)


def _read_process_identity(pid: int) -> Optional[str]:
    """Read a minimal process identity for lock metadata.

    Args:
        pid: Process identifier.

    Returns:
        Executable basename, or ``None`` when unavailable.
    """
    command_line = _read_process_command_line(pid)
    if not command_line:
        return None
    return Path(command_line.split(" ", 1)[0]).name


def _read_process_start_time(pid: int) -> Optional[str]:
    """Read the kernel start-time token used to detect PID reuse.

    Args:
        pid: Process identifier.

    Returns:
        Kernel start-time token, or ``None`` when unavailable.
    """
    stat_path = Path("/proc") / str(pid) / "stat"
    try:
        stat_text = stat_path.read_text(encoding="utf-8")
    except Exception:
        return None
    stat_fields = stat_text.split()
    if len(stat_fields) < 22:
        return None
    return stat_fields[21]


def _lock_pid_is_active(
    pid: Any,
    expected_command: Optional[str] = None,
    expected_start_time: Optional[str] = None,
    expected_uid: Optional[int] = None,
) -> Optional[bool]:
    """Return whether a lock holder pid still looks alive.

    Args:
        pid: Process identifier stored in the lock.
        expected_command: Optional expected process executable name.
        expected_start_time: Optional kernel start-time token.
        expected_uid: Optional owner uid.

    Returns:
        ``True`` when the owner looks alive, ``False`` when clearly stale, or
        ``None`` when liveness cannot be verified safely.
    """
    if not isinstance(pid, int) or pid <= 0:
        return False
    permission_denied = False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        permission_denied = True
    except OSError:
        return False

    running_start_time: Optional[str] = None
    if expected_start_time:
        running_start_time = _read_process_start_time(pid)
        if running_start_time and running_start_time != expected_start_time:
            return False

    running_command: Optional[str] = None
    if expected_command:
        running_command = _read_process_identity(pid)
        if running_command and running_command != expected_command:
            return False

    if permission_denied:
        if expected_start_time and running_start_time == expected_start_time:
            return True
        if isinstance(expected_uid, int) and hasattr(os, "getuid") and expected_uid == os.getuid():
            return False
        return None

    return True


def acquire_lock(
    lock_path: Path,
    *,
    run_id: Optional[str],
    owner_fields: Dict[str, Any],
) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    """Try to acquire one file lock.

    Args:
        lock_path: Final lock file path.
        run_id: Optional logical run id stored in metadata.
        owner_fields: Additional JSON-serializable metadata.

    Returns:
        Tuple of ``(status, lock_info, detail)``.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    owner = {
        "token": uuid4().hex,
        "pid": os.getpid(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "command": _read_process_identity(os.getpid()) or Path(sys.argv[0]).name,
        "pid_start_time": _read_process_start_time(os.getpid()),
        **owner_fields,
    }

    for _ in range(2):
        with _hold_lock_coordination_lock(lock_path):
            if _publish_lock_file(lock_path, owner):
                heartbeat_stop_event, heartbeat_thread = _start_lock_heartbeat(lock_path, owner["token"])
                return LOCK_STATUS_ACQUIRED, {
                    "lock_path": lock_path,
                    "token": owner["token"],
                    "heartbeat_stop_event": heartbeat_stop_event,
                    "heartbeat_thread": heartbeat_thread,
                }, None

            lock_state, lock_data, lock_error, lock_identity = _inspect_lock(lock_path)
            if lock_state == LOCK_STATUS_MISSING:
                continue
            if lock_state == LOCK_STATUS_INITIALIZING:
                return LOCK_STATUS_BUSY, None, f"lock at {lock_path} is initializing"
            if lock_state == LOCK_STATUS_ERROR or lock_data is None:
                lock_age = _lock_age_seconds(lock_path)
                if lock_age is not None and lock_age >= LOCK_INITIALIZATION_GRACE_SECONDS:
                    try:
                        removed = _remove_lock_path_if_identity_matches(lock_path, lock_identity)
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        return LOCK_STATUS_ERROR, None, f"broken lock at {lock_path} could not be removed: {exc}"
                    if not removed:
                        continue
                    continue
                return LOCK_STATUS_ERROR, None, f"could not inspect existing lock at {lock_path}: {lock_error or 'unknown error'}"

            lock_pid = lock_data.get("pid")
            if not isinstance(lock_pid, int):
                try:
                    removed = _remove_lock_path_if_identity_matches(lock_path, lock_identity)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    return LOCK_STATUS_ERROR, None, f"malformed lock at {lock_path} could not be removed: {exc}"
                if removed is False:
                    continue
                continue
            lock_is_active = _lock_pid_is_active(
                lock_pid,
                expected_command=lock_data.get("command"),
                expected_start_time=lock_data.get("pid_start_time"),
                expected_uid=lock_data.get("uid"),
            )
            if lock_is_active is False:
                try:
                    removed = _remove_lock_path_if_identity_matches(lock_path, lock_identity)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    return LOCK_STATUS_ERROR, None, f"stale lock at {lock_path} could not be removed: {exc}"
                if removed is False:
                    continue
                continue
            if lock_is_active is None:
                lock_age = _lock_age_seconds(lock_path)
                if lock_age is not None and lock_age >= LOCK_UNVERIFIED_STALE_SECONDS:
                    try:
                        removed = _remove_lock_path_if_identity_matches(lock_path, lock_identity)
                    except FileNotFoundError:
                        pass
                    except OSError as exc:
                        return LOCK_STATUS_ERROR, None, f"unverified stale lock at {lock_path} could not be removed: {exc}"
                    if removed is False:
                        continue
                    continue
                holder_parts = [f"pid={lock_pid}", "holder=unverified"]
                if lock_data.get("run_id"):
                    holder_parts.append(f"run_id={lock_data['run_id']}")
                return LOCK_STATUS_BUSY, None, f"could not verify existing lock at {lock_path}: {', '.join(holder_parts)}"

            holder_parts = [f"pid={lock_pid}"]
            if lock_data.get("run_id"):
                holder_parts.append(f"run_id={lock_data['run_id']}")
            if lock_data.get("purpose"):
                holder_parts.append(f"purpose={lock_data['purpose']}")
            return LOCK_STATUS_BUSY, None, ", ".join(holder_parts)

    return LOCK_STATUS_ERROR, None, f"could not acquire lock at {lock_path}"


def release_lock(lock_info: Optional[Dict[str, Any]]) -> None:
    """Release one owned lock.

    Args:
        lock_info: Lock handle returned by :func:`acquire_lock`.
    """
    if not lock_info:
        return
    heartbeat_stop_event = lock_info.get("heartbeat_stop_event")
    heartbeat_thread = lock_info.get("heartbeat_thread")
    if isinstance(heartbeat_stop_event, threading.Event):
        heartbeat_stop_event.set()
    if isinstance(heartbeat_thread, threading.Thread):
        heartbeat_thread.join(timeout=LOCK_HEARTBEAT_SECONDS)

    lock_path = lock_info.get("lock_path")
    token = lock_info.get("token")
    if not isinstance(lock_path, Path) or not isinstance(token, str) or not token:
        return
    if not lock_path.exists():
        return
    lock_data = _load_lock_payload(lock_path)
    if lock_data.get("token") != token:
        return
    try:
        _remove_lock_path(lock_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        logger.warning("Failed to release lock %s: %s", lock_path, exc)


def resolve_repo_lock_path(repo_path: Path) -> Path:
    """Resolve the stable lock path for one repository path.

    Args:
        repo_path: Repository path that may be checked out temporarily.

    Returns:
        Stable lock file path under ``.runtime-locks/repos``.
    """
    normalized_repo_path = repo_path.expanduser().resolve()
    repo_hash = hashlib.sha1(str(normalized_repo_path).encode("utf-8")).hexdigest()
    return _path_config["repo_root"] / ".runtime-locks" / "repos" / f"{repo_hash}.lock"


def acquire_repo_lock(
    repo_path: Path,
    *,
    purpose: str,
    run_id: Optional[str] = None,
    poll_interval_seconds: float = DEFAULT_REPO_LOCK_POLL_SECONDS,
) -> Dict[str, Any]:
    """Block until one repository lock is acquired safely.

    Args:
        repo_path: Repository path whose working tree may be mutated.
        purpose: Human-readable purpose for lock metadata and logs.
        run_id: Optional logical run id.
        poll_interval_seconds: Delay between retries when another worker owns the lock.

    Returns:
        Lock handle used by :func:`release_lock`.

    Raises:
        RuntimeError: If the lock cannot be coordinated safely.
    """
    lock_path = resolve_repo_lock_path(repo_path)
    normalized_repo_path = repo_path.expanduser().resolve()
    wait_logged = False
    wait_started_at: Optional[float] = None

    while True:
        status, lock_info, detail = acquire_lock(
            lock_path,
            run_id=run_id,
            owner_fields={
                "repo_path": str(normalized_repo_path),
                "purpose": purpose,
            },
        )
        if status == LOCK_STATUS_ACQUIRED and lock_info is not None:
            if wait_started_at is not None:
                logger.info(
                    "Acquired repo lock for %s (%s) after waiting %.2fs",
                    normalized_repo_path,
                    purpose,
                    max(0.0, time.time() - wait_started_at),
                )
            else:
                logger.info("Acquired repo lock for %s (%s)", normalized_repo_path, purpose)
            return lock_info
        if status == LOCK_STATUS_BUSY:
            if not wait_logged:
                logger.info(
                    "Waiting for repo lock on %s (%s)",
                    normalized_repo_path,
                    detail or purpose,
                )
                wait_logged = True
                wait_started_at = time.time()
            time.sleep(max(poll_interval_seconds, 0.01))
            continue
        raise RuntimeError(
            f"Failed to coordinate repo lock for {normalized_repo_path} ({detail or status})"
        )


def release_repo_lock(lock_info: Optional[Dict[str, Any]], repo_path: Path, purpose: str) -> None:
    """Release one repository lock and log the lifecycle.

    Args:
        lock_info: Lock handle returned by :func:`acquire_repo_lock`.
        repo_path: Repository path used for logging.
        purpose: Human-readable purpose used for logging.
    """
    release_lock(lock_info)
    logger.info("Released repo lock for %s (%s)", repo_path.expanduser().resolve(), purpose)


@contextmanager
def hold_repo_lock(
    repo_path: Path,
    *,
    purpose: str,
    run_id: Optional[str] = None,
    poll_interval_seconds: float = DEFAULT_REPO_LOCK_POLL_SECONDS,
) -> Generator[None, None, None]:
    """Hold one repository lock around a commit-sensitive workflow.

    Args:
        repo_path: Repository path whose working tree must remain stable.
        purpose: Human-readable purpose for lock metadata and logs.
        run_id: Optional logical run id.
        poll_interval_seconds: Delay between retries while waiting for the lock.

    Yields:
        ``None`` while the caller owns the repository lock.
    """
    lock_info = acquire_repo_lock(
        repo_path,
        purpose=purpose,
        run_id=run_id,
        poll_interval_seconds=poll_interval_seconds,
    )
    try:
        yield
    finally:
        release_repo_lock(lock_info, repo_path, purpose)
