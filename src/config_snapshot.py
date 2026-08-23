"""冻结 scanner YAML 配置的原始字节。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import threading
from typing import Dict, Optional, Tuple


SCANNER_CONFIG_FILENAMES = (
    "paths.yaml",
    "scanner_config.yaml",
    "codeql_config.yaml",
    "llm_config.yaml",
)
SCANNER_CONFIG_ROOT = Path(__file__).resolve().parent.parent / "config"


class ConfigSnapshotError(ValueError):
    """无法建立精确配置快照。"""


class ConfigSnapshotDriftError(ConfigSnapshotError):
    """当前配置与已消费快照不一致。"""


@dataclass(frozen=True)
class _ConfigByteSnapshot:
    path: str
    raw_bytes: bytes
    sha256: str
    identity: Tuple[int, ...]


_CONSUMED_SCANNER_CONFIGS: Dict[str, _ConfigByteSnapshot] = {}
_SNAPSHOT_LOCK = threading.RLock()


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
        raise ConfigSnapshotError(
            "safe descriptor-relative config reads are unsupported"
        )
    if (
        os.open not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_follow_symlinks", set())
    ):
        raise ConfigSnapshotError(
            "safe descriptor-relative config reads are unsupported"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= os.O_NONBLOCK
    return flags


def _absolute_path(path: Path) -> Path:
    """转为绝对路径，不跟随符号链接。"""
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _open_directory_without_symlinks(path: Path) -> int:
    """用 O_NOFOLLOW 逐级打开绝对目录。"""
    absolute_path = _absolute_path(path)
    if not absolute_path.is_absolute() or not absolute_path.anchor:
        raise ConfigSnapshotError("config directory path must be absolute")
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
            raise ConfigSnapshotError("config parent is not a directory")
        result = directory_fd
        directory_fd = None
        return result
    except ConfigSnapshotError:
        raise
    except OSError as exc:
        raise ConfigSnapshotError(
            "config directory contains an unsafe path component"
        ) from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _read_regular_file_snapshot(
    path: Path,
    *,
    label: str,
) -> _ConfigByteSnapshot:
    """通过稳定目录和文件描述符读取普通文件。"""
    absolute_path = _absolute_path(path)
    parent_fd: Optional[int] = None
    file_fd: Optional[int] = None
    live_parent_fd: Optional[int] = None
    try:
        parent_fd = _open_directory_without_symlinks(
            absolute_path.parent
        )
        parent_before = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_before.st_mode):
            raise ConfigSnapshotError(f"{label} parent is not a directory")
        expected = os.stat(
            absolute_path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(
            expected.st_mode
        ):
            raise ConfigSnapshotError(
                f"{label} must be a non-symlink regular file"
            )
        file_fd = os.open(
            absolute_path.name,
            _safe_open_flags(directory=False),
            dir_fd=parent_fd,
        )
        opened = os.fstat(file_fd)
        expected_identity = _stable_stat_identity(expected)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stable_stat_identity(opened) != expected_identity
        ):
            raise ConfigSnapshotError(f"{label} changed before it was read")

        chunks = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)

        after_read = os.fstat(file_fd)
        current = os.stat(
            absolute_path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        parent_after = os.fstat(parent_fd)
        live_parent_fd = _open_directory_without_symlinks(
            absolute_path.parent
        )
        live_parent = os.fstat(live_parent_fd)
        live_current = os.stat(
            absolute_path.name,
            dir_fd=live_parent_fd,
            follow_symlinks=False,
        )
        if (
            _stable_stat_identity(after_read) != expected_identity
            or _stable_stat_identity(current) != expected_identity
            or _stable_stat_identity(parent_after)
            != _stable_stat_identity(parent_before)
            or _stable_stat_identity(live_parent)
            != _stable_stat_identity(parent_before)
            or _stable_stat_identity(live_current) != expected_identity
        ):
            raise ConfigSnapshotError(f"{label} changed while it was read")
        return _ConfigByteSnapshot(
            path=os.fspath(absolute_path),
            raw_bytes=raw_bytes,
            sha256=hashlib.sha256(raw_bytes).hexdigest(),
            identity=expected_identity,
        )
    except ConfigSnapshotError:
        raise
    except OSError as exc:
        raise ConfigSnapshotError(
            f"{label} cannot be read through a stable regular-file descriptor"
        ) from exc
    finally:
        if live_parent_fd is not None:
            os.close(live_parent_fd)
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def read_config_file_bytes(path: Path, *, label: str) -> bytes:
    """安全读取自定义配置，不写入 scanner 注册表。"""
    return _read_regular_file_snapshot(path, label=label).raw_bytes


def scanner_config_path(filename: str) -> Path:
    """返回默认 scanner 配置的精确路径。"""
    if filename not in SCANNER_CONFIG_FILENAMES:
        raise ConfigSnapshotError("unknown scanner config filename")
    return _absolute_path(Path(SCANNER_CONFIG_ROOT) / filename)


def _verify_unchanged(
    filename: str,
    snapshot: _ConfigByteSnapshot,
) -> None:
    current_path = scanner_config_path(filename)
    if os.fspath(current_path) != snapshot.path:
        raise ConfigSnapshotDriftError(
            f"{filename} config root changed after consumption"
        )
    current = _read_regular_file_snapshot(current_path, label=filename)
    if current.identity != snapshot.identity:
        raise ConfigSnapshotDriftError(
            f"{filename} file identity changed after consumption"
        )
    if current.raw_bytes != snapshot.raw_bytes:
        raise ConfigSnapshotDriftError(
            f"{filename} bytes changed after consumption"
        )


def _read_scanner_config_generation(
) -> Dict[str, _ConfigByteSnapshot]:
    """双遍读取整组配置，拒绝跨文件混代。"""
    first = {
        filename: _read_regular_file_snapshot(
            scanner_config_path(filename),
            label=filename,
        )
        for filename in SCANNER_CONFIG_FILENAMES
    }
    second = {
        filename: _read_regular_file_snapshot(
            scanner_config_path(filename),
            label=filename,
        )
        for filename in SCANNER_CONFIG_FILENAMES
    }
    for filename in SCANNER_CONFIG_FILENAMES:
        if (
            first[filename].path != second[filename].path
            or first[filename].identity != second[filename].identity
            or first[filename].raw_bytes != second[filename].raw_bytes
        ):
            raise ConfigSnapshotDriftError(
                f"{filename} changed across scanner config generation"
            )
    return second


def _freeze_scanner_config_files_locked() -> None:
    if _CONSUMED_SCANNER_CONFIGS:
        if set(_CONSUMED_SCANNER_CONFIGS) != set(
            SCANNER_CONFIG_FILENAMES
        ):
            raise ConfigSnapshotError(
                "scanner config registry contains a partial generation"
            )
        for filename in SCANNER_CONFIG_FILENAMES:
            _verify_unchanged(
                filename,
                _CONSUMED_SCANNER_CONFIGS[filename],
            )
        return
    generation = _read_scanner_config_generation()
    _CONSUMED_SCANNER_CONFIGS.update(generation)


def consume_scanner_config_bytes(filename: str) -> bytes:
    """校验当前文件后返回首次冻结的配置字节。"""
    if filename not in SCANNER_CONFIG_FILENAMES:
        raise ConfigSnapshotError("unknown scanner config filename")
    with _SNAPSHOT_LOCK:
        _freeze_scanner_config_files_locked()
        return _CONSUMED_SCANNER_CONFIGS[filename].raw_bytes


def freeze_scanner_config_files() -> Dict[str, str]:
    """一次性冻结四个 scanner 配置并校验当前路径。"""
    with _SNAPSHOT_LOCK:
        _freeze_scanner_config_files_locked()
        return {
            filename: _CONSUMED_SCANNER_CONFIGS[filename].sha256
            for filename in SCANNER_CONFIG_FILENAMES
        }


def consumed_scanner_config_hashes() -> Dict[str, str]:
    """确认当前路径未变后返回已消费配置哈希。"""
    with _SNAPSHOT_LOCK:
        missing = [
            filename
            for filename in SCANNER_CONFIG_FILENAMES
            if filename not in _CONSUMED_SCANNER_CONFIGS
        ]
        if missing:
            raise ConfigSnapshotError(
                "scanner config snapshots are incomplete: " + ",".join(missing)
            )
        for filename in SCANNER_CONFIG_FILENAMES:
            _verify_unchanged(
                filename,
                _CONSUMED_SCANNER_CONFIGS[filename],
            )
        return {
            filename: _CONSUMED_SCANNER_CONFIGS[filename].sha256
            for filename in SCANNER_CONFIG_FILENAMES
        }


def immutable_consumed_scanner_config_hashes(
) -> Dict[str, Optional[str]]:
    """只返回首次消费哈希，不重读漂移路径。"""
    with _SNAPSHOT_LOCK:
        return {
            filename: (
                _CONSUMED_SCANNER_CONFIGS[filename].sha256
                if filename in _CONSUMED_SCANNER_CONFIGS
                else None
            )
            for filename in SCANNER_CONFIG_FILENAMES
        }
