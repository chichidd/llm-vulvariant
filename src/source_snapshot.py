"""用描述符遍历并检测 Python 源码集合变更。"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from typing import Dict, List, Optional, Tuple


_DirectoryEntrySnapshot = Tuple[
    str,
    str,
    int,
    int,
    int,
    int,
    int,
    int,
]


def _portable_directory_entry_name(name: object) -> str:
    """校验 scandir 返回的可移植规范名称。"""
    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or chr(92) in name
    ):
        raise ValueError("Python source tree contains a non-canonical entry")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Python source tree entry is not valid UTF-8"
        ) from exc
    return name


def _scan_directory_snapshot(
    directory_fd: int,
) -> List[_DirectoryEntrySnapshot]:
    """返回按确定顺序排列的 lstat 目录快照。"""
    entries: List[_DirectoryEntrySnapshot] = []
    try:
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                name = _portable_directory_entry_name(entry.name)
                metadata = entry.stat(follow_symlinks=False)
                mode = metadata.st_mode
                if stat.S_ISLNK(mode):
                    raise ValueError(
                        "Python source tree must not contain symlinks"
                    )
                if stat.S_ISDIR(mode):
                    kind = "directory"
                elif stat.S_ISREG(mode):
                    kind = "regular"
                else:
                    raise ValueError(
                        "Python source tree must not contain special entries"
                    )
                entries.append(
                    (
                        name,
                        kind,
                        metadata.st_dev,
                        metadata.st_ino,
                        mode,
                        metadata.st_size,
                        metadata.st_mtime_ns,
                        metadata.st_ctime_ns,
                    )
                )
    except OSError as exc:
        raise ValueError(
            "Python source directory cannot be read safely"
        ) from exc
    entries.sort(key=lambda item: item[0].encode("utf-8"))
    return entries


def _stable_stat_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    """记录可检测哈希期间替换或修改的字段。"""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_source_open_flags(*, directory: bool) -> int:
    """构造描述符相对遍历所需的失败关闭标志。"""
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        raise ValueError("safe Python source traversal is unsupported")
    if (
        os.open not in getattr(os, "supports_dir_fd", set())
        or os.scandir not in getattr(os, "supports_fd", set())
        or os.stat not in getattr(os, "supports_dir_fd", set())
        or os.stat not in getattr(os, "supports_follow_symlinks", set())
    ):
        raise ValueError("safe Python source traversal is unsupported")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    else:
        flags |= os.O_NONBLOCK
    return flags


def _absolute_source_path(path: Path) -> Path:
    """转为绝对源码路径，不解析符号链接。"""
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _open_source_directory_without_symlinks(path: Path) -> int:
    """用 O_NOFOLLOW 逐级打开绝对源码目录。"""
    absolute_path = _absolute_source_path(path)
    if not absolute_path.is_absolute() or not absolute_path.anchor:
        raise ValueError("Python source directory path must be absolute")
    flags = _safe_source_open_flags(directory=True)
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
            raise ValueError("Python source parent is not a directory")
        result = directory_fd
        directory_fd = None
        return result
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(
            "Python source path contains an unsafe component"
        ) from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _hash_regular_file_at(
    directory_fd: int,
    entry: _DirectoryEntrySnapshot,
) -> str:
    """通过 O_NOFOLLOW 目录描述符哈希普通文件。"""
    (
        name,
        _kind,
        expected_dev,
        expected_ino,
        expected_mode,
        expected_size,
        expected_mtime_ns,
        expected_ctime_ns,
    ) = entry
    flags = _safe_source_open_flags(directory=False)
    try:
        file_fd = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise ValueError(
            "Python source file cannot be opened safely"
        ) from exc
    try:
        before = os.fstat(file_fd)
        expected_identity = (
            expected_dev,
            expected_ino,
            expected_mode,
            expected_size,
            expected_mtime_ns,
            expected_ctime_ns,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or _stable_stat_identity(before) != expected_identity
        ):
            raise ValueError(
                "Python source file changed during traversal"
            )
        digest = hashlib.sha256()
        while True:
            block = os.read(file_fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(file_fd)
        if _stable_stat_identity(after) != expected_identity:
            raise ValueError(
                "Python source file changed while hashing"
            )
        return digest.hexdigest()
    except OSError as exc:
        raise ValueError("Python source file cannot be read safely") from exc
    finally:
        os.close(file_fd)


def _hash_python_source_directory(
    directory_fd: int,
    prefix: Tuple[str, ...],
    hashes: Dict[str, str],
) -> None:
    """遍历已打开目录并检测条目集合变化。"""
    before_directory = os.fstat(directory_fd)
    if not stat.S_ISDIR(before_directory.st_mode):
        raise ValueError("Python source directory is not a directory")
    entries = _scan_directory_snapshot(directory_fd)
    for entry in entries:
        name, kind = entry[0], entry[1]
        relative_parts = (*prefix, name)
        if kind == "directory":
            flags = _safe_source_open_flags(directory=True)
            try:
                child_fd = os.open(
                    name,
                    flags,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ValueError(
                    "Python source directory cannot be opened safely"
                ) from exc
            try:
                child_stat = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(child_stat.st_mode)
                    or child_stat.st_dev != entry[2]
                    or child_stat.st_ino != entry[3]
                ):
                    raise ValueError(
                        "Python source directory changed during traversal"
                    )
                _hash_python_source_directory(
                    child_fd,
                    relative_parts,
                    hashes,
                )
            finally:
                os.close(child_fd)
        elif name.endswith(".py"):
            relative_path = "/".join(relative_parts)
            if relative_path in hashes:
                raise ValueError(
                    "Python source tree contains duplicate paths"
                )
            hashes[relative_path] = _hash_regular_file_at(
                directory_fd,
                entry,
            )
    after_entries = _scan_directory_snapshot(directory_fd)
    after_directory = os.fstat(directory_fd)
    if (
        entries != after_entries
        or _stable_stat_identity(before_directory)
        != _stable_stat_identity(after_directory)
    ):
        raise ValueError(
            "Python source directory changed during traversal"
        )


def _collect_python_source_identities(
    directory_fd: int,
    prefix: Tuple[str, ...],
    identities: Dict[Tuple[int, int], str],
) -> None:
    """收集 Python 文件身份，并拒绝同一 inode 的多路径别名。"""
    before_directory = os.fstat(directory_fd)
    entries = _scan_directory_snapshot(directory_fd)
    for entry in entries:
        name, kind = entry[0], entry[1]
        relative_parts = (*prefix, name)
        if kind == "directory":
            try:
                child_fd = os.open(
                    name,
                    _safe_source_open_flags(directory=True),
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise ValueError(
                    "Python source directory cannot be opened safely"
                ) from exc
            try:
                child_stat = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(child_stat.st_mode)
                    or child_stat.st_dev != entry[2]
                    or child_stat.st_ino != entry[3]
                ):
                    raise ValueError(
                        "Python source directory changed during traversal"
                    )
                _collect_python_source_identities(
                    child_fd,
                    relative_parts,
                    identities,
                )
            finally:
                os.close(child_fd)
        elif name.endswith(".py"):
            relative_path = "/".join(relative_parts)
            identity = (entry[2], entry[3])
            previous_path = identities.get(identity)
            if previous_path is not None and previous_path != relative_path:
                raise ValueError(
                    "Python source tree contains hard-linked files"
                )
            identities[identity] = relative_path
    after_entries = _scan_directory_snapshot(directory_fd)
    after_directory = os.fstat(directory_fd)
    if (
        entries != after_entries
        or _stable_stat_identity(before_directory)
        != _stable_stat_identity(after_directory)
    ):
        raise ValueError(
            "Python source directory changed during traversal"
        )


def hash_python_source_tree(source_root: Path) -> Dict[str, str]:
    """通过可检测变化的描述符遍历哈希全部 Python 源码。"""
    root = _absolute_source_path(Path(source_root))
    if root == Path(root.anchor) or not root.name:
        raise ValueError("Python source root must name a directory")
    flags = _safe_source_open_flags(directory=True)
    parent_fd: Optional[int] = None
    root_fd: Optional[int] = None
    live_parent_fd: Optional[int] = None
    try:
        parent_fd = _open_source_directory_without_symlinks(root.parent)
        parent_before = os.fstat(parent_fd)
        expected_root = os.stat(
            root.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if stat.S_ISLNK(expected_root.st_mode) or not stat.S_ISDIR(
            expected_root.st_mode
        ):
            raise ValueError(
                "Python source root must be a non-symlink directory"
            )
        root_fd = os.open(root.name, flags, dir_fd=parent_fd)
        opened_root = os.fstat(root_fd)
        expected_identity = _stable_stat_identity(expected_root)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or _stable_stat_identity(opened_root) != expected_identity
        ):
            raise ValueError(
                "Python source root changed during traversal"
            )
        first_hashes: Dict[str, str] = {}
        _hash_python_source_directory(root_fd, (), first_hashes)
        if not first_hashes:
            raise ValueError("Python source tree is empty")
        identities: Dict[Tuple[int, int], str] = {}
        _collect_python_source_identities(root_fd, (), identities)
        second_hashes: Dict[str, str] = {}
        _hash_python_source_directory(root_fd, (), second_hashes)
        if first_hashes != second_hashes:
            raise ValueError(
                "Python source tree changed after traversal"
            )
        opened_after = os.fstat(root_fd)
        current_root = os.stat(
            root.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        parent_after = os.fstat(parent_fd)
        live_parent_fd = _open_source_directory_without_symlinks(
            root.parent
        )
        live_parent = os.fstat(live_parent_fd)
        live_root = os.stat(
            root.name,
            dir_fd=live_parent_fd,
            follow_symlinks=False,
        )
        if (
            _stable_stat_identity(opened_after) != expected_identity
            or _stable_stat_identity(current_root) != expected_identity
            or _stable_stat_identity(parent_after)
            != _stable_stat_identity(parent_before)
            or _stable_stat_identity(live_parent)
            != _stable_stat_identity(parent_before)
            or _stable_stat_identity(live_root) != expected_identity
        ):
            raise ValueError(
                "Python source root changed during traversal"
            )
        return {
            relative_path: second_hashes[relative_path]
            for relative_path in sorted(
                second_hashes,
                key=lambda value: value.encode("utf-8"),
            )
        }
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(
            "Python source root changed during traversal"
        ) from exc
    finally:
        if live_parent_fd is not None:
            os.close(live_parent_fd)
        if root_fd is not None:
            os.close(root_fd)
        if parent_fd is not None:
            os.close(parent_fd)
