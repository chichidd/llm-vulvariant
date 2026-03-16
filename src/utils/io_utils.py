"""Shared file I/O helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def read_json_file(path: Path) -> Any:
    """Read and decode JSON content from disk.

    Args:
        path: JSON file path.

    Returns:
        Decoded JSON payload.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def write_atomic_text(path: Path, content: str, newline: Optional[str] = None) -> None:
    """Write text via a same-directory temp file and atomic replace.

    Args:
        path: Final destination path.
        content: Text payload to persist.
        newline: Optional newline mode forwarded to ``open``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Optional[Path] = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline=newline,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        temp_path.replace(path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def write_atomic_json(path: Path, payload: Any) -> None:
    """Write JSON content atomically.

    Args:
        path: Final destination path.
        payload: JSON-serializable payload.
    """
    write_atomic_text(
        path,
        json.dumps(payload, indent=2, ensure_ascii=False),
    )
