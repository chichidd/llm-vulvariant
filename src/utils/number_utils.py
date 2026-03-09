"""Shared numeric coercion helpers."""

from __future__ import annotations

from typing import Any


def to_int(value: Any) -> int:
    """Convert ``value`` to ``int`` with a safe zero fallback."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def to_float(value: Any) -> float:
    """Convert ``value`` to ``float`` with a safe zero fallback."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
