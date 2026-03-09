"""Shared CLI helpers."""

from __future__ import annotations

from collections.abc import Callable
import logging
import sys

from utils.logger import set_global_log_level


def setup_logging(verbose: bool = False) -> None:
    """Configure consistent stderr logging for CLI entrypoints.

    Args:
        verbose: Whether to enable debug-level logs.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    set_global_log_level(level)


def import_setup_logging() -> Callable[[bool], None]:
    """Return ``setup_logging`` for direct-script import fallbacks."""
    return setup_logging
