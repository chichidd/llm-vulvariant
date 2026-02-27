"""Shared CLI helpers."""

import logging
import sys

from utils.logger import set_global_log_level


def setup_logging(verbose: bool = False) -> None:
    """Configure logging output for CLI entrypoints."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    set_global_log_level(level)
