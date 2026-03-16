"""Shared CLI helpers."""

from __future__ import annotations

import logging
from pathlib import Path
import sys
from typing import Optional, Tuple

from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    DEFAULT_VULN_PROFILE_DIRNAME,
    resolve_profile_base_path,
    resolve_software_profiles_path,
    resolve_vuln_profiles_path,
)
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


def resolve_cli_path(path_arg: str | Path, base_dir: str | Path | None = None) -> Path:
    """Resolve one CLI path argument with optional base-directory fallback.

    Args:
        path_arg: User-provided CLI path.
        base_dir: Optional base directory for relative paths.

    Returns:
        Resolved ``Path`` with ``~`` expanded.
    """
    path = Path(path_arg).expanduser()
    if base_dir is not None and not path.is_absolute():
        return Path(base_dir) / path
    return path


def resolve_path_override(
    path_arg: str | Path | None,
    default_path: Path,
    base_dir: str | Path | None = None,
) -> Path:
    """Resolve an optional CLI override path or fall back to a default path.

    Args:
        path_arg: Optional override path from CLI args.
        default_path: Default path used when no override is provided.
        base_dir: Optional base directory for relative override paths.

    Returns:
        Resolved override path or the provided default path.
    """
    if path_arg is None:
        return default_path
    return resolve_cli_path(path_arg, base_dir=base_dir)


def resolve_profile_dirs(
    profile_base_path: str | Path | None,
    software_profile_dirname: Optional[str],
    vuln_profile_dirname: Optional[str],
) -> Tuple[Path, Path]:
    """Resolve software and vulnerability profile directories consistently.

    Args:
        profile_base_path: Optional profile base path override.
        software_profile_dirname: Optional software profile directory name.
        vuln_profile_dirname: Optional vulnerability profile directory name.

    Returns:
        A tuple of ``(software_profiles_dir, vuln_profiles_dir)``.
    """
    resolved_profile_base = resolve_profile_base_path(profile_base_path)
    soft_dirname = software_profile_dirname or DEFAULT_SOFTWARE_PROFILE_DIRNAME
    vuln_dirname = vuln_profile_dirname or DEFAULT_VULN_PROFILE_DIRNAME

    return (
        resolve_software_profiles_path(
            profile_base_path=resolved_profile_base,
            software_profile_dirname=soft_dirname,
        ),
        resolve_vuln_profiles_path(
            profile_base_path=resolved_profile_base,
            vuln_profile_dirname=vuln_dirname,
        ),
    )
