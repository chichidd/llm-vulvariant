"""Load persisted software and vulnerability profiles."""

from __future__ import annotations

import json
from pathlib import Path

from config import resolve_software_profiles_path, resolve_vuln_profiles_path
from profiler import SoftwareProfile, VulnerabilityProfile

from utils.logger import get_logger

logger = get_logger(__name__)


def load_software_profile(
    repo_name: str,
    commit_hash: str,
    base_dir: str | Path | None = None,
) -> SoftwareProfile | None:
    """Load a persisted software profile from disk.

    Args:
        repo_name: Repository name used in the profile path layout.
        commit_hash: Commit hash subdirectory name.
        base_dir: Optional software profile root override.

    Returns:
        Parsed ``SoftwareProfile`` or ``None`` when the profile cannot be read.
    """
    resolved_base_dir = Path(base_dir) if base_dir is not None else resolve_software_profiles_path()
    profile_path = resolved_base_dir / repo_name / commit_hash / "software_profile.json"
    if not profile_path.exists():
        logger.error(f"Software profile not found: {profile_path}")
        return None
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        return SoftwareProfile.from_dict(data)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Failed to load software profile: {exc}")
        return None


def load_vulnerability_profile(
    repo_name: str,
    cve_id: str,
    base_dir: str | Path | None = None,
) -> VulnerabilityProfile | None:
    """Load a persisted vulnerability profile from disk.

    Args:
        repo_name: Repository name used in the profile path layout.
        cve_id: Vulnerability identifier subdirectory name.
        base_dir: Optional vulnerability profile root override.

    Returns:
        Parsed ``VulnerabilityProfile`` or ``None`` when the profile cannot be
        read.
    """
    resolved_base_dir = Path(base_dir) if base_dir is not None else resolve_vuln_profiles_path()
    profile_path = resolved_base_dir / repo_name / cve_id / "vulnerability_profile.json"
    if not profile_path.exists():
        logger.error(f"Vulnerability profile not found: {profile_path}")
        return None
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        return VulnerabilityProfile.from_dict(data)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Failed to load vulnerability profile: {exc}")
        return None
