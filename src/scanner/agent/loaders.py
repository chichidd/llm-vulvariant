"""Load persisted software and vulnerability profiles."""

import json
from pathlib import Path
from typing import Optional

from config import resolve_software_profiles_path, resolve_vuln_profiles_path
from profiler import SoftwareProfile, VulnerabilityProfile

from utils.logger import get_logger

logger = get_logger(__name__)


def load_software_profile(
    repo_name: str,
    commit_hash: str,
    base_dir: str | Path | None = None,
) -> Optional[SoftwareProfile]:
    resolved_base_dir = Path(base_dir) if base_dir is not None else resolve_software_profiles_path()
    profile_path = resolved_base_dir / repo_name / commit_hash / "software_profile.json"
    if not profile_path.exists():
        logger.error(f"Software profile not found: {profile_path}")
        return None
    try:
        with open(profile_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return SoftwareProfile.from_dict(data)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Failed to load software profile: {exc}")
        return None


def load_vulnerability_profile(
    repo_name: str,
    cve_id: str,
    base_dir: str | Path | None = None,
) -> Optional[VulnerabilityProfile]:
    resolved_base_dir = Path(base_dir) if base_dir is not None else resolve_vuln_profiles_path()
    profile_path = resolved_base_dir / repo_name / cve_id / "vulnerability_profile.json"
    if not profile_path.exists():
        logger.error(f"Vulnerability profile not found: {profile_path}")
        return None
    try:
        with open(profile_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return VulnerabilityProfile.from_dict(data)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"Failed to load vulnerability profile: {exc}")
        return None
