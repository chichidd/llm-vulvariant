"""Load persisted software and vulnerability profiles."""

import json
from pathlib import Path
from typing import Optional

from profiler import SoftwareProfile, VulnerabilityProfile

from utils.logger import get_logger

logger = get_logger(__name__)


def load_software_profile(
    repo_name: str, commit_hash: str, base_dir: str = "repo-profiles"
) -> Optional[SoftwareProfile]:
    profile_path = Path(base_dir) / repo_name / commit_hash / "software_profile.json"
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
    repo_name: str,  cve_id: str, base_dir: str ="vuln-profiles"
) -> Optional[VulnerabilityProfile]:
    profile_path = Path(base_dir) / repo_name /  cve_id / "vulnerability_profile.json"
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
