"""Helpers for loading AI infrastructure taxonomy definitions."""

from __future__ import annotations

import importlib.util
import hashlib
from pathlib import Path
from typing import Any, Dict

from utils.logger import get_logger

logger = get_logger(__name__)


def load_ai_infra_taxonomy(skill_root: Path | None) -> Dict[str, Any]:
    """Load ``AI_INFRA_TAXONOMY`` from a skill's ``ai_infra_taxonomy.py`` module."""
    if not skill_root:
        return {}

    scripts_dir = skill_root / "scripts"
    module_path = scripts_dir / "ai_infra_taxonomy.py"
    if not module_path.exists():
        logger.warning(f"Taxonomy scripts path not found: {scripts_dir}")
        return {}

    try:
        module_name = f"ai_infra_taxonomy_{hashlib.sha1(str(module_path).encode('utf-8')).hexdigest()}"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            logger.warning(f"Failed to build taxonomy module spec: {module_path}")
            return {}
        taxonomy_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(taxonomy_mod)
        return getattr(taxonomy_mod, "AI_INFRA_TAXONOMY", {})
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(f"Failed to load ai_infra_taxonomy: {exc}")
        return {}
