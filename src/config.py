"""Configuration loading and profile directory resolution helpers."""

from __future__ import annotations

from pathlib import Path
import logging
from typing import Any, Dict, Optional

import yaml

DEFAULT_SOFTWARE_PROFILE_DIRNAME = "soft"
DEFAULT_VULN_PROFILE_DIRNAME = "vuln"
DEFAULT_SCANNER_EMBEDDING_MODEL_NAME = "jinaai--jina-code-embeddings-1.5b"
logger = logging.getLogger(__name__)


def resolve_profile_base_path(profile_base_path: str | Path | None = None) -> Path:
    """Return the configured profile root or a caller-provided override.

    Args:
        profile_base_path: Optional absolute or repo-root-relative override.

    Returns:
        Resolved profile base directory.
    """
    if profile_base_path is None:
        return _path_config["profile_base_path"]
    path = Path(profile_base_path).expanduser()
    if path.is_absolute():
        return path
    return _path_config["repo_root"] / path


def resolve_software_profiles_path(
    profile_base_path: str | Path | None = None,
    software_profile_dirname: str | None = None,
) -> Path:
    """Resolve the directory containing software profiles.

    Args:
        profile_base_path: Optional profile root override.
        software_profile_dirname: Optional folder name or absolute path.

    Returns:
        Absolute path to the software profile directory.
    """
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (software_profile_dirname or DEFAULT_SOFTWARE_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname


def resolve_vuln_profiles_path(
    profile_base_path: str | Path | None = None,
    vuln_profile_dirname: str | None = None,
) -> Path:
    """Resolve the directory containing vulnerability profiles.

    Args:
        profile_base_path: Optional profile root override.
        vuln_profile_dirname: Optional folder name or absolute path.

    Returns:
        Absolute path to the vulnerability profile directory.
    """
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (vuln_profile_dirname or DEFAULT_VULN_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname


def load_paths_config(config_path: Optional[Path] = None) -> Dict[str, Path]:
    """Load path configuration from ``config/paths.yaml`` or built-in defaults.

    Args:
        config_path: Optional explicit config file path.

    Returns:
        Mapping of configured path names to resolved ``Path`` objects.
    """
    def _expand_path(value: Optional[Any], default: Any, base_dir: Optional[Path] = None) -> Path:
        raw = value if value is not None else default
        path = Path(raw).expanduser()
        if path.is_absolute() or base_dir is None:
            return path
        return (base_dir / path).expanduser()

    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "paths.yaml"

        if config_path.exists():
            config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            paths = config.get("paths", {})
            config_dir = config_path.parent
            project_root = _expand_path(paths.get("project_root"), "~/vuln", base_dir=config_dir)
            repo_root = project_root / "llm-vulvariant"
            profile_base_path = _expand_path(
                paths.get("profile_base_path"),
                project_root / "profiles",
                base_dir=project_root,
            )
            return {
                "project_root": project_root,
                "skill_path": (repo_root / ".claude" / "skills").expanduser(),
                "repo_root": repo_root.expanduser(),
                "profile_base_path": profile_base_path,
                "data_base_path": _expand_path(
                    paths.get("data_base_path"),
                    "~/vuln/data",
                    base_dir=project_root,
                ),
                "vuln_data_path": _expand_path(
                    paths.get("vuln_data_path"),
                    "~/vuln/data/vuln.json",
                    base_dir=project_root,
                ),
                "repo_base_path": _expand_path(
                    paths.get("repo_base_path"),
                    "~/vuln/data/repos",
                    base_dir=project_root,
                ),
                "codeql_db_path": _expand_path(
                    paths.get("codeql_db_path"),
                    "~/vuln/codeql_dbs",
                    base_dir=project_root,
                ),
                "embedding_model_path": _expand_path(
                    paths.get("embedding_model_path"),
                    "~/vuln/models",
                    base_dir=project_root,
                ),
            }
    except Exception as e:
        import logging

        logging.debug(f"Failed to load paths config: {e}")

    # Fall back to the repository's conventional ``~/vuln`` layout so CLI tools
    # remain usable even when the YAML file is missing or invalid.
    project_root = Path.home() / "vuln"
    repo_root = project_root / "llm-vulvariant"
    return {
        "project_root": project_root,
        "repo_root": repo_root,
        "skill_path": repo_root / ".claude" / "skills",
        "profile_base_path": project_root / "profiles",
        "data_base_path": project_root / "data",
        "vuln_data_path": project_root / "data" / "vuln.json",
        "repo_base_path": project_root / "data" / "repos",
        "codeql_db_path": project_root / "codeql_dbs",
        "embedding_model_path": project_root / "models",
    }


def load_scanner_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load scanner configuration from ``config/scanner_config.yaml``.

    Args:
        config_path: Optional explicit config file path.

    Returns:
        Scanner configuration with defaults filled in.
    """
    default_config: Dict[str, Any] = {
        "module_similarity": {
            "threshold": 0.8,
            "model_name": DEFAULT_SCANNER_EMBEDDING_MODEL_NAME,
            "device": "cpu",
        }
    }
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config" / "scanner_config.yaml"

    try:
        if config_path.exists():
            raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if isinstance(raw_config, dict):
                module_similarity = raw_config.get("module_similarity", {})
                if isinstance(module_similarity, dict):
                    default_config["module_similarity"].update(
                        {
                            key: value
                            for key, value in module_similarity.items()
                            if value is not None
                        }
                    )
    except Exception as exc:
        logger.warning("Failed to load scanner config from %s: %s", config_path, exc)

    module_similarity_config = default_config["module_similarity"]
    try:
        module_similarity_config["threshold"] = float(module_similarity_config.get("threshold", 0.8))
    except (TypeError, ValueError):
        module_similarity_config["threshold"] = 0.8
    module_similarity_config["model_name"] = str(
        module_similarity_config.get("model_name", DEFAULT_SCANNER_EMBEDDING_MODEL_NAME)
        or DEFAULT_SCANNER_EMBEDDING_MODEL_NAME
    ).strip() or DEFAULT_SCANNER_EMBEDDING_MODEL_NAME
    module_similarity_config["device"] = str(module_similarity_config.get("device", "cpu") or "cpu").strip() or "cpu"
    return default_config


_path_config = load_paths_config()
_scanner_config = load_scanner_config()
