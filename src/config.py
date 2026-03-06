"""
Load the config files.
"""
from typing import Dict, Optional, Any
import yaml
from pathlib import Path

DEFAULT_SOFTWARE_PROFILE_DIRNAME = "soft"
DEFAULT_VULN_PROFILE_DIRNAME = "vuln"


def resolve_profile_base_path(profile_base_path: str | Path | None = None) -> Path:
    if profile_base_path is None:
        return _path_config["profile_base_path"]
    return Path(profile_base_path).expanduser()


def resolve_software_profiles_path(
    profile_base_path: str | Path | None = None,
    software_profile_dirname: str | None = None,
) -> Path:
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (software_profile_dirname or DEFAULT_SOFTWARE_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname


def resolve_vuln_profiles_path(
    profile_base_path: str | Path | None = None,
    vuln_profile_dirname: str | None = None,
) -> Path:
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (vuln_profile_dirname or DEFAULT_VULN_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname


def load_paths_config(config_path: Optional[Path] = None) -> Dict[str, Path]:
    """
    Load path configuration from a config file.

    Args:
        config_path: Path to the config file; uses the default path if not provided.

    Returns:
        A dict containing path configuration.
    """
    def _expand_path(value: Optional[Any], default: Any) -> Path:
        raw = value if value is not None else default
        return Path(raw).expanduser()

    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "paths.yaml"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            paths = config.get('paths', {})
            project_root = _expand_path(paths.get('project_root'), '~/vuln')
            repo_root = project_root / "llm-vulvariant"
            profile_base_path = _expand_path(paths.get('profile_base_path'), project_root / "profiles")
            return {
                'project_root': project_root,
                'skill_path': (repo_root / ".claude" / "skills").expanduser(),
                'repo_root': repo_root.expanduser(),
                'profile_base_path': profile_base_path,
                'data_base_path': _expand_path(paths.get('data_base_path'), '~/vuln/data'),
                'vuln_data_path': _expand_path(paths.get('vuln_data_path'), '~/vuln/data/vuln.json'),
                'repo_base_path': _expand_path(paths.get('repo_base_path'), '~/vuln/data/repos'),
                'codeql_db_path': _expand_path(paths.get('codeql_db_path'), '~/vuln/codeql_dbs'),
                'embedding_model_path': _expand_path(paths.get('embedding_model_path'), '~/vuln/models'),
            }
    except Exception as e:
        import logging
        logging.debug(f"Failed to load paths config: {e}")
    
    # Defaults
    project_root = Path.home() / "vuln"
    repo_root = project_root / "llm-vulvariant"
    return {
        'project_root': project_root,
        'repo_root': repo_root,
        'skill_path': repo_root / ".claude" / "skills",
        'profile_base_path': project_root / "profiles",
        'data_base_path': project_root / "data",
        'vuln_data_path': project_root / "data" / "vuln.json",
        'repo_base_path': project_root / "data" / "repos",
        'codeql_db_path': project_root / "codeql_dbs",
        'embedding_model_path': project_root / "models",
    }


_path_config = load_paths_config()
