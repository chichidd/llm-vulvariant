"""
Load the config files.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os
import yaml
from pathlib import Path


def load_paths_config(config_path: Optional[Path] = None) -> Dict[str, Path]:
    """
    Load path configuration from a config file.

    Args:
        config_path: Path to the config file; uses the default path if not provided.

    Returns:
        A dict containing path configuration.
    """
    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "paths.yaml"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            paths = config.get('paths', {})
            project_root = Path(paths.get('project_root', '~/vuln'))
            repo_root = project_root / "llm-vulvariant"
            return {
                'project_root': project_root.expanduser(),
                'skill_path': (repo_root / ".claude" / "skills").expanduser(),
                'repo_root': repo_root.expanduser(),
                'data_base_path': Path(paths.get('data_base_path', '~/vuln/data')).expanduser(),
                'vuln_data_path': Path(paths.get('vuln_data_path', '~/vuln/data/vuln.json')).expanduser(),
                'repo_base_path': Path(paths.get('repo_base_path', '~/vuln/data/repos')).expanduser(),
                'codeql_db_path': Path(paths.get('codeql_db_path', '~/vuln/codeql_dbs')).expanduser(),
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
        'data_base_path': project_root / "data",
        'vuln_data_path': project_root / "data" / "vuln.json",
        'repo_base_path': project_root / "data" / "repos",
        'codeql_db_path': project_root / "codeql_dbs",
        
    }


_path_config = load_paths_config()
