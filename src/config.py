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
            return {
                'project_root': Path(paths.get('project_root', '~/vuln')).expanduser(),
                'data_base_path': Path(paths.get('data_base_path', '~/vuln/data')).expanduser(),
                'vuln_data_path': Path(paths.get('vuln_data_path', '~/vuln/data/vuln.json')).expanduser(),
                'repo_base_path': Path(paths.get('repo_base_path', '~/vuln/data/repos')).expanduser(),
                'codeql_db_path': Path(paths.get('codeql_db_path', '~/vuln/codeql_dbs')).expanduser(),
            }
        else:
            # Fall back to defaults
            pass
    except Exception as e:
        # Fall back to defaults if loading fails
        pass
    
    # Defaults
    project_root = Path.home() / "vuln"
    return {
        'project_root': project_root,
        'data_base_path': project_root / "data",
        'vuln_data_path': project_root / "data" / "vuln.json",
        'repo_base_path': project_root / "data" / "repos",
        'codeql_db_path': project_root / "codeql_dbs",
    }


_path_config = load_paths_config()
