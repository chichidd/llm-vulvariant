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
    从配置文件加载路径配置
    
    Args:
        config_path: 配置文件路径，如果未提供则使用默认路径
        
    Returns:
        包含路径配置的字典
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
            # 使用默认值
            pass
    except Exception as e:
        # 如果加载失败，使用默认值
        pass
    
    # 默认值
    project_root = Path.home() / "vuln"
    return {
        'project_root': project_root,
        'data_base_path': project_root / "data",
        'vuln_data_path': project_root / "data" / "vuln.json",
        'repo_base_path': project_root / "data" / "repos",
        'codeql_db_path': project_root / "codeql_dbs",
    }


_path_config = load_paths_config()
