"""仓库信息收集器"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict

from utils.logger import get_logger
from utils.text_utils import clean_readme_for_llm
from .models import EXTENSION_MAPPING

logger = get_logger(__name__)


class RepoInfoCollector:
    """收集仓库的基本信息和文件列表"""
    
    def __init__(
        self,
        file_extensions: List[str] = None,
        exclude_dirs: List[str] = None,
        readme_files: List[str] = None,
        dependency_files: List[str] = None,
    ):
        self.file_extensions = file_extensions or list(EXTENSION_MAPPING.keys())
        self.exclude_dirs = set(exclude_dirs or [
            '.git', '__pycache__', 'node_modules', '.pytest_cache', 
            '.mypy_cache', '.tox', 'venv', '.venv', 'dist', 'build',
            '.eggs', '*.egg-info'
        ])
        self.readme_files = readme_files or [
            "README.md", "README.rst", "README.txt", "README"
        ]
        self.dependency_files = dependency_files or [
            "requirements.txt", "setup.py", "pyproject.toml", 
            "Pipfile", "poetry.lock", "package.json"
        ]
    
    def collect(self, repo_path: Path, repo_name: str = None, version: str = None) -> Dict[str, Any]:
        """
        收集仓库信息
        
        Returns:
            包含以下字段的字典:
            - files: 文件路径列表
            - file_count: 文件总数
            - languages: 检测到的编程语言
            - readme_content: README内容
            - dependencies: 依赖列表
            - config_files: 配置文件列表
        """
        logger.info(f"Collecting repo info from {repo_path}")
        
        def _should_exclude(file_path: Path) -> bool:
            """检查是否应该排除此文件"""
            path_str = str(file_path)
            return any(excluded in path_str for excluded in self.exclude_dirs)
        
        info = {
            "files": [],
            "file_count": 0,
            "languages": [],
            "readme_content": "",
            "dependencies": [],
            "config_files": []
        }
        
        # 收集文件列表
        logger.info("Scanning files...")
        languages = defaultdict(int)
        
        for root, dirs, files in os.walk(repo_path):
            # 过滤排除的目录
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for file in files:
                file_path = Path(root) / file
                
                if _should_exclude(file_path):
                    continue
                
                ext = file_path.suffix.lower()
                if ext in self.file_extensions:
                    rel_path = file_path.relative_to(repo_path)
                    info["files"].append(str(rel_path))
                    languages[EXTENSION_MAPPING.get(ext, "Unknown")] += 1
        
        info["file_count"] = len(info["files"])
        info["languages"] = list(languages)
        logger.info(f"Found {info['file_count']} files in {len(languages)} languages")

        # 读取README
        logger.info("Reading README...")
        for readme_name in self.readme_files:
            readme_path = repo_path / readme_name
            if readme_path.exists():
                try:
                    raw_readme = readme_path.read_text(encoding="utf-8")
                    # 清理 README，移除图标链接等噪音
                    info["readme_content"] = clean_readme_for_llm(raw_readme, max_length=4000)
                    logger.info(f"Found README: {readme_name}")
                except Exception as e:
                    logger.warning(f"Failed to read README: {e}")
                break
        
        # 读取包配置
        logger.info("Reading dependency files...")
        dependencies = set()
        for config_name in self.dependency_files:
            config_path = repo_path / config_name
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding="utf-8")
                    info["config_files"].append({
                        "name": config_name,
                        "content": content
                    })
                    # 简单提取依赖
                    if config_name == "pyproject.toml":
                        dep_match = re.findall(r'"([a-zA-Z0-9_-]+)(?:[>=<].*?)?"', content)
                        dependencies.update(dep_match)
                    elif config_name == "setup.py":
                        dep_match = re.findall(r"['\"]([a-zA-Z0-9_-]+)(?:[>=<].*?)?['\"]", content)
                        dependencies.update(dep_match)
                except Exception as e:
                    logger.warning(f"Failed to read {config_name}: {e}")
        
        info["dependencies"] = list(dependencies)
        logger.info(f"Found {len(dependencies)} dependencies")
        
        return info
