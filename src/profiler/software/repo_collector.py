"""Repository information collector."""

import fnmatch
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from utils.logger import get_logger
from utils.text_utils import clean_readme_for_llm
from .models import DEFAULT_FILE_EXTENSIONS, EXTENSION_MAPPING, normalize_file_extensions

logger = get_logger(__name__)


class RepoInfoCollector:
    """Collect basic repository information and file lists."""
    
    def __init__(
        self,
        file_extensions: List[str] = None,
        exclude_dirs: List[str] = None,
        readme_files: List[str] = None,
        dependency_files: List[str] = None,
    ):
        self.file_extensions = normalize_file_extensions(file_extensions or DEFAULT_FILE_EXTENSIONS)
        self.exclude_dirs = list(exclude_dirs or [
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
    
    def collect(self, repo_path: Path) -> Dict[str, Any]:
        """
        Collect repository information.
        
        Returns:
            A dict containing:
            - files: List of file paths
            - file_count: Total number of files
            - languages: Detected programming languages
            - readme_content: README content
            - dependencies: Dependency list
            - config_files: List of config files
        """
        logger.info(f"Collecting repo info from {repo_path}")
        
        def _should_exclude(relative_path: Path) -> bool:
            """Check whether a relative repo path should be excluded."""
            parts = relative_path.parts
            path_str = relative_path.as_posix()
            for excluded in self.exclude_dirs:
                if any(char in excluded for char in "*?[]"):
                    if fnmatch.fnmatch(path_str, excluded):
                        return True
                    if any(fnmatch.fnmatch(part, excluded) for part in parts):
                        return True
                    continue
                if excluded in parts:
                    return True
            return False
        
        info = {
            "files": [],
            "file_count": 0,
            "languages": [],
            "readme_content": "",
            "dependencies": [],
            "config_files": []
        }
        
        # Collect file list
        logger.info("Scanning files...")
        languages = defaultdict(int)
        
        for root, dirs, files in os.walk(repo_path):
            # Filter excluded directories
            dirs[:] = [
                d for d in dirs
                if not _should_exclude((Path(root) / d).relative_to(repo_path))
            ]
            
            for file in files:
                file_path = Path(root) / file
                rel_path = file_path.relative_to(repo_path)
                
                if _should_exclude(rel_path):
                    continue
                
                ext = file_path.suffix.lower()
                if ext in self.file_extensions:
                    info["files"].append(str(rel_path))
                    languages[EXTENSION_MAPPING.get(ext, "Unknown")] += 1
        
        info["file_count"] = len(info["files"])
        info["languages"] = list(languages)
        logger.info(f"Found {info['file_count']} files in {len(languages)} languages")

        # Read README
        logger.info("Reading README...")
        for readme_name in self.readme_files:
            readme_path = repo_path / readme_name
            if readme_path.exists():
                try:
                    raw_readme = readme_path.read_text(encoding="utf-8")
                    # Clean README: remove icon links and other noise
                    info["readme_content"] = clean_readme_for_llm(raw_readme, max_length=4000)
                    logger.info(f"Found README: {readme_name}")
                except Exception as e:
                    logger.warning(f"Failed to read README: {e}")
                break
        
        # Read dependency/config files
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
                    # Simple dependency extraction
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
