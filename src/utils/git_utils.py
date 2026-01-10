"""
Git diff utilities for analyzing code changes between commits
"""
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from .logger import get_logger

logger = get_logger(__name__)


def get_git_commit(repo_path: str) -> Optional[str]:
    """
    Get the current commit hash of a git repository.
    
    Args:
        repo_path: Path to the git repository
        
    Returns:
        The commit hash as a string, or None if the operation fails
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except FileNotFoundError:
        logger.info("Git is not installed or not found in PATH")
        return None
    except subprocess.CalledProcessError as e:
        logger.info(f"Git command failed: {e.stderr}")
        return None
    except Exception as e:
        logger.info(f"Unexpected error: {e}")
        return None


def checkout_commit(repo_path: str, target_commit: str) -> bool:
    """
    Check if repository is at target commit, and checkout if different.
    
    Args:
    repo_path: Path to the git repository
    target_commit: The commit hash to checkout
    
    Returns:
    True if successful, False otherwise
    """
    try:
        current_commit = get_git_commit(repo_path)
        if current_commit is None:
            logger.info("Failed to get current commit")
            return False
        
        if current_commit == target_commit:
            logger.info(f"Already at commit {target_commit}")
            return True
        
        logger.info(f"Checking out commit {target_commit}...")
        result = subprocess.run(
            ['git', 'checkout', target_commit],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"Successfully checked out {target_commit}")
        return True
    
    except subprocess.CalledProcessError as e:
        logger.info(f"Git checkout failed: {e.stderr}")
        return False
    except Exception as e:
        logger.info(f"Unexpected error during checkout: {e}")
        return False


def restore_to_latest_commit(repo_path: str) -> bool:
    """
    将仓库恢复到最新commit（切回之前的分支/commit位置）。
    
    使用 git checkout - 命令切换回上一次所在的分支或commit。
    
    Args:
        repo_path: Git 仓库路径
    
    Returns:
        True 表示成功，False 表示失败
    """
    try:
        result = subprocess.run(
            ['git', 'checkout', '-'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        current_commit = get_git_commit(repo_path)
        logger.info(f"已恢复到之前的位置，当前 commit: {current_commit}")
        return True
    except subprocess.CalledProcessError as e:
        logger.info(f"恢复失败: {e.stderr}")
        return False
    except Exception as e:
        logger.info(f"恢复时发生错误: {e}")
        return False


def get_changed_files(repo_path: str, commit1: str, commit2: str = "HEAD") -> List[str]:
    """
    Get list of changed files between two commits
    
    Args:
        repo_path: Path to the repository
        commit1: First commit hash (older)
        commit2: Second commit hash (newer, default: HEAD)
        
    Returns:
        List of file paths that changed
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", commit1, commit2],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return [f for f in result.stdout.strip().split('\n') if f]
        return []
    except Exception as e:
        logger.error(f"Failed to get changed files: {e}")
        return []


def get_file_diff(repo_path: str, file_path: str, commit1: str, commit2: str = "HEAD") -> Optional[str]:
    """
    Get diff for a specific file between two commits
    
    Args:
        repo_path: Path to repository
        file_path: Relative path to file in repo
        commit1: First commit
        commit2: Second commit
        
    Returns:
        Diff text for the specific file
    """
    try:
        result = subprocess.run(
            ["git", "diff", commit1, commit2, "--", file_path],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception as e:
        logger.error(f"Failed to get file diff for {file_path}: {e}")
        return None


def get_diff_stats(repo_path: str, commit1: str, commit2: str = "HEAD") -> Optional[str]:
    """
    Get diff statistics (insertions/deletions summary)
    
    Args:
        repo_path: Path to repository
        commit1: First commit
        commit2: Second commit
        
    Returns:
        Diff statistics as a string
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--stat", commit1, commit2],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception as e:
        logger.error(f"Failed to get diff stats: {e}")
        return None


def get_full_diff(repo_path: str, commit1: str, commit2: str = "HEAD") -> Optional[str]:
    """
    Get full git diff between two commits
    
    Args:
        repo_path: Path to repository
        commit1: First commit hash
        commit2: Second commit hash
        
    Returns:
        Full diff text or None if error
    """
    try:
        result = subprocess.run(
            ["git", "diff", commit1, commit2],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception as e:
        logger.error(f"Failed to get full diff: {e}")
        return None


def categorize_changed_files(changed_files: List[str]) -> Dict[str, List[str]]:
    """
    Categorize changed files by type
    
    Args:
        changed_files: List of file paths
        
    Returns:
        Dictionary with categories as keys and file lists as values
    """
    categories = {
        'added': [],
        'modified': [],
        'deleted': [],
        'python': [],
        'test': [],
        'config': [],
        'docs': [],
        'other': []
    }
    
    for file_path in changed_files:
        # Categorize by file extension/type
        if file_path.endswith('.py'):
            categories['python'].append(file_path)
            if 'test' in file_path.lower():
                categories['test'].append(file_path)
        elif file_path.endswith(('.md', '.rst', '.txt')):
            categories['docs'].append(file_path)
        elif file_path.endswith(('.json', '.yaml', '.yml', '.toml', '.cfg', '.ini')):
            categories['config'].append(file_path)
        else:
            categories['other'].append(file_path)
    
    return categories


def get_changed_files_with_status(repo_path: str, commit1: str, commit2: str = "HEAD") -> List[Tuple[str, str]]:
    """
    Get changed files with their change status (Added, Modified, Deleted, etc.)
    
    Args:
        repo_path: Path to repository
        commit1: First commit
        commit2: Second commit
        
    Returns:
        List of tuples (status, file_path)
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-status", commit1, commit2],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            changes = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t', 1)
                    if len(parts) == 2:
                        status, file_path = parts
                        changes.append((status, file_path))
            return changes
        return []
    except Exception as e:
        logger.error(f"Failed to get changed files with status: {e}")
        return []
