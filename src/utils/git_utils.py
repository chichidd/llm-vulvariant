"""
Git diff utilities for analyzing code changes between commits
"""
import subprocess
from typing import Optional
from .logger import get_logger

logger = get_logger(__name__)


def _is_ignorable_cleanliness_path(path: str) -> bool:
    """
    Return True when the git-status path is a known transient artifact that
    should not fail repository cleanliness checks.
    """
    normalized = (path or "").strip()
    if not normalized:
        return False

    # Rename output format: "old/path -> new/path"
    if " -> " in normalized:
        normalized = normalized.split(" -> ", 1)[1].strip()

    normalized = normalized.strip('"').replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]

    return (
        normalized == "_codeql_detected_source_root"
        or normalized == "_codeql_build_dir"
        or normalized.startswith("_codeql_build_dir/")
    )


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
        subprocess.run(
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


def get_git_branch(repo_path: str) -> Optional[str]:
    """
    Get current branch name if HEAD points to a local branch.

    Returns None when repository is in detached HEAD state.
    """
    try:
        result = subprocess.run(
            ['git', 'symbolic-ref', '--quiet', '--short', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        branch = result.stdout.strip()
        return branch or None
    except subprocess.CalledProcessError:
        return None
    except Exception as e:
        logger.info(f"Unexpected error while reading branch: {e}")
        return None


def get_git_restore_target(repo_path: str) -> Optional[str]:
    """
    Get a stable restore target for current git position.

    Priority:
    1. Current branch name (if not detached)
    2. Current commit hash
    """
    branch = get_git_branch(repo_path)
    if branch:
        return branch
    return get_git_commit(repo_path)


def restore_git_position(repo_path: str, restore_target: str) -> bool:
    """
    Restore repository to a previously recorded target (branch or commit hash).
    """
    if not restore_target:
        logger.info("Restore target is empty")
        return False
    try:
        subprocess.run(
            ['git', 'checkout', restore_target],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info(f"Restored repository to: {restore_target}")
        return True
    except subprocess.CalledProcessError as e:
        logger.info(f"Restore failed for target {restore_target}: {e.stderr}")
        return False
    except Exception as e:
        logger.info(f"Error while restoring target {restore_target}: {e}")
        return False


def has_uncommitted_changes(repo_path: str, include_untracked: bool = True) -> bool:
    """
    Return True when repository has local modifications.
    """
    args = ['git', 'status', '--porcelain']
    if not include_untracked:
        args.append('--untracked-files=no')
    try:
        result = subprocess.run(
            args,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        for raw_line in result.stdout.splitlines():
            line = raw_line.rstrip()
            if not line:
                continue

            # Porcelain v1 format: XY<space><path>
            path = line[3:] if len(line) >= 4 else line
            if _is_ignorable_cleanliness_path(path):
                continue
            return True
        return False
    except Exception as e:
        logger.info(f"Failed to check repository cleanliness: {e}")
        return False
