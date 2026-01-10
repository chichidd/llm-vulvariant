from pathlib import Path


def to_relative_path(file_path: str, repo_path: Path) -> str:
    """transform absolute path to relative path from repo root"""
    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        return file_path