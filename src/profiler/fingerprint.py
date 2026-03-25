"""Helpers for profile cache invalidation fingerprints."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable


PROFILE_FINGERPRINT_SCHEMA_VERSION = 1
UNREADABLE_FILE_HASH = "__unreadable__"


def _stable_json_dumps(data: Any) -> str:
    """Serialize data into a stable JSON string for hashing."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def stable_data_hash(data: Any) -> str:
    """Hash structured data using stable JSON serialization."""
    return hashlib.sha256(_stable_json_dumps(data).encode("utf-8")).hexdigest()


def _hash_file(path: Path) -> str:
    """Hash one source file and return a stable sentinel when it is unreadable."""
    if not path.exists():
        return ""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return UNREADABLE_FILE_HASH


def _hash_files(paths: Iterable[Path]) -> Dict[str, str]:
    """Hash a sequence of files keyed by filename for provenance tracking."""
    return {
        path.name: _hash_file(path)
        for path in paths
    }


def _llm_fingerprint(llm_client: Any) -> Dict[str, Any]:
    """Capture the effective LLM configuration that impacts profile outputs."""
    config = getattr(llm_client, "config", None)
    if config is None:
        return {}
    return {
        "provider": getattr(config, "provider", ""),
        "model": getattr(config, "model", ""),
        "base_url": getattr(config, "base_url", ""),
        "temperature": getattr(config, "temperature", None),
        "top_p": getattr(config, "top_p", None),
        "max_tokens": getattr(config, "max_tokens", None),
        "enable_thinking": getattr(config, "enable_thinking", None),
    }


def extract_profile_fingerprint(profile: Any) -> Dict[str, Any]:
    """Read the persisted profile fingerprint from profile metadata."""
    metadata: Dict[str, Any] = {}
    if isinstance(profile, dict):
        metadata = profile.get("metadata", {}) if isinstance(profile.get("metadata"), dict) else {}
    else:
        metadata = getattr(profile, "metadata", {}) if isinstance(getattr(profile, "metadata", {}), dict) else {}
    fingerprint = metadata.get("profile_fingerprint", {})
    return fingerprint if isinstance(fingerprint, dict) else {}


def profile_fingerprint_field_matches(
    profile: Any,
    expected_fingerprint: Dict[str, Any],
    field_name: str = "hash",
) -> bool:
    """Check whether one persisted fingerprint field matches the expected value."""
    existing_fingerprint = extract_profile_fingerprint(profile)
    existing_hash = str(existing_fingerprint.get(field_name, "")).strip()
    expected_hash = str(expected_fingerprint.get(field_name, "")).strip()
    return bool(existing_hash) and bool(expected_hash) and existing_hash == expected_hash


def profile_fingerprint_matches(profile: Any, expected_fingerprint: Dict[str, Any]) -> bool:
    """Check whether a persisted profile matches the current expected fingerprint."""
    return profile_fingerprint_field_matches(profile, expected_fingerprint, "hash")


def _is_repo_path_excluded(relative_path: Path, exclude_dirs: Iterable[str]) -> bool:
    """Apply the same path exclusion rules used by ``RepoInfoCollector``."""
    parts = relative_path.parts
    path_str = relative_path.as_posix()
    for excluded in exclude_dirs or []:
        if any(char in excluded for char in "*?[]"):
            if fnmatch.fnmatch(path_str, excluded):
                return True
            if any(fnmatch.fnmatch(part, excluded) for part in parts):
                return True
            continue
        if excluded in parts:
            return True
    return False


def _is_module_path_excluded(relative_path: Path, excluded_folders: Iterable[str]) -> bool:
    """Apply module-analysis folder exclusions to repo-state hashing."""
    if not excluded_folders:
        return False

    normalized_path = relative_path.as_posix()
    path_parts = normalized_path.split("/")
    parent_paths = [
        Path(*relative_path.parts[:index])
        for index in range(1, len(relative_path.parts))
    ]
    for pattern in excluded_folders:
        if Path(normalized_path).match(pattern):
            return True
        if any(Path(part).match(pattern) for part in path_parts):
            return True
        if any(parent_path.match(pattern) for parent_path in parent_paths):
            return True
    return False


def _is_repo_state_file_in_scope(
    relative_path: Path,
    *,
    file_extensions: Iterable[str],
    exclude_dirs: Iterable[str],
    readme_files: Iterable[str],
    dependency_files: Iterable[str],
    module_excluded_folders: Iterable[str],
) -> bool:
    """Return whether a repo file can affect software-profile generation."""
    if _is_repo_path_excluded(relative_path, exclude_dirs):
        return False
    if _is_module_path_excluded(relative_path, module_excluded_folders):
        return False

    if len(relative_path.parts) == 1:
        if relative_path.name in set(readme_files or []):
            return True
        if relative_path.name in set(dependency_files or []):
            return True

    return relative_path.suffix.lower() in {str(ext).lower() for ext in (file_extensions or [])}


def _build_repo_state_fingerprint(
    repo_path: Path | None,
    *,
    file_extensions: Iterable[str],
    exclude_dirs: Iterable[str],
    readme_files: Iterable[str],
    dependency_files: Iterable[str],
    module_excluded_folders: Iterable[str],
) -> Dict[str, Any]:
    """Hash the current repository tree for cache validation."""
    if repo_path is None or not repo_path.exists():
        return {
            "hash": "",
            "file_count": 0,
        }

    digest = hashlib.sha256()
    file_count = 0
    stack = [repo_path]

    while stack:
        current_dir = stack.pop()
        for child in sorted(current_dir.iterdir(), key=lambda item: item.name, reverse=True):
            if child.is_symlink():
                relative_path = child.relative_to(repo_path).as_posix()
                if not _is_repo_state_file_in_scope(
                    Path(relative_path),
                    file_extensions=file_extensions,
                    exclude_dirs=exclude_dirs,
                    readme_files=readme_files,
                    dependency_files=dependency_files,
                    module_excluded_folders=module_excluded_folders,
                ):
                    continue
                digest.update(relative_path.encode("utf-8"))
                digest.update(b"\0symlink\0")
                digest.update(os.readlink(child).encode("utf-8", errors="surrogateescape"))
                digest.update(b"\0")
                file_count += 1
                continue
            if child.is_dir():
                if _is_repo_path_excluded(child.relative_to(repo_path), exclude_dirs):
                    continue
                if _is_module_path_excluded(child.relative_to(repo_path), module_excluded_folders):
                    continue
                stack.append(child)
                continue
            relative_path = child.relative_to(repo_path)
            if not _is_repo_state_file_in_scope(
                relative_path,
                file_extensions=file_extensions,
                exclude_dirs=exclude_dirs,
                readme_files=readme_files,
                dependency_files=dependency_files,
                module_excluded_folders=module_excluded_folders,
            ):
                continue
            relative_path_str = relative_path.as_posix()
            digest.update(relative_path_str.encode("utf-8"))
            digest.update(b"\0file\0")
            digest.update(_hash_file(child).encode("utf-8"))
            digest.update(b"\0")
            file_count += 1

    return {
        "hash": digest.hexdigest(),
        "file_count": file_count,
    }


def build_software_profile_fingerprint(
    *,
    detection_rules: Dict[str, Any],
    repo_analyzer_config: Dict[str, Any],
    module_analyzer_config: Dict[str, Any],
    file_extensions: Iterable[str],
    exclude_dirs: Iterable[str],
    readme_files: Iterable[str],
    dependency_files: Iterable[str],
    llm_client: Any,
    repo_path: Path | None = None,
    repo_version: str | None = None,
) -> Dict[str, Any]:
    """Build the cache invalidation fingerprint for software profiles."""
    profiler_root = Path(__file__).resolve().parent
    src_root = profiler_root.parent
    repo_root = src_root.parent
    source_hashes = _hash_files(
        [
            profiler_root / "software" / "analyzer.py",
            profiler_root / "software" / "basic_info_analyzer.py",
            profiler_root / "software" / "models.py",
            profiler_root / "software" / "prompts.py",
            profiler_root / "software" / "repo_analyzer.py",
            profiler_root / "software" / "module_analyzer" / "agent.py",
            profiler_root / "software" / "module_analyzer" / "base.py",
            profiler_root / "software" / "module_analyzer" / "skill.py",
            profiler_root / "software" / "module_analyzer" / "taxonomy_loader.py",
            profiler_root / "software" / "module_analyzer" / "toolkit.py",
            src_root / "utils" / "codeql_native.py",
            repo_root / ".claude" / "skills" / "ai-infra-module-modeler" / "scripts" / "ai_infra_taxonomy.py",
            repo_root / ".claude" / "skills" / "ai-infra-module-modeler" / "scripts" / "scan_repo.py",
        ]
    )
    inputs_payload = {
        "schema_version": PROFILE_FINGERPRINT_SCHEMA_VERSION,
        "kind": "software_profile",
        "rules_hash": stable_data_hash(detection_rules or {}),
        "repo_analyzer_config_hash": stable_data_hash(repo_analyzer_config or {}),
        "module_analyzer_config_hash": stable_data_hash(module_analyzer_config or {}),
        "file_extensions": list(file_extensions or []),
        "exclude_dirs": list(exclude_dirs or []),
        "readme_files": list(readme_files or []),
        "dependency_files": list(dependency_files or []),
        "llm": _llm_fingerprint(llm_client),
        "source_hashes": source_hashes,
    }
    repo_state = _build_repo_state_fingerprint(
        repo_path,
        file_extensions=file_extensions,
        exclude_dirs=exclude_dirs,
        readme_files=readme_files,
        dependency_files=dependency_files,
        module_excluded_folders=module_analyzer_config.get("excluded_folders", []),
    )
    payload = {
        **inputs_payload,
        "repo_version": repo_version or "",
        "repo_state_hash": repo_state.get("hash", ""),
        "repo_state_file_count": repo_state.get("file_count", 0),
    }
    return {
        **payload,
        "inputs_hash": stable_data_hash(inputs_payload),
        "hash": stable_data_hash(payload),
    }


def build_vulnerability_profile_fingerprint(
    *,
    repo_profile: Any,
    vuln_entry: Any,
    llm_client: Any,
    extraction_temperature: float,
) -> Dict[str, Any]:
    """Build the cache invalidation fingerprint for vulnerability profiles."""
    profiler_root = Path(__file__).resolve().parent
    source_hashes = _hash_files(
        [
            profiler_root / "vulnerability" / "analyzer.py",
            profiler_root / "vulnerability" / "models.py",
            profiler_root / "vulnerability" / "prompts.py",
        ]
    )
    source_profile_fingerprint = extract_profile_fingerprint(repo_profile)
    source_profile_hash = str(source_profile_fingerprint.get("hash", "")).strip()
    if not source_profile_hash:
        source_profile_dict = repo_profile.to_dict() if hasattr(repo_profile, "to_dict") else repo_profile
        source_profile_hash = stable_data_hash(source_profile_dict)

    vuln_entry_dict = vuln_entry.to_dict() if hasattr(vuln_entry, "to_dict") else vuln_entry
    payload = {
        "schema_version": PROFILE_FINGERPRINT_SCHEMA_VERSION,
        "kind": "vulnerability_profile",
        "source_profile_hash": source_profile_hash,
        "vuln_entry_hash": stable_data_hash(vuln_entry_dict),
        "llm": _llm_fingerprint(llm_client),
        "extraction_temperature": extraction_temperature,
        "source_hashes": source_hashes,
    }
    return {
        **payload,
        "hash": stable_data_hash(payload),
    }
