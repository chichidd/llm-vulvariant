"""Configuration loading and profile directory resolution helpers."""

from __future__ import annotations

from pathlib import Path
import hashlib
import logging
import math
import os
from typing import Any, Dict, Optional

import yaml

from config_snapshot import (
    consume_scanner_config_bytes,
    consumed_scanner_config_hashes,
    freeze_scanner_config_files,
    read_config_file_bytes,
    scanner_config_path,
)

DEFAULT_SOFTWARE_PROFILE_DIRNAME = "soft"
DEFAULT_VULN_PROFILE_DIRNAME = "vuln"
DEFAULT_SCANNER_EMBEDDING_MODEL_NAME = "jinaai--jina-code-embeddings-1.5b"
_CONFIG_REPO_ROOT = Path(__file__).resolve().parent.parent
logger = logging.getLogger(__name__)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """拒绝重复映射键的安全 YAML loader。"""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ValueError("YAML mapping keys must be strings")
        if key in mapping:
            raise ValueError(f"Duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_yaml_bytes_strict(raw_bytes: bytes) -> Any:
    """解析精确 UTF-8 YAML 字节快照并拒绝重复键。"""
    return yaml.load(raw_bytes.decode("utf-8"), Loader=_UniqueKeySafeLoader)


def _load_yaml_snapshot(
    path: Path,
    *,
    scanner_filename: Optional[str] = None,
) -> tuple[Any, str]:
    """读取、哈希并解析同一不可变 YAML 字节快照。"""
    if scanner_filename is not None:
        raw_bytes = consume_scanner_config_bytes(scanner_filename)
    elif isinstance(path, (str, os.PathLike)):
        raw_bytes = read_config_file_bytes(
            Path(path),
            label="YAML config",
        )
    else:
        # 保留现有内部单次读取抽象；默认 scanner 始终走上面的描述符安全分支。
        raw_bytes = path.read_bytes()
    if not isinstance(raw_bytes, bytes):
        raise TypeError("YAML snapshot reader must return bytes")
    parsed = _load_yaml_bytes_strict(raw_bytes)
    if scanner_filename is not None:
        verified_bytes = consume_scanner_config_bytes(scanner_filename)
        if verified_bytes != raw_bytes:
            raise ValueError(
                f"{scanner_filename} bytes changed while parsing"
            )
    return (
        parsed,
        hashlib.sha256(raw_bytes).hexdigest(),
    )

def resolve_profile_base_path(profile_base_path: str | Path | None = None) -> Path:
    """Return the configured profile root or a caller-provided override.

    Args:
        profile_base_path: Optional absolute or repo-root-relative override.

    Returns:
        Resolved profile base directory.
    """
    if profile_base_path is None:
        return _path_config["profile_base_path"]
    path = Path(profile_base_path).expanduser()
    if path.is_absolute():
        return path
    return _path_config["repo_root"] / path


def resolve_software_profiles_path(
    profile_base_path: str | Path | None = None,
    software_profile_dirname: str | None = None,
) -> Path:
    """Resolve the directory containing software profiles.

    Args:
        profile_base_path: Optional profile root override.
        software_profile_dirname: Optional folder name or absolute path.

    Returns:
        Absolute path to the software profile directory.
    """
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (software_profile_dirname or DEFAULT_SOFTWARE_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname


def resolve_vuln_profiles_path(
    profile_base_path: str | Path | None = None,
    vuln_profile_dirname: str | None = None,
) -> Path:
    """Resolve the directory containing vulnerability profiles.

    Args:
        profile_base_path: Optional profile root override.
        vuln_profile_dirname: Optional folder name or absolute path.

    Returns:
        Absolute path to the vulnerability profile directory.
    """
    base_path = resolve_profile_base_path(profile_base_path)
    dirname = (vuln_profile_dirname or DEFAULT_VULN_PROFILE_DIRNAME).strip()
    candidate = Path(dirname).expanduser()
    return candidate if candidate.is_absolute() else base_path / dirname



def load_paths_config(
    config_path: Optional[Path] = None,
    *,
    _snapshot: Optional[tuple[Any, str]] = None,
) -> Dict[str, Path]:
    """加载显式路径配置，不回退到父工作区。"""

    using_default_config = config_path is None
    resolved_config_path = (
        scanner_config_path("paths.yaml")
        if using_default_config
        else Path(config_path).expanduser().absolute()
    )
    if not resolved_config_path.is_file():
        raise FileNotFoundError(f"Path configuration not found: {resolved_config_path}")

    try:
        config, _ = _snapshot or _load_yaml_snapshot(
            resolved_config_path,
            scanner_filename=("paths.yaml" if using_default_config else None),
        )
    except Exception as exc:
        raise ValueError(
            f"Failed to load path configuration: {resolved_config_path}: {exc}"
        ) from exc
    if not isinstance(config, dict) or not isinstance(config.get("paths"), dict):
        raise ValueError("Path configuration must contain a paths mapping")
    paths = config["paths"]
    required_keys = {
        "project_root",
        "repo_root",
        "results_base_path",
        "profile_base_path",
        "data_base_path",
        "vuln_data_path",
        "repo_base_path",
        "codeql_db_path",
        "embedding_model_path",
    }
    missing_keys = sorted(required_keys - set(paths))
    if missing_keys:
        raise ValueError(
            "Path configuration is missing required keys: "
            + ", ".join(missing_keys)
        )

    def resolve_path(
        name: str,
        *,
        base_dir: Path,
        require_relative: bool = False,
        follow_symlinks: bool = True,
    ) -> Path:
        raw_value = paths.get(name)
        if not isinstance(raw_value, (str, Path)) or not str(raw_value).strip():
            raise ValueError(f"Path configuration value is invalid: {name}")
        text = str(raw_value).strip()
        if text.startswith("~") or "$" in text:
            raise ValueError(
                f"Implicit home/environment path aliases are forbidden: {name}"
            )
        candidate = Path(text)
        if require_relative and candidate.is_absolute():
            raise ValueError(
                f"Default path configuration value must be relative: {name}"
            )
        if not candidate.is_absolute():
            candidate = base_dir / candidate
        if follow_symlinks:
            return candidate.resolve(strict=False)
        # 模型体积较大，允许工作区内的显式入口链接到共享模型库。
        # 仍然规范化父目录组件，但保留最后路径组件的符号链接身份。
        return Path(os.path.abspath(candidate))

    config_dir = resolved_config_path.parent
    project_root = resolve_path(
        "project_root",
        base_dir=config_dir,
        require_relative=using_default_config,
    )
    if project_root == Path(project_root.anchor):
        raise ValueError("Path configuration project_root must not be filesystem root")
    repo_root = resolve_path(
        "repo_root",
        base_dir=config_dir,
        require_relative=using_default_config,
    )
    if using_default_config:
        expected_repo_root = _CONFIG_REPO_ROOT
        expected_revision_root = expected_repo_root.parents[1]
        if project_root != expected_revision_root:
            raise ValueError(
                "Default path configuration project_root does not identify "
                "this revision root"
            )
        if repo_root != expected_repo_root:
            raise ValueError(
                "Default path configuration repo_root does not identify this checkout"
            )

    resolved = {
        "project_root": project_root,
        "repo_root": repo_root,
        "results_base_path": resolve_path(
            "results_base_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "skill_path": (repo_root / ".claude" / "skills").resolve(strict=False),
        "profile_base_path": resolve_path(
            "profile_base_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "data_base_path": resolve_path(
            "data_base_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "vuln_data_path": resolve_path(
            "vuln_data_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "repo_base_path": resolve_path(
            "repo_base_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "codeql_db_path": resolve_path(
            "codeql_db_path",
            base_dir=project_root,
            require_relative=using_default_config,
        ),
        "embedding_model_path": resolve_path(
            "embedding_model_path",
            base_dir=project_root,
            require_relative=using_default_config,
            follow_symlinks=False,
        ),
    }

    for name, path in resolved.items():
        try:
            path.relative_to(project_root)
        except ValueError as exc:
            raise ValueError(
                f"Path configuration escapes project_root: {name}"
            ) from exc
    return resolved


def load_scanner_config(
    config_path: Optional[Path] = None,
    *,
    _snapshot: Optional[tuple[Any, str]] = None,
) -> Dict[str, Any]:
    """加载 scanner 配置，证据格式错误时失败关闭。"""
    resolved_config_path = (
        scanner_config_path("scanner_config.yaml")
        if config_path is None
        else Path(config_path).expanduser().absolute()
    )
    if not resolved_config_path.is_file():
        raise FileNotFoundError(
            f"Scanner configuration not found: {resolved_config_path}"
        )
    try:
        raw_config, _ = _snapshot or _load_yaml_snapshot(
            resolved_config_path,
            scanner_filename=(
                "scanner_config.yaml" if config_path is None else None
            ),
        )
    except Exception as exc:
        raise ValueError(
            f"Failed to load scanner configuration: {resolved_config_path}: {exc}"
        ) from exc
    if not isinstance(raw_config, dict):
        raise ValueError("Scanner configuration must be a mapping")
    module_similarity = raw_config.get("module_similarity")
    if not isinstance(module_similarity, dict):
        raise ValueError("Scanner configuration must contain module_similarity mapping")

    raw_threshold = module_similarity.get("threshold")
    if isinstance(raw_threshold, bool):
        raise ValueError("module_similarity.threshold must be a finite number in [0, 1]")
    try:
        threshold = float(raw_threshold)
    except (TypeError, ValueError) as exc:
        raise ValueError("module_similarity.threshold must be numeric") from exc
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("module_similarity.threshold must be a finite number in [0, 1]")
    model_name = module_similarity.get("model_name")
    device = module_similarity.get("device")
    if not isinstance(model_name, str) or not model_name.strip():
        raise ValueError("module_similarity.model_name must be a non-empty string")
    if not isinstance(device, str) or not device.strip():
        raise ValueError("module_similarity.device must be a non-empty string")
    return {
        "module_similarity": {
            "threshold": threshold,
            "model_name": model_name.strip(),
            "device": device.strip(),
        }
    }


freeze_scanner_config_files()
_path_config_snapshot = _load_yaml_snapshot(
    scanner_config_path("paths.yaml"),
    scanner_filename="paths.yaml",
)
_scanner_config_snapshot = _load_yaml_snapshot(
    scanner_config_path("scanner_config.yaml"),
    scanner_filename="scanner_config.yaml",
)
_path_config = load_paths_config(_snapshot=_path_config_snapshot)
_scanner_config = load_scanner_config(_snapshot=_scanner_config_snapshot)
_config_snapshot_hashes = consumed_scanner_config_hashes()
