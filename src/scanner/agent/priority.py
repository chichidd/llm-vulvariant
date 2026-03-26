"""Module priority calculator for vulnerability scanning."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from config import _scanner_config
from scanner.similarity.retriever import (
    _embedding_only_text_similarity,
    _module_embedding_text,
    _normalize_token,
    build_text_retriever,
)
from utils.logger import get_logger

logger = get_logger(__name__)


def calculate_module_priorities(
    software_profile: Any,
    vulnerability_profile: Any,
) -> Tuple[Dict[str, int], Dict[str, str]]:
    """Calculate module priorities for one scan target.

    Args:
        software_profile: Target software profile with modules.
        vulnerability_profile: Vulnerability profile with affected modules.

    Returns:
        Tuple of module priorities and file-to-module mappings.
    """
    affected_module_names = _extract_affected_module_names(vulnerability_profile)
    logger.info("Affected modules from vulnerability profile: %s", sorted(affected_module_names))

    modules = _extract_target_modules(software_profile)
    if not modules:
        return {}, {}

    normalized_name_map = {
        _normalize_token(module["name"]): module["name"]
        for module in modules
        if module["name"]
    }
    normalized_affected_module_names = {
        _normalize_token(name)
        for name in affected_module_names
    }
    direct_priority_one_modules = {
        module["name"]
        for module in modules
        if _normalize_token(module["name"]) in normalized_affected_module_names
    }
    promoted_priority_one_modules = _find_embedding_similar_modules(
        modules,
        affected_module_names,
        direct_priority_one_modules,
    )
    priority_one_modules = direct_priority_one_modules | promoted_priority_one_modules

    for module in modules:
        module["calls"] = {
            normalized_name_map.get(_normalize_token(name), name)
            for name in module["calls"]
            if name
        }
        module["called_by"] = {
            normalized_name_map.get(_normalize_token(name), name)
            for name in module["called_by"]
            if name
        }

    module_priorities: Dict[str, int] = {}
    file_to_module: Dict[str, str] = {}
    for module in modules:
        name = module["name"]
        if name in priority_one_modules:
            priority = 1
        elif _is_related_to_priority_one(module, priority_one_modules):
            priority = 2
        else:
            priority = 3
        module_priorities[name] = priority
        for file_path in module["files"]:
            file_to_module[file_path] = name

    logger.info(
        "Module priorities: %s priority-1, %s priority-2, %s priority-3",
        sum(1 for priority in module_priorities.values() if priority == 1),
        sum(1 for priority in module_priorities.values() if priority == 2),
        sum(1 for priority in module_priorities.values() if priority == 3),
    )
    logger.info("Total files mapped: %s", len(file_to_module))
    return module_priorities, file_to_module


def _extract_affected_module_names(vulnerability_profile: Any) -> Set[str]:
    """Extract affected module names from a vulnerability profile."""
    affected_modules = getattr(vulnerability_profile, "affected_modules", {}) or {}
    if isinstance(affected_modules, dict):
        raw_names = affected_modules.values()
    elif isinstance(affected_modules, list):
        raw_names = affected_modules
    else:
        raw_names = []
    return {
        str(module_name).strip()
        for module_name in raw_names
        if str(module_name).strip()
    }


def _extract_target_modules(software_profile: Any) -> List[Dict[str, Any]]:
    """Normalize target module payloads for priority calculation."""
    raw_modules = []
    if hasattr(software_profile, "modules"):
        raw_modules = software_profile.modules or []
    elif isinstance(software_profile, dict):
        raw_modules = software_profile.get("modules", []) or []

    modules: List[Dict[str, Any]] = []
    for module in raw_modules:
        if hasattr(module, "to_dict"):
            module_data = module.to_dict()
        elif isinstance(module, dict):
            module_data = module
        elif hasattr(module, "name"):
            module_data = {
                "name": getattr(module, "name", ""),
                "files": getattr(module, "files", []) or [],
                "calls_modules": getattr(module, "calls_modules", []) or [],
                "called_by_modules": getattr(module, "called_by_modules", []) or [],
                "category": getattr(module, "category", "") or "",
                "description": getattr(module, "description", "") or "",
            }
        else:
            continue

        name = str(module_data.get("name", "") or "").strip()
        if not name:
            continue

        modules.append(
            {
                "name": name,
                "files": list(module_data.get("files", []) or []),
                "calls": set(module_data.get("calls_modules", []) or []),
                "called_by": set(module_data.get("called_by_modules", []) or []),
                "embedding_text": _module_embedding_text(module_data),
            }
        )
    return modules


def _find_embedding_similar_modules(
    modules: List[Dict[str, Any]],
    affected_module_names: Set[str],
    direct_priority_one_modules: Set[str],
) -> Set[str]:
    """Promote target modules whose semantic similarity exceeds the configured threshold."""
    module_similarity_config = _scanner_config.get("module_similarity", {})
    if not isinstance(module_similarity_config, dict):
        module_similarity_config = {}

    try:
        threshold = float(module_similarity_config.get("threshold", 0.8))
    except (TypeError, ValueError):
        threshold = 0.8

    if threshold <= 0.0 or not affected_module_names:
        return set()

    retriever = build_text_retriever(
        model_name=str(module_similarity_config.get("model_name", "") or "").strip() or None,
        device=str(module_similarity_config.get("device", "cpu") or "cpu").strip() or "cpu",
    )
    if retriever is None:
        return set()

    promoted_modules: Set[str] = set()
    for module in modules:
        module_name = module["name"]
        if module_name in direct_priority_one_modules:
            continue

        best_score = 0.0
        for affected_module_name in affected_module_names:
            best_score = max(
                best_score,
                _embedding_only_text_similarity(
                    affected_module_name,
                    module["embedding_text"],
                    text_retriever=retriever,
                ),
            )
        if best_score >= threshold:
            promoted_modules.add(module_name)
            logger.info(
                "Promoted module %s to priority-1 via embedding similarity score %.4f",
                module_name,
                best_score,
            )
    return promoted_modules


def _is_related_to_priority_one(module: Dict[str, Any], priority_one_modules: Set[str]) -> bool:
    """Return whether the module calls or is called by a priority-1 module."""
    return bool((module.get("calls", set()) & priority_one_modules) or (module.get("called_by", set()) & priority_one_modules))
