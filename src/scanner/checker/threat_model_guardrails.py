"""Threat-model guardrail facts extraction helpers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Dict, List, Set


DEVELOPER_LOCAL_PATH_PREFIXES = ("examples/", "scripts/", "tests/")
PUBLIC_EXPOSURE_HINTS = (
    "api",
    "endpoint",
    "request",
    "route",
    "web",
    "ui",
    "http",
    "runner",
    "remote",
    "model store",
    "import model",
    "imported model",
    "dataset artifact",
    "checkpoint artifact",
)
LOCAL_ONLY_SOURCE_HINTS = (
    "config",
    "configuration",
    "json",
    "yaml",
    "kwargs",
    "sctk_dir",
    "out_dir",
    "glm",
    "data_root",
    "output_file",
    "dist_start_cmd",
    "conda_prefix",
    "tmp_path",
    "save_dir",
    "logging_dir",
)
ARTIFACT_EXPOSURE_HINTS = (
    "dataset",
    "checkpoint",
    "cache_file",
    "probs_cache_file",
    "hyps_cache_file",
    "input-image-path",
    ".pkl",
    ".pt",
    ".ckpt",
    ".npy",
    "model store",
    "import model",
    "imported model",
)
LOCAL_PATH_TRAVERSAL_HINTS = (
    "hydra configuration",
    "cfg[",
    "motion_file",
    "output_dir",
    "web_ui",
)
PRODUCT_CLI_SOURCE_TYPES = {
    "cli",
    "cli_argument",
    "command_line",
    "command_line_argument",
}


@dataclass(frozen=True)
class ThreatModelFacts:
    """Structured threat-model facts extracted from analysis and finding data."""

    file_path: str
    vuln_type: str
    developer_local_path: bool
    is_script_entrypoint: bool
    source_types: Set[str]
    public_exposure_hints: Set[str]
    local_only_hints: Set[str]
    artifact_exposure_hints: Set[str]
    local_path_traversal_hints: Set[str]


def _normalize_text_items(value: Any) -> List[str]:
    """Normalize list/string evidence sections into rendered strings."""
    if isinstance(value, str):
        rendered = value.strip()
        return [rendered] if rendered else []
    if not isinstance(value, list):
        return []

    normalized_items: List[str] = []
    for item in value:
        if isinstance(item, dict):
            rendered = str(
                item.get("step")
                or item.get("description")
                or item.get("summary")
                or item.get("location")
                or item.get("function")
                or ""
            ).strip()
            if not rendered:
                rendered = json.dumps(item, ensure_ascii=False, sort_keys=True)
        else:
            rendered = str(item).strip()
        if rendered:
            normalized_items.append(rendered)
    return normalized_items


def _text_contains_hint(text: str, hint: str) -> bool:
    """Match short hints conservatively to avoid substring collisions."""
    normalized_hint = hint.lower()
    if " " in normalized_hint or "-" in normalized_hint:
        return normalized_hint in text
    return bool(re.search(rf"(?<![a-z0-9_]){re.escape(normalized_hint)}(?![a-z0-9_])", text))


def extract_threat_model_facts(
    analysis: Dict[str, Any],
    vuln: Dict[str, Any],
) -> ThreatModelFacts:
    """Extract structured facts used by post-hoc threat-model guardrails."""
    file_path = str(vuln.get("file_path") or "").strip().lower()
    developer_local_path = file_path.startswith(DEVELOPER_LOCAL_PATH_PREFIXES)
    vuln_type = str(vuln.get("vulnerability_type") or "").strip().lower()

    source_analysis = analysis.get("source_analysis")
    sources_found = source_analysis.get("sources_found", []) if isinstance(source_analysis, dict) else []
    source_types = {
        str(source.get("type") or "").strip().lower()
        for source in sources_found
        if isinstance(source, dict)
    }

    evidence_parts = [file_path]
    attack_path_items: List[str] = []
    if isinstance(source_analysis, dict):
        attack_path = source_analysis.get("attack_path", []) or []
        attack_path_items = _normalize_text_items(attack_path)
        evidence_parts.extend(attack_path_items)
        if isinstance(sources_found, list):
            for source in sources_found:
                if isinstance(source, dict):
                    evidence_parts.append(str(source.get("type") or ""))
                    evidence_parts.append(str(source.get("location") or ""))

    attack_scenario = analysis.get("attack_scenario")
    if isinstance(attack_scenario, dict):
        evidence_parts.append(str(attack_scenario.get("description") or ""))
        attack_steps = attack_scenario.get("steps", []) or []
        evidence_parts.extend(_normalize_text_items(attack_steps))

    evidence_parts.extend(_normalize_text_items(analysis.get("preconditions")))
    evidence_text = " ".join(part for part in evidence_parts if part).lower()

    is_script_entrypoint = False
    if file_path.startswith("scripts/"):
        is_script_entrypoint = any(
            file_path in item.lower()
            for item in attack_path_items
        )

    return ThreatModelFacts(
        file_path=file_path,
        vuln_type=vuln_type,
        developer_local_path=developer_local_path,
        is_script_entrypoint=is_script_entrypoint,
        source_types=source_types,
        public_exposure_hints={
            hint for hint in PUBLIC_EXPOSURE_HINTS if _text_contains_hint(evidence_text, hint)
        },
        local_only_hints={
            hint for hint in LOCAL_ONLY_SOURCE_HINTS if _text_contains_hint(evidence_text, hint)
        },
        artifact_exposure_hints={
            hint for hint in ARTIFACT_EXPOSURE_HINTS if _text_contains_hint(evidence_text, hint)
        },
        local_path_traversal_hints={
            hint for hint in LOCAL_PATH_TRAVERSAL_HINTS if _text_contains_hint(evidence_text, hint)
        },
    )


def apply_threat_model_guardrails(
    analysis: Dict[str, Any],
    vuln: Dict[str, Any],
) -> Dict[str, Any]:
    """Downgrade findings that only fit developer-local workflows."""
    normalized_confidence = str(analysis.get("confidence") or "").strip().lower()
    facts = extract_threat_model_facts(analysis, vuln)

    if facts.public_exposure_hints:
        return analysis
    if facts.vuln_type in {"path_traversal", "path traversal"}:
        nonlocal_cli_output_dir_only = (
            not facts.developer_local_path
            and bool(facts.source_types & PRODUCT_CLI_SOURCE_TYPES)
            and facts.local_path_traversal_hints
            and all(hint == "output_dir" for hint in facts.local_path_traversal_hints)
        )
        if nonlocal_cli_output_dir_only:
            return analysis
        if facts.local_path_traversal_hints:
            analysis["verdict"] = "LIBRARY_RISK"
            if normalized_confidence == "high":
                analysis["confidence"] = "medium"
            rationale = str(analysis.get("verdict_rationale") or "").strip()
            downgrade_note = (
                "Threat-model guardrail: this path traversal appears limited to local "
                "configuration-driven file access rather than a public product input surface."
            )
            analysis["verdict_rationale"] = f"{rationale} {downgrade_note}".strip()
            docker_verification = analysis.get("docker_verification")
            if isinstance(docker_verification, dict):
                docker_verification["verification_verdict"] = "NOT_VERIFIED"
                docker_verification["exploit_confirmed"] = False
                docker_verification["error"] = docker_verification.get("error") or downgrade_note
            return analysis
    if not facts.developer_local_path:
        return analysis
    if facts.is_script_entrypoint and facts.source_types & PRODUCT_CLI_SOURCE_TYPES:
        return analysis
    if facts.artifact_exposure_hints:
        return analysis
    if not facts.local_only_hints:
        return analysis

    analysis["verdict"] = "LIBRARY_RISK"
    if normalized_confidence == "high":
        analysis["confidence"] = "medium"

    rationale = str(analysis.get("verdict_rationale") or "").strip()
    downgrade_note = (
        "Threat-model guardrail: this finding appears limited to developer-local-only "
        "script/example/test workflows and is downgraded from EXPLOITABLE."
    )
    analysis["verdict_rationale"] = f"{rationale} {downgrade_note}".strip()

    docker_verification = analysis.get("docker_verification")
    if isinstance(docker_verification, dict):
        docker_verification["verification_verdict"] = "NOT_VERIFIED"
        docker_verification["exploit_confirmed"] = False
        docker_verification["error"] = docker_verification.get("error") or downgrade_note

    return analysis
