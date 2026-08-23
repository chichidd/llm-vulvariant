#!/usr/bin/env python3
"""CLI wrapper for the agentic vulnerability finder.

Modes:
1) Manual mode:
   - `--target-repo` provided (optional `--target-commit`)
2) Auto-target mode:
   - `--target-repo` not provided
   - select top-k most similar software profiles automatically
"""

from __future__ import annotations

import argparse
from datetime import datetime
from functools import wraps
import hashlib
import json
import math
import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from config_snapshot import (
    consumed_scanner_config_hashes,
    immutable_consumed_scanner_config_hashes,
)
from config import (
    DEFAULT_SOFTWARE_PROFILE_DIRNAME,
    DEFAULT_VULN_PROFILE_DIRNAME,
    _path_config,
    _scanner_config,  # noqa: F401 - compatibility export used by tests and callers
)
from llm import (
    LLMConfig,
    aggregate_llm_usage_since,
    capture_llm_usage_snapshot,
    create_llm_client,
)
from profiler.fingerprint import (
    extract_profile_fingerprint,
    hash_python_source_tree,
    stable_data_hash,
)
from profiler.software.models import SoftwareProfile
from scanner.agent import AgenticVulnFinder, load_software_profile, load_vulnerability_profile
from scanner.agent.priority import resolve_module_similarity_config
from scanner.agent.shared_memory import SharedPublicMemoryManager
from scanner.agent.schedule_window import (
    FROZEN_SCHEDULE_PAGE_ALGORITHM,
    FROZEN_SCHEDULE_PAGE_SIZE,
)
from scanner.evaluation_contract import (
    EvaluationEvidenceUnavailableError,
    MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE,
    module_similarity_byte_binding,
    observed_module_similarity_metadata,
    require_evaluation_embedding_byte_binding,
    require_evaluation_response_identity_usage,
)
from scanner.output_commit import (
    SCAN_CONVERSATION_FILENAME,
    SCAN_FINDINGS_FILENAME,
    SCAN_FINGERPRINT_FILENAME,
    SCAN_MEMORY_FILENAME,
    SCAN_OUTPUT_COMMIT_FILENAME,
    SCAN_PROVENANCE_FILENAME,
    SCAN_RUN_FAILURE_FILENAME,
    SCAN_RUN_STATE_FILENAME,
    SCAN_SIMILARITY_FILENAME,
    ScanOutputCommitError,
    build_scan_output_commit,
    canonical_scan_commit,
    canonical_scan_reference_id,
    canonical_scan_repo_name,
    is_lowercase_sha256,
    read_stable_scan_artifact,
    validate_committed_scan_outputs,
)
from scanner.agent.utils import make_serializable
from scanner.similarity.embedding import (
    DEFAULT_EMBEDDING_MODEL_NAME,
    embedding_model_artifact_signature,
)
from scanner.similarity import (
    SimilarProfileCandidate,
    EmbeddingUnavailableError,
    build_text_retriever,
    load_all_software_profiles,
    rank_similar_profiles,
    resolve_profile_commit,
    select_profile_ref,
)
from utils.io_utils import write_atomic_text
from utils.git_utils import (
    checkout_commit,
    get_git_commit,
    get_git_restore_target,
    has_uncommitted_changes,
    restore_git_position,
)
from utils.language import dedupe_languages as _dedupe_languages, detect_languages as detect_repo_languages
from utils.logger import get_logger
from utils.number_utils import to_int
from utils.repo_lock import acquire_repo_lock, hold_repo_lock, release_repo_lock
try:
    from cli.common import resolve_cli_path, resolve_profile_dirs, setup_logging
except ImportError:  # pragma: no cover - direct script execution fallback
    from common import resolve_cli_path, resolve_profile_dirs, setup_logging


MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION = 2
MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM = "recursive-exact-target-path-redaction-v2"
MODEL_VISIBLE_INPUT_PROJECTION_SOURCE = "git_ls_tree_regular_blobs"
MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT = "<TARGET_PATH>"
MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY = {
    "strategy": "asymmetric-ascii-posix-suffix-boundary-v2",
    "left_blocking_characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-",
    "right_blocking_characters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~/-",
    "match_order": "longest-codepoint-count-then-utf8-bytes-ascending",
}
MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION = {
    "strategy": "recursive-json-key-and-value-projection-v2",
    "mapping_order": "raw-key-utf8-bytes-ascending",
    "collision_policy": (
        "reserve-all-projected-bases-then-smallest-hash-suffix-from-2"
    ),
    "collision_suffix_format": "{base}#{n}",
}
MODEL_VISIBLE_INPUT_PROJECTION_SCOPE = [
    "reference_semantics",
    "static_analysis_semantics",
    "generic_system_guidance",
    "other_non_policy_model_inputs",
]
MODEL_VISIBLE_INPUT_POLICY_EXCLUSIONS = [
    "candidate_priority_selected_paths",
    "unprioritized_schedule_active_page_paths",
    "method_native_candidate_paths",
]
MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS = (
    "raw_reference_sha256",
    "projected_reference_sha256",
    "raw_static_input_sha256",
    "projected_static_input_sha256",
    "invariant_projected_static_input_sha256",
    "policy_visible_static_input_sha256",
    "policy_preserved_fields",
)
MODEL_VISIBLE_INPUT_POLICY_PRESERVED_FIELDS = [
    "target_software.modules[].files",
]
ENDPOINT_SNAPSHOT_KEYS = {
    "snapshot_id",
    "base_url",
    "api_family",
}
ENDPOINT_API_FAMILIES = {
    "openai_compatible",
}
ENDPOINT_SNAPSHOT_MUTABLE_ALIASES = {
    "current",
    "default",
    "latest",
    "prod",
    "production",
    "stable",
}
MODEL_REVISION_ATTESTATION_SCHEMA_VERSION = 1
MODEL_REVISION_ATTESTATION_KIND = (
    "operator_attested_deployment_revision"
)
MODEL_REVISION_ATTESTATION_KEYS = {
    "schema_version",
    "kind",
    "provider",
    "model_name",
    "model_revision",
    "endpoint_snapshot_sha256",
}
DECODING_CONFIG_KEYS = {
    "temperature",
    "top_p",
    "max_tokens",
    "enable_thinking",
    "reasoning_effort",
    "service_tier",
}
DECODING_REASONING_EFFORT_VALUES = {
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
}
DECODING_SERVICE_TIER_VALUES = {
    "auto",
    "default",
    "flex",
    "priority",
}
logger = get_logger(__name__)
SCAN_FINGERPRINT_SCHEMA_VERSION = 1
RUN_PROVENANCE_SCHEMA_VERSION = 1
RUN_EXECUTION_STATUSES = {"running", "complete", "partial", "failed"}
REPO_STRUCTURE_ONLY_WEIGHTS = {
    "description": 0.0,
    "target_application": 0.0,
    "target_user": 0.0,
    "module_jaccard": 1.0,
    "module_dependency_import": 1.0,
}


@dataclass
class ScanTarget:
    repo_name: str
    commit_hash: str
    similarity: Optional[SimilarProfileCandidate] = None
    selection_provenance: Optional[Dict[str, Any]] = None


def normalize_ablation_config(config: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
    """返回稳定的五项消融开关结构。"""
    raw = config if isinstance(config, dict) else {}
    return {
        "repo_semantics": bool(raw.get("repo_semantics", False)),
        "reference_semantics": bool(raw.get("reference_semantics", False)),
        "candidate_priority": bool(raw.get("candidate_priority", False)),
        "memory": bool(raw.get("memory", False)),
        "verifier": bool(raw.get("verifier", False)),
    }


def ablation_config_from_args(args: argparse.Namespace) -> Dict[str, bool]:
    return normalize_ablation_config(
        {
            "repo_semantics": getattr(args, "ablate_repo_semantics", False),
            "reference_semantics": getattr(args, "ablate_reference_semantics", False),
            "candidate_priority": getattr(args, "ablate_candidate_priority", False),
            "memory": getattr(args, "ablate_memory", False),
            "verifier": getattr(args, "ablate_verifier", False),
        }
    )


def _extract_repo_analysis(software_profile) -> Dict[str, object]:
    repo_info = {}
    if hasattr(software_profile, "repo_info"):
        repo_info = getattr(software_profile, "repo_info", {}) or {}
    elif isinstance(software_profile, dict):
        repo_info = software_profile.get("repo_info", {}) or {}

    if not isinstance(repo_info, dict):
        return {}
    repo_analysis = repo_info.get("repo_analysis", {})
    return repo_analysis if isinstance(repo_analysis, dict) else {}


def _resolve_scan_languages(target_repo_path: Path, software_profile) -> List[str]:
    repo_analysis = _extract_repo_analysis(software_profile)
    profile_languages = repo_analysis.get("languages", [])
    if isinstance(profile_languages, list):
        normalized_profile_languages = _dedupe_languages(profile_languages)
        if normalized_profile_languages:
            return normalized_profile_languages

    detected_languages = _dedupe_languages(detect_repo_languages(target_repo_path))
    return detected_languages


def _resolve_codeql_database_names(
    target: ScanTarget,
    scan_languages: List[str],
    software_profile,
) -> Dict[str, str]:
    repo_analysis = _extract_repo_analysis(software_profile)
    metadata = getattr(software_profile, "metadata", {}) if hasattr(software_profile, "metadata") else {}
    if not isinstance(metadata, dict) and isinstance(software_profile, dict):
        metadata = software_profile.get("metadata", {})
    profile_repo_path = str(metadata.get("profile_repo_path", "") or "").strip() if isinstance(metadata, dict) else ""
    repo_path_hash = stable_data_hash(profile_repo_path)[:12] if profile_repo_path else ""
    codeql_languages: List[str] = []

    configured_codeql_languages = repo_analysis.get("codeql_languages", [])
    if isinstance(configured_codeql_languages, list):
        codeql_languages = _dedupe_languages(configured_codeql_languages)

    active_languages = codeql_languages or _dedupe_languages(scan_languages)
    return {
        # Match the path-sensitive CodeQL DB identity emitted during repo analysis.
        lang: (
            f"{target.repo_name}-{repo_path_hash}-{target.commit_hash[:8]}-{lang}"
            if repo_path_hash
            else f"{target.repo_name}-{target.commit_hash[:8]}-{lang}"
        )
        for lang in active_languages
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Finder")
    parser.add_argument(
        "--vuln-repo",
        type=str,
        required=True,
        help="Repository name where vulnerability profile was generated",
    )
    parser.add_argument("--cve", type=str, required=True, help="CVE or vulnerability ID")

    parser.add_argument(
        "--target-repo",
        type=str,
        default=None,
        help=(
            "Repository name to scan. If omitted, scanner automatically picks top-k "
            "similar software profiles from configured repo profiles directory."
        ),
    )
    parser.add_argument(
        "--target-commit",
        type=str,
        default=None,
        help=(
            "Target commit hash or prefix for manual mode. If omitted, scanner tries "
            "source vulnerable commit (same repo) or current/local profile commit."
        ),
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="In auto-target mode, number of most similar profiles to scan (default: 3)",
    )
    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=None,
        help=(
            "Optional minimum overall similarity for auto-target candidates. "
            "When set, only candidates with overall similarity >= threshold are kept."
        ),
    )
    parser.add_argument(
        "--include-same-repo",
        action="store_true",
        help="In auto-target mode, include profiles from the same source repository",
    )
    parser.add_argument(
        "--similarity-model-name",
        type=str,
        default=DEFAULT_EMBEDDING_MODEL_NAME,
        help="Embedding model name under paths.embedding_model_path for text similarity",
    )
    parser.add_argument(
        "--similarity-device",
        type=str,
        default="cpu",
        help="Embedding device for similarity scoring (default: cpu)",
    )
    parser.add_argument(
        "--evaluation-mode",
        "--benchmark-mode",
        dest="evaluation_mode",
        action="store_true",
        help="Require embedding-backed similarity and fail closed if the model/backend is unavailable",
    )
    parser.add_argument(
        "--ablate-repo-semantics",
        action="store_true",
        help="Exclude repository description/application/user semantics from target ranking",
    )
    parser.add_argument(
        "--ablate-candidate-priority",
        "--ablate-repo-priority",
        dest="ablate_candidate_priority",
        action="store_true",
        help=(
            "Disable candidate priority and require an externally frozen global "
            "unique file schedule"
        ),
    )
    parser.add_argument(
        "--ablate-memory",
        action="store_true",
        help="Disable shared public memory while retaining the local coverage ledger",
    )
    parser.add_argument(
        "--ablate-verifier",
        action="store_true",
        help="Disable the claim-verification prompt contract and same-type report gate",
    )

    parser.add_argument(
        "--ablate-reference-semantics",
        action="store_true",
        help="Use only the frozen opaque CWE reference card as model-visible reference context",
    )
    parser.add_argument(
        "--reference-card",
        type=str,
        default=None,
        help="Frozen reference-context envelope containing a model card and host-only priority plan",
    )
    parser.add_argument(
        "--reference-card-sha256",
        type=str,
        default=None,
        help="Expected raw SHA-256 of --reference-card",
    )
    parser.add_argument(
        "--reference-card-binding-path",
        type=str,
        default=None,
        help=(
            "Canonical workspace-relative typed-binding path for the staged "
            "--reference-card bytes"
        ),
    )
    parser.add_argument(
        "--target-path-projection",
        type=str,
        default=None,
        help=(
            "Frozen canonical target-file universe used only to redact accidental "
            "exact target paths from non-policy model inputs"
        ),
    )
    parser.add_argument(
        "--target-path-projection-sha256",
        type=str,
        default=None,
        help="Expected raw SHA-256 of --target-path-projection",
    )
    parser.add_argument(
        "--target-path-projection-binding-path",
        type=str,
        default=None,
        help=(
            "Canonical workspace-relative typed-binding path for the staged "
            "--target-path-projection bytes"
        ),
    )
    parser.add_argument(
        "--model-input-invariant-stage-sha256",
        type=str,
        default=None,
        help="Expected canonical SHA-256 of the frozen invariant preprocessing stage",
    )
    parser.add_argument(
        "--model-input-policy-stage-sha256",
        type=str,
        default=None,
        help="Expected canonical SHA-256 of the frozen policy eligibility stage",
    )
    parser.add_argument(
        "--unprioritized-file-order",
        type=str,
        default=None,
        help="Frozen seed-hash file presentation/enumeration schedule for candidate-priority ablation",
    )
    parser.add_argument(
        "--unprioritized-file-order-sha256",
        type=str,
        default=None,
        help="Expected raw SHA-256 of --unprioritized-file-order",
    )
    parser.add_argument(
        "--unprioritized-file-order-binding-path",
        type=str,
        default=None,
        help=(
            "Canonical workspace-relative typed-binding path for the staged "
            "--unprioritized-file-order bytes"
        ),
    )
    parser.add_argument(
        "--target-software-profile-sha256",
        type=str,
        default=None,
        help=(
            "Raw SHA-256 of the exact target software_profile.json bound to "
            "frozen projection and schedule controls"
        ),
    )
    parser.add_argument(
        "--shared-public-memory-dir",
        type=str,
        default=None,
        help="Run-scoped shared public memory directory",
    )

    parser.add_argument(
        "--repo-base-path",
        type=str,
        default=str(_path_config["repo_base_path"]),
        help="Base directory containing target repositories (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--profile-base-path",
        type=str,
        default=str(_path_config["profile_base_path"]),
        help="Base directory containing profile folders (default from config/paths.yaml)",
    )
    parser.add_argument(
        "--software-profile-dirname",
        type=str,
        default=DEFAULT_SOFTWARE_PROFILE_DIRNAME,
        help="Software profile directory name under --profile-base-path (default: soft)",
    )
    parser.add_argument(
        "--vuln-profile-dirname",
        type=str,
        default=DEFAULT_VULN_PROFILE_DIRNAME,
        help="Vulnerability profile directory name under --profile-base-path (default: vuln)",
    )

    parser.add_argument(
        "--llm-provider",
        type=str,
        default="deepseek",
        help="LLM provider (deepseek, openai, lab)",
    )
    parser.add_argument(
        "--llm-name",
        type=str,
        default=None,
        help="Optional model name override for the chosen provider",
    )
    parser.add_argument(
        "--llm-max-attempts",
        type=int,
        default=None,
        help=(
            "Maximum total HTTP request attempts per LLM call; when omitted, "
            "use the provider configuration"
        ),
    )
    parser.add_argument(
        "--llm-timeout-seconds",
        type=float,
        default=None,
        help=(
            "Per-request LLM timeout in seconds; when omitted, use the "
            "provider configuration"
        ),
    )
    parser.add_argument(
        "--model-revision",
        type=str,
        default=None,
        help=(
            "Exact operator-attested model revision identifier; evaluation "
            "also requires a separately frozen attestation artifact"
        ),
    )
    parser.add_argument(
        "--model-revision-attestation",
        type=str,
        default=None,
        help="Frozen operator deployment-revision attestation JSON artifact",
    )
    parser.add_argument(
        "--model-revision-attestation-sha256",
        type=str,
        default=None,
        help="Expected raw file SHA-256 of --model-revision-attestation",
    )
    parser.add_argument(
        "--model-revision-attestation-binding-path",
        type=str,
        default=None,
        help=(
            "Canonical workspace-relative path bound to the frozen "
            "model-revision attestation"
        ),
    )
    parser.add_argument(
        "--endpoint-snapshot-json",
        type=str,
        default=None,
        help=(
            "Canonical compact JSON endpoint identity with exact keys "
            "snapshot_id, base_url, and api_family"
        ),
    )
    parser.add_argument(
        "--endpoint-snapshot-sha256",
        type=str,
        default=None,
        help="SHA-256 of the canonical --endpoint-snapshot-json bytes",
    )
    parser.add_argument(
        "--decoding-config-json",
        type=str,
        default=None,
        help=(
            "Canonical compact JSON for the exact six-field evaluation "
            "decoding contract"
        ),
    )
    parser.add_argument(
        "--decoding-config-sha256",
        type=str,
        default=None,
        help="SHA-256 of the canonical --decoding-config-json bytes",
    )
    parser.add_argument("--max-iterations", type=int, default=3, help="Maximum iterations")
    parser.add_argument(
        "--stop-when-critical-complete",
        action="store_true",
        help=(
            "Enable priority-1 completion aware stopping policy. "
            "Use --critical-stop-mode to choose min/max composition."
        ),
    )
    parser.add_argument(
        "--critical-stop-mode",
        type=str,
        choices=["min", "max"],
        default="max",
        help=(
            "When --stop-when-critical-complete is enabled: "
            "min => stop at min(max-iterations, X); "
            "max => stop at max(max-iterations, X). Default: max"
        ),
    )
    parser.add_argument(
        "--critical-stop-max-priority",
        type=int,
        choices=[1, 2],
        default=2,
        help=(
            "Highest module priority included in critical-stop completion checks. "
            "1 => affected only; 2 => affected + related. Default: 2"
        ),
    )
    parser.add_argument(
        "--require-full-universe-completion",
        action="store_true",
        help=(
            "Require every item in the frozen host universe to be durably completed; "
            "--max-iterations remains a safety ceiling and incomplete runs stay partial"
        ),
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Caller-supplied run identifier bound into run provenance",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output base directory (default: revision-root results/scan-results)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def resolve_output_dir(
    cve_id: str,
    target_repo: str,
    target_commit: str,
    output_base: Optional[str | Path],
) -> Path:
    """在可信输出根下解析一个规范目标目录。"""
    reference_id = canonical_scan_reference_id(cve_id)
    repo_name = canonical_scan_repo_name(target_repo)
    commit = canonical_scan_commit(target_commit)
    output_root = (
        resolve_cli_path(output_base, base_dir=_path_config["repo_root"])
        if output_base is not None
        else _path_config["results_base_path"] / "scan-results"
    )
    return output_root / reference_id / f"{repo_name}-{commit[:12]}"


def build_shared_public_memory_visibility_scope_id(
    cve_id: str,
    target_repo: str,
    target_commit: str,
    target_output_dir: Path,
) -> str:
    """Build the stable logical scan scope id used to hide self-produced shared memory."""
    return stable_data_hash(
        {
            "cve_id": cve_id,
            "target_repo": target_repo,
            "target_commit": target_commit,
            "target_output_dir": str(target_output_dir.resolve()),
        }
    )[:16]


def _validate_args(args: argparse.Namespace) -> bool:
    try:
        args.cve = canonical_scan_reference_id(
            getattr(args, "cve", None)
        )
        args.vuln_repo = canonical_scan_repo_name(
            getattr(args, "vuln_repo", None)
        )
        if getattr(args, "target_repo", None) is not None:
            args.target_repo = canonical_scan_repo_name(args.target_repo)
        if getattr(args, "target_commit", None) is not None:
            args.target_commit = canonical_scan_commit(args.target_commit)
    except ScanOutputCommitError as exc:
        logger.error("Invalid scanner identity: %s", exc)
        return False
    if args.target_commit and not args.target_repo:
        logger.error("Manual target commits require an explicit target repository")
        return False
    if args.top_k <= 0:
        logger.error("--top-k must be >= 1")
        return False
    llm_max_attempts = getattr(args, "llm_max_attempts", None)
    if llm_max_attempts is not None and llm_max_attempts <= 0:
        logger.error("--llm-max-attempts must be >= 1")
        return False
    llm_timeout_seconds = getattr(args, "llm_timeout_seconds", None)
    if llm_timeout_seconds is not None and (
        not math.isfinite(llm_timeout_seconds) or llm_timeout_seconds <= 0
    ):
        logger.error("--llm-timeout-seconds must be a finite value > 0")
        return False
    similarity_threshold = getattr(args, "similarity_threshold", None)
    if similarity_threshold is not None and not (0.0 <= similarity_threshold <= 1.0):
        logger.error("--similarity-threshold must be between 0 and 1")
        return False
    if not str(
        getattr(args, "software_profile_dirname", DEFAULT_SOFTWARE_PROFILE_DIRNAME)
    ).strip():
        logger.error("--software-profile-dirname must not be empty")
        return False
    if not str(
        getattr(args, "vuln_profile_dirname", DEFAULT_VULN_PROFILE_DIRNAME)
    ).strip():
        logger.error("--vuln-profile-dirname must not be empty")
        return False
    reference_ablation = bool(getattr(args, "ablate_reference_semantics", False))
    reference_path = str(getattr(args, "reference_card", "") or "").strip()
    reference_sha256_value = getattr(args, "reference_card_sha256", "")
    reference_sha256 = (
        reference_sha256_value
        if isinstance(reference_sha256_value, str)
        else ""
    )
    reference_binding_path = str(
        getattr(args, "reference_card_binding_path", "") or ""
    ).strip()
    if bool(reference_path) != bool(reference_sha256):
        logger.error("--reference-card and --reference-card-sha256 must be provided together")
        return False
    if reference_binding_path and not reference_path:
        logger.error("--reference-card-binding-path requires --reference-card")
        return False
    if reference_ablation and (
        not reference_path
        or not getattr(args, "target_repo", None)
        or not getattr(args, "target_commit", None)
    ):
        logger.error(
            "--ablate-reference-semantics requires a frozen reference card and explicit --target-repo/--target-commit"
        )
        return False

    projection_path = str(
        getattr(args, "target_path_projection", "") or ""
    ).strip()
    projection_sha256_value = getattr(
        args,
        "target_path_projection_sha256",
        "",
    )
    projection_sha256 = (
        projection_sha256_value
        if isinstance(projection_sha256_value, str)
        else ""
    )
    projection_binding_path = str(
        getattr(args, "target_path_projection_binding_path", "") or ""
    ).strip()
    if bool(projection_path) != bool(projection_sha256):
        logger.error(
            "--target-path-projection and --target-path-projection-sha256 "
            "must be provided together"
        )
        return False
    if projection_binding_path and not projection_path:
        logger.error(
            "--target-path-projection-binding-path requires "
            "--target-path-projection"
        )
        return False
    if projection_path and (
        not getattr(args, "target_repo", None)
        or not getattr(args, "target_commit", None)
    ):
        logger.error(
            "--target-path-projection requires explicit --target-repo/--target-commit"
        )
        return False
    invariant_stage_sha256_value = getattr(
        args,
        "model_input_invariant_stage_sha256",
        "",
    )
    invariant_stage_sha256 = (
        invariant_stage_sha256_value
        if isinstance(invariant_stage_sha256_value, str)
        else ""
    )
    policy_stage_sha256_value = getattr(
        args,
        "model_input_policy_stage_sha256",
        "",
    )
    policy_stage_sha256 = (
        policy_stage_sha256_value
        if isinstance(policy_stage_sha256_value, str)
        else ""
    )
    if bool(invariant_stage_sha256) != bool(policy_stage_sha256):
        logger.error(
            "--model-input-invariant-stage-sha256 and "
            "--model-input-policy-stage-sha256 must be provided together"
        )
        return False
    if invariant_stage_sha256 and (
        not is_lowercase_sha256(invariant_stage_sha256)
        or invariant_stage_sha256 != invariant_stage_sha256.lower()
        or not is_lowercase_sha256(policy_stage_sha256)
        or policy_stage_sha256 != policy_stage_sha256.lower()
    ):
        logger.error("model-input stage hashes must be lowercase SHA-256 values")
        return False
    evaluation_mode = bool(getattr(args, "evaluation_mode", False))
    model_revision = getattr(args, "model_revision", None)
    if model_revision is not None and (
        not isinstance(model_revision, str)
        or not model_revision
        or model_revision != model_revision.strip()
    ):
        logger.error("--model-revision must be a non-empty exact string")
        return False
    if evaluation_mode and model_revision is None:
        logger.error(
            "--evaluation-mode requires an explicit --model-revision; aliases are insufficient"
        )
        return False
    llm_name = getattr(args, "llm_name", None)
    llm_provider = getattr(args, "llm_provider", None)
    if evaluation_mode and (
        llm_provider != "lab"
        or llm_name != "GLM-5.2"
    ):
        logger.error(
            "--evaluation-mode requires --llm-provider lab and --llm-name GLM-5.2"
        )
        return False
    if evaluation_mode and llm_max_attempts != 3:
        logger.error(
            "--evaluation-mode requires --llm-max-attempts 3"
        )
        return False
    if evaluation_mode and (
        not isinstance(llm_name, str)
        or not llm_name
        or llm_name != llm_name.strip()
    ):
        logger.error(
            "--evaluation-mode requires an explicit exact --llm-name; aliases are insufficient"
        )
        return False
    revision_attestation_path = getattr(
        args,
        "model_revision_attestation",
        None,
    )
    revision_attestation_sha256 = getattr(
        args,
        "model_revision_attestation_sha256",
        None,
    )
    revision_attestation_binding_path = getattr(
        args,
        "model_revision_attestation_binding_path",
        None,
    )
    revision_attestation_present = (
        revision_attestation_path is not None,
        revision_attestation_sha256 is not None,
        revision_attestation_binding_path is not None,
    )
    if any(revision_attestation_present) and not all(
        revision_attestation_present
    ):
        logger.error(
            "--model-revision-attestation, its SHA-256, and its "
            "binding path must be provided together"
        )
        return False
    if revision_attestation_path is not None:
        if not is_lowercase_sha256(revision_attestation_sha256):
            logger.error(
                "model-revision attestation file SHA-256 must be exact lowercase hex"
            )
            return False
        if (
            _portable_frozen_artifact_locator(
                revision_attestation_binding_path
            )
            != revision_attestation_binding_path
        ):
            logger.error(
                "model-revision attestation binding path must be canonical "
                "workspace-relative POSIX"
            )
            return False
    if evaluation_mode and revision_attestation_path is None:
        logger.error(
            "--evaluation-mode requires a frozen operator model-revision attestation"
        )
        return False
    endpoint_snapshot_json = getattr(args, "endpoint_snapshot_json", None)
    endpoint_snapshot_sha256 = getattr(args, "endpoint_snapshot_sha256", None)
    validated_endpoint_snapshot: Optional[Dict[str, str]] = None
    if (endpoint_snapshot_json is None) != (endpoint_snapshot_sha256 is None):
        logger.error(
            "--endpoint-snapshot-json and --endpoint-snapshot-sha256 must be provided together"
        )
        return False
    if endpoint_snapshot_json is not None:
        try:
            validated_endpoint_snapshot, _ = validate_endpoint_snapshot_contract(
                endpoint_snapshot_json,
                endpoint_snapshot_sha256,
            )
        except ValueError as exc:
            logger.error("Invalid endpoint snapshot contract: %s", exc)
            return False
    if evaluation_mode and endpoint_snapshot_json is None:
        logger.error(
            "--evaluation-mode requires an explicit immutable endpoint snapshot"
        )
        return False
    if evaluation_mode and (
        validated_endpoint_snapshot is None
        or validated_endpoint_snapshot.get("base_url")
        != "https://llm.shtech.org/v1"
    ):
        logger.error(
            "--evaluation-mode requires the frozen shtech lab endpoint"
        )
        return False
    decoding_config_json = getattr(args, "decoding_config_json", None)
    decoding_config_sha256 = getattr(args, "decoding_config_sha256", None)
    if (decoding_config_json is None) != (decoding_config_sha256 is None):
        logger.error(
            "--decoding-config-json and --decoding-config-sha256 must be provided together"
        )
        return False
    if decoding_config_json is not None:
        try:
            validate_decoding_config_contract(
                decoding_config_json,
                decoding_config_sha256,
            )
        except ValueError as exc:
            logger.error("Invalid decoding config contract: %s", exc)
            return False
    if evaluation_mode and decoding_config_json is None:
        logger.error(
            "--evaluation-mode requires an explicit exact decoding config"
        )
        return False
    if evaluation_mode and not projection_path:
        logger.error(
            "--evaluation-mode requires a frozen --target-path-projection and raw SHA-256"
        )
        return False
    if evaluation_mode and not projection_binding_path:
        logger.error(
            "--evaluation-mode requires --target-path-projection-binding-path"
        )
        return False
    if evaluation_mode and not invariant_stage_sha256:
        logger.error(
            "--evaluation-mode requires both frozen model-input stage SHA-256 values"
        )
        return False
    if invariant_stage_sha256 and not projection_path:
        logger.error("model-input stage hashes require --target-path-projection")
        return False

    order_path = str(getattr(args, "unprioritized_file_order", "") or "").strip()
    order_sha256_value = getattr(
        args,
        "unprioritized_file_order_sha256",
        "",
    )
    order_sha256 = (
        order_sha256_value
        if isinstance(order_sha256_value, str)
        else ""
    )
    order_binding_path = str(
        getattr(args, "unprioritized_file_order_binding_path", "") or ""
    ).strip()
    if bool(order_path) != bool(order_sha256):
        logger.error(
            "--unprioritized-file-order and --unprioritized-file-order-sha256 must be provided together"
        )
        return False
    if order_binding_path and not order_path:
        logger.error(
            "--unprioritized-file-order-binding-path requires "
            "--unprioritized-file-order"
        )
        return False
    candidate_ablation = bool(getattr(args, "ablate_candidate_priority", False))
    target_profile_sha256_value = getattr(
        args,
        "target_software_profile_sha256",
        "",
    )
    target_profile_sha256 = (
        target_profile_sha256_value
        if isinstance(target_profile_sha256_value, str)
        else ""
    )
    if order_path and not candidate_ablation:
        logger.error("--unprioritized-file-order requires --ablate-candidate-priority")
        return False
    if invariant_stage_sha256 and not projection_binding_path:
        logger.error(
            "model-input stages require --target-path-projection-binding-path"
        )
        return False
    if invariant_stage_sha256 and not candidate_ablation and not reference_path:
        logger.error(
            "prioritized model-input policy stage requires a frozen --reference-card"
        )
        return False
    if invariant_stage_sha256 and not candidate_ablation and not reference_binding_path:
        logger.error(
            "prioritized model-input policy stage requires "
            "--reference-card-binding-path"
        )
        return False
    if invariant_stage_sha256 and candidate_ablation and not order_binding_path:
        logger.error(
            "unprioritized model-input policy stage requires "
            "--unprioritized-file-order-binding-path"
        )
        return False
    if candidate_ablation and not order_path:
        logger.error(
            "candidate-priority ablation requires a frozen --unprioritized-file-order"
        )
        return False
    if candidate_ablation and (
        not getattr(args, "target_repo", None)
        or not getattr(args, "target_commit", None)
    ):
        logger.error(
            "candidate-priority ablation requires explicit --target-repo/--target-commit"
        )
        return False
    if (projection_path or candidate_ablation) and (
        not is_lowercase_sha256(target_profile_sha256)
        or target_profile_sha256 != target_profile_sha256.lower()
    ):
        logger.error(
            "frozen target controls require a lowercase "
            "--target-software-profile-sha256"
        )
        return False
    if target_profile_sha256 and not (projection_path or candidate_ablation):
        logger.error(
            "--target-software-profile-sha256 requires a frozen target control"
        )
        return False
    for option_name, binding_path in (
        ("--target-path-projection-binding-path", projection_binding_path),
        ("--reference-card-binding-path", reference_binding_path),
        ("--unprioritized-file-order-binding-path", order_binding_path),
    ):
        if (
            binding_path
            and _portable_frozen_artifact_locator(binding_path) != binding_path
        ):
            logger.error(
                "%s must be a canonical portable workspace-relative POSIX path",
                option_name,
            )
            return False
    if bool(getattr(args, "ablate_memory", False)) and getattr(
        args, "shared_public_memory_dir", None
    ):
        logger.error("--ablate-memory cannot be combined with --shared-public-memory-dir")
        return False

    return True


def _scanner_config_hashes() -> Dict[str, str]:
    """校验四个当前路径后返回首次消费哈希。"""
    return consumed_scanner_config_hashes()


def _failure_scanner_config_hashes() -> Dict[str, Optional[str]]:
    """返回不以漂移值替换的首次消费哈希。"""
    return immutable_consumed_scanner_config_hashes()


def validate_endpoint_snapshot_contract(
    snapshot_json: Any,
    expected_sha256: Any,
    *,
    allow_localhost_http: bool = False,
) -> tuple[Dict[str, str], str]:
    """校验不含密钥的不可变端点身份快照。"""
    if not isinstance(snapshot_json, str) or not snapshot_json:
        raise ValueError("endpoint snapshot JSON must be a non-empty exact string")
    normalized_expected = (
        expected_sha256 if isinstance(expected_sha256, str) else ""
    )
    if not is_lowercase_sha256(normalized_expected):
        raise ValueError(
            "endpoint snapshot SHA-256 must be 64 lowercase hexadecimal characters"
        )

    def reject_duplicate_keys(pairs):
        parsed: Dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise ValueError("endpoint snapshot JSON contains a duplicate key")
            parsed[key] = value
        return parsed

    try:
        snapshot = json.loads(
            snapshot_json,
            object_pairs_hook=reject_duplicate_keys,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("endpoint snapshot is not valid JSON") from exc
    if not isinstance(snapshot, dict) or set(snapshot) != ENDPOINT_SNAPSHOT_KEYS:
        raise ValueError("endpoint snapshot must contain exactly the declared key set")
    canonical_json = json.dumps(
        snapshot,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if snapshot_json != canonical_json:
        raise ValueError("endpoint snapshot JSON must use canonical compact encoding")
    actual_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    if actual_sha256 != normalized_expected:
        raise ValueError("endpoint snapshot canonical SHA-256 mismatch")

    snapshot_id = snapshot.get("snapshot_id")
    base_url = snapshot.get("base_url")
    api_family = snapshot.get("api_family")
    if (
        not isinstance(snapshot_id, str)
        or not snapshot_id
        or snapshot_id != snapshot_id.strip()
        or len(snapshot_id) > 256
        or snapshot_id.casefold() in ENDPOINT_SNAPSHOT_MUTABLE_ALIASES
    ):
        raise ValueError(
            "endpoint snapshot_id must be an immutable non-alias exact string"
        )
    if api_family not in ENDPOINT_API_FAMILIES:
        raise ValueError("endpoint api_family is not supported")
    if (
        not isinstance(base_url, str)
        or not base_url
        or base_url != base_url.strip()
        or any(character.isspace() for character in base_url)
    ):
        raise ValueError("endpoint base_url is invalid")

    try:
        parsed_url = urlsplit(base_url)
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError("endpoint base_url is invalid") from exc
    hostname = parsed_url.hostname
    localhost = hostname in {"localhost", "127.0.0.1", "::1"}
    scheme_is_allowed = parsed_url.scheme == "https" or (
        allow_localhost_http
        and localhost
        and parsed_url.scheme == "http"
    )
    if (
        not scheme_is_allowed
        or not hostname
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
        or "%" in base_url
    ):
        raise ValueError("endpoint base_url is invalid")
    if any(ord(character) > 127 for character in hostname):
        raise ValueError("endpoint base_url is invalid")
    if port == (443 if parsed_url.scheme == "https" else 80):
        raise ValueError("endpoint base_url must omit the default port")
    canonical_host = f"[{hostname}]" if ":" in hostname else hostname
    canonical_netloc = (
        f"{canonical_host}:{port}" if port is not None else canonical_host
    )
    path = parsed_url.path
    if (
        path == "/"
        or path.endswith("/")
        or "//" in path
        or "/./" in path
        or "/../" in path
        or path.endswith("/.")
        or path.endswith("/..")
    ):
        raise ValueError("endpoint base_url path is not canonical")
    canonical_base_url = urlunsplit(
        (
            parsed_url.scheme,
            canonical_netloc,
            path,
            "",
            "",
        )
    )
    if base_url != canonical_base_url:
        raise ValueError("endpoint base_url must use canonical HTTPS form")

    return {
        "snapshot_id": snapshot_id,
        "base_url": base_url,
        "api_family": api_family,
    }, actual_sha256


def validate_endpoint_snapshot_payload(
    snapshot: Any,
    expected_sha256: Any,
    *,
    allow_localhost_http: bool = False,
) -> tuple[Dict[str, str], str]:
    """用相同规范字节校验内存端点快照。"""
    if not isinstance(snapshot, dict):
        raise ValueError("endpoint snapshot payload must be an object")
    try:
        canonical_json = json.dumps(
            snapshot,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("endpoint snapshot payload is not canonical JSON") from exc
    return validate_endpoint_snapshot_contract(
        canonical_json,
        expected_sha256,
        allow_localhost_http=allow_localhost_http,
    )


def validate_decoding_config_contract(
    config_json: Any,
    expected_sha256: Any,
) -> tuple[Dict[str, Any], str]:
    """校验实验所需的规范精确解码意图。"""
    if not isinstance(config_json, str) or not config_json:
        raise ValueError("decoding config JSON must be a non-empty exact string")
    normalized_expected = (
        expected_sha256 if isinstance(expected_sha256, str) else ""
    )
    if not is_lowercase_sha256(normalized_expected):
        raise ValueError(
            "decoding config SHA-256 must be 64 lowercase hexadecimal characters"
        )

    def reject_duplicate_keys(pairs):
        parsed: Dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise ValueError("decoding config JSON contains a duplicate key")
            parsed[key] = value
        return parsed

    def reject_nonfinite_constant(_value):
        raise ValueError("decoding config numbers must be finite")

    try:
        config = json.loads(
            config_json,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("decoding config is not valid JSON") from exc
    if not isinstance(config, dict) or set(config) != DECODING_CONFIG_KEYS:
        raise ValueError("decoding config must contain exactly the declared key set")
    canonical_json = json.dumps(
        config,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if config_json != canonical_json:
        raise ValueError("decoding config JSON must use canonical compact encoding")
    actual_sha256 = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    if actual_sha256 != normalized_expected:
        raise ValueError("decoding config canonical SHA-256 mismatch")

    temperature = config.get("temperature")
    top_p = config.get("top_p")
    max_tokens = config.get("max_tokens")
    enable_thinking = config.get("enable_thinking")
    reasoning_effort = config.get("reasoning_effort")
    service_tier = config.get("service_tier")
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(float(temperature))
        or not 0 <= temperature <= 2
    ):
        raise ValueError("decoding temperature must be finite and between 0 and 2")
    if (
        isinstance(top_p, bool)
        or not isinstance(top_p, (int, float))
        or not math.isfinite(float(top_p))
        or not 0 < top_p <= 1
    ):
        raise ValueError("decoding top_p must be finite and in the interval (0, 1]")
    if (
        isinstance(max_tokens, bool)
        or not isinstance(max_tokens, int)
        or not 1 <= max_tokens <= 1_000_000
    ):
        raise ValueError(
            "decoding max_tokens must be an integer between 1 and 1000000"
        )
    if enable_thinking is not None and not isinstance(enable_thinking, bool):
        raise ValueError("decoding enable_thinking must be boolean or null")
    if (
        reasoning_effort is not None
        and (
            not isinstance(reasoning_effort, str)
            or reasoning_effort not in DECODING_REASONING_EFFORT_VALUES
        )
    ):
        raise ValueError("decoding reasoning_effort is unsupported")
    if (
        service_tier is not None
        and (
            not isinstance(service_tier, str)
            or service_tier not in DECODING_SERVICE_TIER_VALUES
        )
    ):
        raise ValueError("decoding service_tier is unsupported")
    return dict(config), actual_sha256


def validate_decoding_config_payload(
    config: Any,
    expected_sha256: Any,
) -> tuple[Dict[str, Any], str]:
    """用规范 JSON 语义校验内存解码配置。"""
    if not isinstance(config, dict):
        raise ValueError("decoding config payload must be an object")
    try:
        canonical_json = json.dumps(
            config,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("decoding config payload is not canonical JSON") from exc
    return validate_decoding_config_contract(
        canonical_json,
        expected_sha256,
    )


def _effective_client_decoding_config(llm_client: Any) -> Dict[str, Any]:
    """读取请求客户端实际消费的六个解码字段。"""
    llm_config = getattr(llm_client, "config", None)
    if llm_config is None:
        raise ValueError("LLM client does not expose decoding configuration")
    return {
        field: getattr(llm_config, field, None)
        for field in (
            "temperature",
            "top_p",
            "max_tokens",
            "enable_thinking",
            "reasoning_effort",
            "service_tier",
        )
    }


def _load_frozen_json_artifact(
    path_value: str,
    expected_sha256: str,
    *,
    label: str,
) -> tuple[Path, Dict[str, Any], str]:
    """加载冻结 JSON 输入并校验原始字节哈希。"""
    artifact_path = resolve_cli_path(path_value, base_dir=_path_config["project_root"])
    if not artifact_path.is_file():
        raise ValueError(f"{label} is not a regular file: {artifact_path}")
    raw_bytes = artifact_path.read_bytes()
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    normalized_expected = (
        expected_sha256 if isinstance(expected_sha256, str) else ""
    )
    if not is_lowercase_sha256(normalized_expected):
        raise ValueError(f"{label} expected SHA-256 must be 64 lowercase hexadecimal characters")
    if actual_sha256 != normalized_expected:
        raise ValueError(
            f"{label} SHA-256 mismatch: expected={normalized_expected}, actual={actual_sha256}"
        )
    def reject_duplicate_keys(pairs):
        parsed: Dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise ValueError(f"duplicate JSON key in {label}: {key}")
            parsed[key] = value
        return parsed

    try:
        payload = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return artifact_path, payload, actual_sha256


def _portable_frozen_artifact_locator(path_value: str) -> Optional[str]:
    """返回调用方给出的规范相对定位符，不返回主机路径。"""
    raw_path = str(path_value or "").strip()
    if not raw_path or "\\" in raw_path or raw_path.startswith("~"):
        return None
    path = Path(raw_path)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    locator = path.as_posix()
    if locator != raw_path:
        return None
    return locator


def _frozen_artifact_provenance(
    physical_path_value: str,
    artifact_sha256: str,
    *,
    binding_path: Optional[str] = None,
) -> Dict[str, str]:
    """分别记录已验证物理字节与逻辑类型绑定。"""
    physical_path = str(physical_path_value or "").strip()
    provenance = {
        "artifact_sha256": artifact_sha256,
        "physical_artifact_path": physical_path,
    }
    logical_path = (
        str(binding_path or "").strip()
        if binding_path is not None
        else physical_path
    )
    locator = _portable_frozen_artifact_locator(logical_path)
    if locator is not None:
        provenance["artifact_path"] = locator
    return provenance


def validate_model_revision_attestation_binding(
    binding: Any,
) -> Dict[str, str]:
    # 校验可移植原始文件与规范 payload 的哈希绑定。
    if not isinstance(binding, dict) or set(binding) != {
        "path",
        "file_sha256",
        "payload_sha256",
    }:
        raise ValueError("model revision attestation binding is malformed")
    if (
        _portable_frozen_artifact_locator(binding.get("path"))
        != binding.get("path")
        or not is_lowercase_sha256(binding.get("file_sha256"))
        or not is_lowercase_sha256(binding.get("payload_sha256"))
    ):
        raise ValueError("model revision attestation file binding is invalid")
    return {
        "path": binding["path"],
        "file_sha256": binding["file_sha256"],
        "payload_sha256": binding["payload_sha256"],
    }


def validate_model_revision_attestation_payload(
    attestation: Any,
    *,
    provider: Any,
    model_name: Any,
    model_revision: Any,
    endpoint_snapshot_sha256: Any,
) -> Dict[str, Dict[str, Any]]:
    # 校验操作员证明的精确部署 revision 绑定。
    if not isinstance(attestation, dict) or set(attestation) != {
        "payload",
        "binding",
    }:
        raise ValueError(
            "model revision attestation envelope must contain payload and binding"
        )
    payload = attestation.get("payload")
    binding = attestation.get("binding")
    if (
        not isinstance(payload, dict)
        or set(payload) != MODEL_REVISION_ATTESTATION_KEYS
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version")
        != MODEL_REVISION_ATTESTATION_SCHEMA_VERSION
        or payload.get("kind") != MODEL_REVISION_ATTESTATION_KIND
    ):
        raise ValueError("model revision attestation payload is malformed")
    for field in (
        "provider",
        "model_name",
        "model_revision",
        "endpoint_snapshot_sha256",
    ):
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
        ):
            raise ValueError(
                f"model revision attestation {field} must be an exact string"
            )
    if payload.get("provider") != provider:
        raise ValueError("model revision attestation provider mismatch")
    if payload.get("model_name") != model_name:
        raise ValueError("model revision attestation model_name mismatch")
    if payload.get("model_revision") != model_revision:
        raise ValueError("model revision attestation revision mismatch")
    if (
        not is_lowercase_sha256(payload.get("endpoint_snapshot_sha256"))
        or payload.get("endpoint_snapshot_sha256")
        != endpoint_snapshot_sha256
    ):
        raise ValueError(
            "model revision attestation endpoint snapshot mismatch"
        )
    resolved_binding = validate_model_revision_attestation_binding(binding)
    payload_sha256 = stable_data_hash(payload)
    if resolved_binding["payload_sha256"] != payload_sha256:
        raise ValueError(
            "model revision attestation canonical payload SHA-256 mismatch"
        )
    return {
        "payload": dict(payload),
        "binding": resolved_binding,
    }


def load_model_revision_attestation(
    path_value: str,
    expected_file_sha256: str,
    binding_path: str,
    *,
    provider: str,
    model_name: str,
    model_revision: str,
    endpoint_snapshot_sha256: str,
) -> Dict[str, Dict[str, Any]]:
    # 加载并校验冻结的操作员 revision 证明。
    _artifact_path, payload, file_sha256 = _load_frozen_json_artifact(
        path_value,
        expected_file_sha256,
        label="model revision attestation",
    )
    logical_path = _portable_frozen_artifact_locator(binding_path)
    if logical_path is None or logical_path != binding_path:
        raise ValueError(
            "model revision attestation binding path is not canonical"
        )
    attestation = {
        "payload": payload,
        "binding": {
            "path": logical_path,
            "file_sha256": file_sha256,
            "payload_sha256": stable_data_hash(payload),
        },
    }
    return validate_model_revision_attestation_payload(
        attestation,
        provider=provider,
        model_name=model_name,
        model_revision=model_revision,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
    )


def _normalize_frozen_repo_path(path_value: Any, *, label: str) -> str:
    if not isinstance(path_value, str):
        raise ValueError(f"{label} must be a JSON string")
    raw_path = path_value
    path = PurePosixPath(raw_path)
    if (
        not raw_path
        or raw_path.startswith("/")
        or ".." in path.parts
        or path.as_posix() != raw_path
        or chr(92) in raw_path
    ):
        raise ValueError(f"{label} must be a canonical repository-relative POSIX path")
    return raw_path


def _run_git_ls_tree(
    repo_path: Path,
    commit: str,
    *,
    nul_terminated: bool,
) -> bytes:
    """读取精确提交树，不查询工作树。"""
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(char not in "0123456789abcdef" for char in commit)
    ):
        raise ValueError("target commit must be full lowercase 40-hex")
    resolved_repo_path = Path(repo_path)
    if not resolved_repo_path.is_dir():
        raise ValueError(f"target repository is not a directory: {resolved_repo_path}")
    command = [
        "git",
        "-C",
        str(resolved_repo_path),
        "ls-tree",
        "-r",
        "--full-tree",
        commit,
    ]
    if nul_terminated:
        command.insert(-1, "-z")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git ls-tree timed out") from exc
    except OSError as exc:
        raise ValueError(f"git ls-tree could not run: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(message or "git ls-tree failed")
    return result.stdout


def _git_regular_blob_tree_snapshot(
    repo_path: Path,
    commit: str,
) -> tuple[str, List[str]]:
    """返回原始 ls-tree 哈希和规范普通 blob 集合。"""
    raw_listing = _run_git_ls_tree(
        repo_path,
        commit,
        nul_terminated=False,
    )
    raw_records = _run_git_ls_tree(
        repo_path,
        commit,
        nul_terminated=True,
    )
    paths: List[str] = []
    for record in raw_records.split(b"\0"):
        if not record:
            continue
        header, separator, raw_path = record.partition(b"\t")
        fields = header.split()
        if not separator or len(fields) != 3:
            raise ValueError("malformed git ls-tree record")
        mode, object_type, _object_id = fields
        if object_type != b"blob" or mode not in {b"100644", b"100755"}:
            continue
        try:
            value = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "non-UTF-8 Git path cannot be represented in the projection"
            ) from exc
        paths.append(
            _normalize_frozen_repo_path(value, label="Git regular-blob path")
        )
    ordered_paths = sorted(paths, key=lambda value: value.encode("utf-8"))
    if not ordered_paths:
        raise ValueError("target Git tree has no regular blob paths")
    if len(ordered_paths) != len(set(ordered_paths)):
        raise ValueError("target Git tree contains duplicate regular blob paths")
    return hashlib.sha256(raw_listing).hexdigest(), ordered_paths


def _validate_target_projection_against_git_tree(
    target_path_projection: Dict[str, Any],
    repo_path: Path,
    *,
    target_repository: str,
    target_commit: str,
) -> None:
    """用独立重算的 Git 树闭合冻结投影。"""
    if not isinstance(target_path_projection, dict):
        raise ValueError("target path projection must be an object")
    files = target_path_projection.get("files")
    provenance = target_path_projection.get("provenance")
    if not isinstance(files, list) or not isinstance(provenance, dict):
        raise ValueError("target path projection has an invalid validated shape")
    expected_metadata = {
        "schema_version": MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION,
        "algorithm": MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "target_repository": target_repository,
        "target_commit": target_commit,
        "source": MODEL_VISIBLE_INPUT_PROJECTION_SOURCE,
        "replacement": MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY,
        "structured_projection": MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION,
        "scope": MODEL_VISIBLE_INPUT_PROJECTION_SCOPE,
        "policy_exclusions": MODEL_VISIBLE_INPUT_POLICY_EXCLUSIONS,
    }
    for field, expected_value in expected_metadata.items():
        if provenance.get(field) != expected_value:
            raise ValueError(
                f"target path projection provenance mismatch for {field}"
            )
    target_id = provenance.get("target_id")
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target path projection target_id must be a non-empty string")

    tree_listing_sha256, committed_paths = _git_regular_blob_tree_snapshot(
        repo_path,
        target_commit,
    )
    if files != committed_paths:
        raise ValueError(
            "target path projection does not equal the checked commit regular-blob universe"
        )
    if provenance.get("path_count") != len(committed_paths):
        raise ValueError("target path projection path_count does not match the Git tree")
    universe_sha256 = stable_data_hash(committed_paths)
    if provenance.get("universe_sha256") != universe_sha256:
        raise ValueError("target path projection universe_sha256 does not match the Git tree")
    if provenance.get("target_tree_listing_sha256") != tree_listing_sha256:
        raise ValueError(
            "target path projection target_tree_listing_sha256 does not match git ls-tree"
        )


def load_reference_context_envelope(
    path_value: str,
    expected_sha256: str,
    binding_path: Optional[str] = None,
) -> Dict[str, Any]:
    """加载严格 model card 和仅主机可见的优先级计划封套。"""
    _artifact_path, payload, artifact_sha256 = _load_frozen_json_artifact(
        path_value,
        expected_sha256,
        label="reference context envelope",
    )
    expected_root_keys = {
        "schema_version",
        "model_card",
        "host_priority_plan",
        "model_card_sha256",
        "host_priority_plan_sha256",
    }
    if set(payload) != expected_root_keys or payload.get("schema_version") != 1:
        raise ValueError(
            "reference context envelope must use schema_version=1 and the exact frozen key set"
        )

    model_card = payload.get("model_card")
    if not isinstance(model_card, dict) or set(model_card) != {
        "schema_version", "card_id", "weaknesses"
    }:
        raise ValueError("model_card must contain exactly schema_version, card_id, and weaknesses")
    if model_card.get("schema_version") != 1:
        raise ValueError("model_card.schema_version must equal 1")
    card_id = str(model_card.get("card_id", "") or "").strip()
    if not card_id or len(card_id) > 128 or "CVE-" in card_id.upper():
        raise ValueError("model_card.card_id must be a non-CVE opaque identifier of at most 128 characters")
    weaknesses = model_card.get("weaknesses")
    if not isinstance(weaknesses, list) or not weaknesses:
        raise ValueError("model_card.weaknesses must be a non-empty list")
    normalized_weaknesses = [str(item or "").strip().upper() for item in weaknesses]
    if any(
        not weakness.startswith("CWE-") or not weakness[4:].isdigit()
        for weakness in normalized_weaknesses
    ):
        raise ValueError("model_card.weaknesses may contain only CWE-N identifiers")
    if normalized_weaknesses != sorted(set(normalized_weaknesses)):
        raise ValueError("model_card.weaknesses must be unique and lexicographically sorted")
    model_card = {
        "schema_version": 1,
        "card_id": card_id,
        "weaknesses": normalized_weaknesses,
    }

    host_plan = payload.get("host_priority_plan")
    if not isinstance(host_plan, dict) or set(host_plan) != {
        "schema_version", "module_priorities", "file_to_module"
    }:
        raise ValueError(
            "host_priority_plan must contain exactly schema_version, module_priorities, and file_to_module"
        )
    if host_plan.get("schema_version") != 1:
        raise ValueError("host_priority_plan.schema_version must equal 1")
    raw_priorities = host_plan.get("module_priorities")
    raw_file_to_module = host_plan.get("file_to_module")
    if not isinstance(raw_priorities, dict) or not isinstance(raw_file_to_module, dict):
        raise ValueError("host priority mappings must be JSON objects")
    module_priorities: Dict[str, int] = {}
    for raw_name, raw_priority in sorted(raw_priorities.items()):
        module_name = str(raw_name or "").strip()
        if not module_name or isinstance(raw_priority, bool) or raw_priority not in {1, 2, 3}:
            raise ValueError("host priority modules require non-empty names and integer priority 1, 2, or 3")
        module_priorities[module_name] = int(raw_priority)
    file_to_module: Dict[str, str] = {}
    for raw_path, raw_module in sorted(raw_file_to_module.items()):
        file_path = _normalize_frozen_repo_path(raw_path, label="host priority file")
        module_name = str(raw_module or "").strip()
        if module_name not in module_priorities:
            raise ValueError(f"host priority file references unknown module {module_name!r}")
        file_to_module[file_path] = module_name
    host_plan = {
        "schema_version": 1,
        "module_priorities": module_priorities,
        "file_to_module": file_to_module,
    }

    model_card_sha256 = stable_data_hash(model_card)
    host_plan_sha256 = stable_data_hash(host_plan)
    if payload.get("model_card_sha256") != model_card_sha256:
        raise ValueError("model_card_sha256 does not match the canonical model_card payload")
    if payload.get("host_priority_plan_sha256") != host_plan_sha256:
        raise ValueError(
            "host_priority_plan_sha256 does not match the canonical host_priority_plan payload"
        )
    return {
        "model_card": model_card,
        "host_priority_plan": host_plan,
        "provenance": {
            **_frozen_artifact_provenance(
                path_value,
                artifact_sha256,
                binding_path=binding_path,
            ),
            "model_card_sha256": model_card_sha256,
            "host_priority_plan_sha256": host_plan_sha256,
        },
    }


def validate_unprioritized_file_schedule_payload(
    payload: Dict[str, Any],
    artifact_sha256: str,
    *,
    target_commit: str,
    artifact_locator: Optional[str] = None,
    physical_artifact_path: Optional[str] = None,
) -> Dict[str, Any]:
    """校验从单一哈希绑定字节快照解析的 schedule。"""
    normalized_artifact_sha256 = (
        artifact_sha256 if isinstance(artifact_sha256, str) else ""
    )
    if not is_lowercase_sha256(normalized_artifact_sha256):
        raise ValueError(
            "unprioritized file order artifact SHA-256 must be 64 lowercase hexadecimal characters"
        )
    expected_keys = {
        "schema_version",
        "algorithm",
        "benchmark_constant",
        "target_commit",
        "replicate",
        "seed_sha256",
        "files",
        "universe_sha256",
        "order_sha256",
    }
    if set(payload) != expected_keys or payload.get("schema_version") != 1:
        raise ValueError("unprioritized file order must use schema_version=1 and the exact key set")
    if payload.get("algorithm") != "sha256-seed-path-v1":
        raise ValueError("unprioritized file order algorithm must be sha256-seed-path-v1")
    requested_commit = (
        target_commit.strip() if isinstance(target_commit, str) else ""
    )
    frozen_commit = payload.get("target_commit")
    if (
        not isinstance(frozen_commit, str)
        or len(requested_commit) != 40
        or any(char not in "0123456789abcdef" for char in requested_commit)
        or frozen_commit != requested_commit
    ):
        raise ValueError(
            "unprioritized file order target_commit must exactly match the full lowercase --target-commit"
        )
    benchmark_constant = payload.get("benchmark_constant")
    replicate = payload.get("replicate")
    if (
        not isinstance(benchmark_constant, str)
        or not benchmark_constant
        or not isinstance(replicate, str)
        or not replicate
    ):
        raise ValueError(
            "unprioritized file order requires string benchmark_constant and replicate"
        )
    seed_payload = {
        "benchmark_constant": benchmark_constant,
        "target_commit": frozen_commit,
        "replicate": replicate,
    }
    seed_sha256 = stable_data_hash(seed_payload)
    if payload.get("seed_sha256") != seed_sha256:
        raise ValueError("unprioritized file order seed_sha256 is not derived from the public seed fields")
    raw_files = payload.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise ValueError("unprioritized file order files must be a non-empty list")
    files = [
        _normalize_frozen_repo_path(path, label="scheduled file")
        for path in raw_files
    ]
    if len(files) != len(set(files)):
        raise ValueError("unprioritized file order contains duplicate files")
    expected_order = sorted(
        files,
        key=lambda path: (
            hashlib.sha256((seed_sha256 + path).encode("utf-8")).hexdigest(),
            path.encode("utf-8"),
        ),
    )
    if files != expected_order:
        raise ValueError("unprioritized file order does not match the declared seed-hash permutation")
    universe_sha256 = stable_data_hash(sorted(files))
    order_sha256 = stable_data_hash(files)
    if payload.get("universe_sha256") != universe_sha256:
        raise ValueError("unprioritized file order universe_sha256 mismatch")
    if payload.get("order_sha256") != order_sha256:
        raise ValueError("unprioritized file order order_sha256 mismatch")
    return {
        "files": files,
        "provenance": {
            **_frozen_artifact_provenance(
                physical_artifact_path or artifact_locator or "",
                normalized_artifact_sha256,
                binding_path=artifact_locator,
            ),
            "algorithm": payload["algorithm"],
            "benchmark_constant": benchmark_constant,
            "target_commit": frozen_commit,
            "replicate": replicate,
            "seed_sha256": seed_sha256,
            "universe_sha256": universe_sha256,
            "order_sha256": order_sha256,
            "file_count": len(files),
            "page_algorithm": FROZEN_SCHEDULE_PAGE_ALGORITHM,
            "page_size": FROZEN_SCHEDULE_PAGE_SIZE,
        },
    }


def load_unprioritized_file_schedule(
    path_value: str,
    expected_sha256: str,
    *,
    target_commit: str,
    binding_path: Optional[str] = None,
) -> Dict[str, Any]:
    """加载并校验预冻结的公开 seed-hash 文件 schedule。"""
    _artifact_path, payload, artifact_sha256 = _load_frozen_json_artifact(
        path_value,
        expected_sha256,
        label="unprioritized file order",
    )
    return validate_unprioritized_file_schedule_payload(
        payload,
        artifact_sha256,
        target_commit=target_commit,
        artifact_locator=binding_path if binding_path is not None else path_value,
        physical_artifact_path=path_value,
    )



def validate_target_path_projection_payload(
    payload: Dict[str, Any],
    artifact_sha256: str,
    *,
    target_repository: str,
    target_commit: str,
    target_software_profile_sha256: str,
    artifact_locator: Optional[str] = None,
    physical_artifact_path: Optional[str] = None,
) -> Dict[str, Any]:
    """校验全部普通 blob 目标路径的规范投影。"""
    normalized_artifact_sha256 = (
        artifact_sha256 if isinstance(artifact_sha256, str) else ""
    )
    normalized_profile_sha256 = (
        target_software_profile_sha256
        if isinstance(target_software_profile_sha256, str)
        else ""
    )
    if not is_lowercase_sha256(normalized_artifact_sha256):
        raise ValueError(
            "target path projection artifact SHA-256 must be lowercase hexadecimal"
        )
    if not is_lowercase_sha256(normalized_profile_sha256):
        raise ValueError(
            "target path projection requires a separately hash-bound target software profile"
        )
    expected_keys = {
        "schema_version",
        "algorithm",
        "target_id",
        "target_repository",
        "target_commit",
        "source",
        "target_tree_listing_sha256",
        "path_count",
        "paths",
        "universe_sha256",
        "replacement",
        "boundary",
        "structured_projection",
        "scope",
        "policy_exclusions",
    }
    if set(payload) != expected_keys or payload.get("schema_version") != MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION:
        raise ValueError(
            "target path projection must use schema_version=2 and the exact key set"
        )
    if payload.get("algorithm") != MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM:
        raise ValueError("target path projection algorithm is unsupported")
    if payload.get("source") != MODEL_VISIBLE_INPUT_PROJECTION_SOURCE:
        raise ValueError("target path projection source is unsupported")
    if payload.get("replacement") != MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT:
        raise ValueError("target path projection replacement is unsupported")
    if payload.get("boundary") != MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY:
        raise ValueError("target path projection boundary contract is unsupported")
    if (
        payload.get("structured_projection")
        != MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
    ):
        raise ValueError(
            "target path projection structured projection contract is unsupported"
        )
    if payload.get("scope") != MODEL_VISIBLE_INPUT_PROJECTION_SCOPE:
        raise ValueError("target path projection invariant scope is unsupported")
    if payload.get("policy_exclusions") != MODEL_VISIBLE_INPUT_POLICY_EXCLUSIONS:
        raise ValueError("target path projection policy exclusions are unsupported")

    requested_repository = str(target_repository or "").strip()
    frozen_repository = payload.get("target_repository")
    target_id = payload.get("target_id")
    if not isinstance(frozen_repository, str):
        raise ValueError("target path projection target_repository must be a JSON string")
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target path projection target_id must be a non-empty string")
    if not requested_repository or frozen_repository != requested_repository:
        raise ValueError(
            "target path projection target_repository must exactly match --target-repo"
        )
    requested_commit = (
        target_commit.strip() if isinstance(target_commit, str) else ""
    )
    frozen_commit = payload.get("target_commit")
    if (
        not isinstance(frozen_commit, str)
        or len(requested_commit) != 40
        or any(char not in "0123456789abcdef" for char in requested_commit)
        or frozen_commit != requested_commit
    ):
        raise ValueError(
            "target path projection target_commit must exactly match the full lowercase --target-commit"
        )
    tree_listing_sha256 = payload.get("target_tree_listing_sha256")
    if not is_lowercase_sha256(tree_listing_sha256):
        raise ValueError("target path projection tree listing hash is invalid")

    raw_paths = payload.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ValueError("target path projection paths must be a non-empty list")
    paths = [
        _normalize_frozen_repo_path(path, label="projection path")
        for path in raw_paths
    ]
    if paths != sorted(set(paths), key=lambda value: value.encode("utf-8")):
        raise ValueError(
            "target path projection paths must be unique and UTF-8-byte sorted"
        )
    path_count = payload.get("path_count")
    if isinstance(path_count, bool) or path_count != len(paths):
        raise ValueError("target path projection path_count mismatch")
    universe_sha256 = stable_data_hash(paths)
    if payload.get("universe_sha256") != universe_sha256:
        raise ValueError("target path projection universe_sha256 mismatch")
    return {
        "files": paths,
        "provenance": {
            **_frozen_artifact_provenance(
                physical_artifact_path or artifact_locator or "",
                normalized_artifact_sha256,
                binding_path=artifact_locator,
            ),
            "schema_version": MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION,
            "algorithm": MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
            "target_id": target_id,
            "target_repository": frozen_repository,
            "target_commit": frozen_commit,
            "source": MODEL_VISIBLE_INPUT_PROJECTION_SOURCE,
            "target_tree_listing_sha256": tree_listing_sha256,
            "path_count": len(paths),
            "universe_sha256": universe_sha256,
            "replacement": MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
            "boundary": dict(MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
            "structured_projection": dict(
                MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
            ),
            "scope": list(MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
            "policy_exclusions": list(MODEL_VISIBLE_INPUT_POLICY_EXCLUSIONS),
            "bound_target_software_profile_sha256": normalized_profile_sha256,
        },
    }


def load_target_path_projection(
    path_value: str,
    expected_sha256: str,
    *,
    target_repository: str,
    target_commit: str,
    target_software_profile_sha256: str,
    binding_path: Optional[str] = None,
) -> Dict[str, Any]:
    """加载并校验与目标无关的模型输入投影。"""
    _artifact_path, payload, artifact_sha256 = _load_frozen_json_artifact(
        path_value,
        expected_sha256,
        label="target path projection",
    )
    return validate_target_path_projection_payload(
        payload,
        artifact_sha256,
        target_repository=target_repository,
        target_commit=target_commit,
        target_software_profile_sha256=target_software_profile_sha256,
        artifact_locator=binding_path if binding_path is not None else path_value,
        physical_artifact_path=path_value,
    )


def _frozen_file_binding(
    provenance: Dict[str, Any],
    *,
    label: str,
) -> Dict[str, str]:
    """从已验证 scanner provenance 重建精确 RQ2 类型绑定。"""
    if not isinstance(provenance, dict):
        raise ValueError(f"{label} provenance must be an object")
    artifact_path = str(provenance.get("artifact_path", "") or "").strip()
    artifact_sha256_value = provenance.get("artifact_sha256", "")
    artifact_sha256 = (
        artifact_sha256_value
        if isinstance(artifact_sha256_value, str)
        else ""
    )
    if _portable_frozen_artifact_locator(artifact_path) != artifact_path:
        raise ValueError(f"{label} requires a portable workspace-relative locator")
    if not is_lowercase_sha256(artifact_sha256) or artifact_sha256 != artifact_sha256.lower():
        raise ValueError(f"{label} requires a lowercase raw artifact SHA-256")
    return {
        "kind": "file",
        "status": "frozen",
        "path": artifact_path,
        "sha256": artifact_sha256,
    }


def _model_input_stage_hash(stage_without_hash: Dict[str, Any]) -> str:
    """在加入自哈希字段前计算规范阶段哈希。"""
    return stable_data_hash(stage_without_hash)


def _validate_verified_model_input_control(
    target_path_projection: Dict[str, Any],
) -> Dict[str, Any]:
    """保存的两阶段控制数据无法精确重算时失败关闭。"""
    provenance = target_path_projection.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ValueError("target path projection provenance must be an object")
    control = provenance.get("model_input_control")
    if not isinstance(control, dict) or set(control) != {
        "schema_version",
        "invariant_preprocessing",
        "policy_specific_eligibility",
    } or control.get("schema_version") != MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION:
        raise ValueError("verified model-input control is missing or malformed")

    projection_binding = _frozen_file_binding(
        provenance,
        label="target path projection",
    )
    expected_invariant = {
        "schema_version": MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION,
        "algorithm": MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "scope": list(MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "replacement": MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "projection_input": projection_binding,
    }
    expected_invariant["stage_sha256"] = _model_input_stage_hash(
        expected_invariant
    )
    invariant = control.get("invariant_preprocessing")
    if invariant != expected_invariant:
        raise ValueError("invariant preprocessing stage or self-hash mismatch")

    policy = control.get("policy_specific_eligibility")
    if not isinstance(policy, dict) or set(policy) != {
        "mode",
        "artifact",
        "stage_sha256",
    }:
        raise ValueError("policy-specific eligibility stage is malformed")
    policy_without_hash = {
        "mode": policy.get("mode"),
        "artifact": policy.get("artifact"),
    }
    if policy_without_hash["mode"] not in {
        "host_priority_plan",
        "frozen_unprioritized_schedule",
    } or not isinstance(policy_without_hash["artifact"], dict):
        raise ValueError("policy-specific eligibility stage is unsupported")
    if policy.get("stage_sha256") != _model_input_stage_hash(policy_without_hash):
        raise ValueError("policy-specific eligibility stage self-hash mismatch")

    stage_hashes = provenance.get("model_input_stage_hashes")
    expected_stage_hashes = {
        "invariant_preprocessing": expected_invariant["stage_sha256"],
        "policy_specific_eligibility": policy["stage_sha256"],
    }
    if stage_hashes != expected_stage_hashes:
        raise ValueError("model-input stage hash provenance mismatch")
    if provenance.get("model_input_control_sha256") != stable_data_hash(control):
        raise ValueError("complete model-input control hash mismatch")
    return control


def _validate_evaluation_model_input_policy_binding(
    *,
    target_path_projection: Dict[str, Any],
    normalized_ablation_config: Dict[str, bool],
    reference_context_provenance: Optional[Dict[str, Any]],
    unprioritized_file_schedule: Optional[Dict[str, Any]],
    bound_profile_sha256: str,
) -> None:
    """把已验证策略阶段与本次调用控制项交叉绑定。"""
    control = _validate_verified_model_input_control(target_path_projection)
    policy = control["policy_specific_eligibility"]
    if normalized_ablation_config["candidate_priority"]:
        if not isinstance(unprioritized_file_schedule, dict):
            raise ValueError(
                "evaluation candidate-priority ablation requires a frozen file schedule"
            )
        schedule_provenance = unprioritized_file_schedule.get("provenance")
        if not isinstance(schedule_provenance, dict):
            raise ValueError("evaluation file schedule provenance must be an object")
        schedule_profile_sha256 = schedule_provenance.get(
            "target_software_profile_sha256"
        )
        if (
            not is_lowercase_sha256(schedule_profile_sha256)
            or schedule_profile_sha256 != bound_profile_sha256
        ):
            raise ValueError(
                "evaluation file schedule target profile binding mismatch"
            )
        expected_mode = "frozen_unprioritized_schedule"
        expected_artifact = _frozen_file_binding(
            schedule_provenance,
            label="unprioritized file order",
        )
    else:
        if unprioritized_file_schedule is not None:
            raise ValueError(
                "evaluation prioritized policy must not receive an unprioritized schedule"
            )
        if not isinstance(reference_context_provenance, dict):
            raise ValueError(
                "evaluation prioritized policy requires frozen reference provenance"
            )
        expected_mode = "host_priority_plan"
        expected_artifact = _frozen_file_binding(
            reference_context_provenance,
            label="reference context envelope",
        )
    if (
        policy.get("mode") != expected_mode
        or policy.get("artifact") != expected_artifact
    ):
        raise ValueError("evaluation model-input policy binding mismatch")


def bind_verified_model_input_control(
    target_path_projection: Dict[str, Any],
    *,
    reference_context: Optional[Dict[str, Any]],
    unprioritized_schedule: Optional[Dict[str, Any]],
    expected_invariant_stage_sha256: str,
    expected_policy_stage_sha256: str,
) -> Dict[str, Any]:
    """重建、校验并绑定精确的两阶段 RQ2 输入控制。"""
    projection_provenance = dict(target_path_projection.get("provenance", {}))
    invariant_without_hash = {
        "schema_version": MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION,
        "algorithm": MODEL_VISIBLE_INPUT_PROJECTION_ALGORITHM,
        "scope": list(MODEL_VISIBLE_INPUT_PROJECTION_SCOPE),
        "replacement": MODEL_VISIBLE_INPUT_PROJECTION_REPLACEMENT,
        "boundary": dict(MODEL_VISIBLE_INPUT_PROJECTION_BOUNDARY),
        "structured_projection": dict(
            MODEL_VISIBLE_INPUT_STRUCTURED_PROJECTION
        ),
        "projection_input": _frozen_file_binding(
            projection_provenance,
            label="target path projection",
        ),
    }
    invariant = dict(invariant_without_hash)
    invariant["stage_sha256"] = _model_input_stage_hash(invariant_without_hash)

    if unprioritized_schedule is not None:
        policy_without_hash = {
            "mode": "frozen_unprioritized_schedule",
            "artifact": _frozen_file_binding(
                dict(unprioritized_schedule.get("provenance", {})),
                label="unprioritized file order",
            ),
        }
    else:
        if not isinstance(reference_context, dict):
            raise ValueError("prioritized policy stage requires a reference card")
        policy_without_hash = {
            "mode": "host_priority_plan",
            "artifact": _frozen_file_binding(
                dict(reference_context.get("provenance", {})),
                label="reference context envelope",
            ),
        }
    policy = dict(policy_without_hash)
    policy["stage_sha256"] = _model_input_stage_hash(policy_without_hash)
    if invariant["stage_sha256"] != expected_invariant_stage_sha256:
        raise ValueError("model-input invariant stage SHA-256 mismatch")
    if policy["stage_sha256"] != expected_policy_stage_sha256:
        raise ValueError("model-input policy stage SHA-256 mismatch")

    control = {
        "schema_version": MODEL_VISIBLE_INPUT_PROJECTION_SCHEMA_VERSION,
        "invariant_preprocessing": invariant,
        "policy_specific_eligibility": policy,
    }
    bound = {
        "files": list(target_path_projection.get("files", [])),
        "provenance": {
            **projection_provenance,
            "model_input_control": control,
            "model_input_control_sha256": stable_data_hash(control),
            "model_input_stage_hashes": {
                "invariant_preprocessing": invariant["stage_sha256"],
                "policy_specific_eligibility": policy["stage_sha256"],
            },
        },
    }
    _validate_verified_model_input_control(bound)
    return bound


def _frozen_control_input_hashes(
    target_path_projection: Optional[Dict[str, Any]],
) -> Dict[str, Optional[str]]:
    provenance = (
        target_path_projection.get("provenance", {})
        if isinstance(target_path_projection, dict)
        else {}
    )
    stage_hashes = provenance.get("model_input_stage_hashes", {})
    if not isinstance(stage_hashes, dict):
        stage_hashes = {}
    return {
        "target_software_profile_artifact": provenance.get("bound_target_software_profile_sha256"),
        "target_path_projection_artifact": provenance.get("artifact_sha256"),
        "model_input_invariant_stage": stage_hashes.get("invariant_preprocessing"),
        "model_input_policy_stage": stage_hashes.get("policy_specific_eligibility"),
        "model_input_control": provenance.get("model_input_control_sha256"),
    }


def _split_model_visible_input_projection_provenance(
    target_path_projection: Optional[Dict[str, Any]],
    finder_projection_provenance: Any,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """分离精确冻结元数据与确定性运行投影证据。"""
    base_projection = (
        dict(target_path_projection.get("provenance", {}))
        if isinstance(target_path_projection, dict)
        and isinstance(target_path_projection.get("provenance"), dict)
        else {}
    )
    if not base_projection:
        if finder_projection_provenance not in (None, {}):
            raise ValueError(
                "Finder reported runtime projection evidence without a frozen projection"
            )
        return {}, {}
    if not isinstance(finder_projection_provenance, dict):
        raise ValueError("Finder did not report model-input projection provenance")
    expected_keys = set(base_projection) | set(
        MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS
    )
    if set(finder_projection_provenance) != expected_keys:
        raise ValueError(
            "Finder model-input projection provenance has an unexpected key set"
        )
    for key, expected_value in base_projection.items():
        if finder_projection_provenance.get(key) != expected_value:
            raise ValueError(
                f"Finder model-input projection base mismatch for {key}"
            )
    runtime_projection = {
        key: finder_projection_provenance[key]
        for key in MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS
    }
    for key in MODEL_VISIBLE_INPUT_RUNTIME_PROJECTION_KEYS[:-1]:
        if not is_lowercase_sha256(runtime_projection[key]):
            raise ValueError(
                f"Finder runtime model-input projection hash is invalid for {key}"
            )
    if (
        runtime_projection["policy_preserved_fields"]
        != MODEL_VISIBLE_INPUT_POLICY_PRESERVED_FIELDS
    ):
        raise ValueError(
            "Finder runtime model-input policy-preserved fields are invalid"
        )
    return base_projection, runtime_projection


def validate_frozen_scan_controls(
    software_profile: Any,
    host_priority_plan: Optional[Dict[str, Any]],
    unprioritized_schedule: Optional[Dict[str, Any]] = None,
    target_path_projection: Optional[Dict[str, Any]] = None,
) -> None:
    """把冻结扫描控制臂绑定到目标画像文件全集。"""
    profile_payload = (
        software_profile.to_dict()
        if hasattr(software_profile, "to_dict")
        else software_profile
    )
    if not isinstance(profile_payload, dict):
        raise ValueError("target software profile cannot be normalized for frozen controls")
    raw_modules = profile_payload.get("modules", [])
    if not isinstance(raw_modules, list):
        raise ValueError("target software profile modules must be a list")
    expected_priorities_universe: set[str] = set()
    expected_file_to_module: Dict[str, str] = {}
    for raw_module in raw_modules:
        if hasattr(raw_module, "to_dict"):
            module_payload = raw_module.to_dict()
        elif isinstance(raw_module, dict):
            module_payload = raw_module
        else:
            continue
        module_name = str(module_payload.get("name", "") or "").strip()
        if not module_name:
            continue
        expected_priorities_universe.add(module_name)
        for raw_file in module_payload.get("files", []) or []:
            file_path = _normalize_frozen_repo_path(
                raw_file,
                label="target software profile file",
            )
            expected_file_to_module[file_path] = module_name

    expected_file_universe = sorted(expected_file_to_module)
    if target_path_projection is not None and not isinstance(
        target_path_projection,
        dict,
    ):
        raise ValueError("target path projection must be an object")

    if unprioritized_schedule is not None:
        raw_schedule_files = unprioritized_schedule.get("files", [])
        if not isinstance(raw_schedule_files, list):
            raise ValueError("frozen unprioritized schedule files must be a list")
        schedule_files = [
            _normalize_frozen_repo_path(path, label="scheduled file")
            for path in raw_schedule_files
        ]
        if len(schedule_files) != len(set(schedule_files)):
            raise ValueError("frozen unprioritized schedule contains duplicate files")
        if sorted(schedule_files) != expected_file_universe:
            raise ValueError(
                "frozen unprioritized schedule universe does not match the target software profile"
            )
        schedule_provenance = unprioritized_schedule.get("provenance", {})
        if not isinstance(schedule_provenance, dict):
            raise ValueError("frozen unprioritized schedule provenance must be an object")
        if schedule_provenance.get("universe_sha256") != stable_data_hash(
            expected_file_universe
        ):
            raise ValueError("frozen unprioritized schedule universe_sha256 mismatch")
        if schedule_provenance.get("order_sha256") != stable_data_hash(schedule_files):
            raise ValueError("frozen unprioritized schedule order_sha256 mismatch")
        if (
            schedule_provenance.get("page_algorithm")
            != FROZEN_SCHEDULE_PAGE_ALGORITHM
            or schedule_provenance.get("page_size") != FROZEN_SCHEDULE_PAGE_SIZE
        ):
            raise ValueError("frozen unprioritized schedule page policy mismatch")
        return

    if host_priority_plan is None:
        return
    if not isinstance(host_priority_plan, dict):
        raise ValueError("prioritized scan requires a frozen host priority plan")
    module_priorities = host_priority_plan.get("module_priorities", {})
    file_to_module = host_priority_plan.get("file_to_module", {})
    if set(module_priorities) != expected_priorities_universe:
        raise ValueError(
            "frozen host priority module universe does not match the target software profile"
        )
    if file_to_module != dict(sorted(expected_file_to_module.items())):
        raise ValueError(
            "frozen host priority file mapping does not match the target software profile"
        )


def _resolve_profile_dirs(args: argparse.Namespace) -> tuple[Path, Path]:
    return resolve_profile_dirs(
        profile_base_path=getattr(args, "profile_base_path", None),
        software_profile_dirname=getattr(args, "software_profile_dirname", None),
        vuln_profile_dirname=getattr(args, "vuln_profile_dirname", None),
    )


def _resolve_manual_targets(
    args: argparse.Namespace,
    vulnerability_profile,
    repo_profiles_dir: Path,
) -> List[ScanTarget]:
    repo_name = args.target_repo
    if not repo_name:
        return []

    commit_hint = args.target_commit
    source_repo = getattr(vulnerability_profile, "repo_name", "") or args.vuln_repo
    source_commit = getattr(vulnerability_profile, "affected_version", None)

    if not commit_hint and repo_name == source_repo and source_commit:
        commit_hint = source_commit

    if not commit_hint:
        repo_base_path = Path(getattr(args, "repo_base_path", _path_config["repo_base_path"])).expanduser()
        if not repo_base_path.is_absolute():
            repo_base_path = _path_config["repo_root"] / repo_base_path
        repo_path = repo_base_path / repo_name
        with hold_repo_lock(repo_path, purpose="resolve_manual_target_commit"):
            commit_hint = get_git_commit(str(repo_path))

    resolved_commit = resolve_profile_commit(repo_profiles_dir, repo_name, commit_hint)
    if not resolved_commit:
        if commit_hint:
            logger.error(
                f"Unable to resolve software profile commit for {repo_name} with hint {commit_hint[:12]}"
            )
        else:
            logger.error(f"Unable to resolve software profile commit for {repo_name}")
        return []

    return [ScanTarget(repo_name=repo_name, commit_hash=resolved_commit)]


def _resolve_auto_targets(
    args: argparse.Namespace,
    vulnerability_profile,
    repo_profiles_dir: Path,
) -> List[ScanTarget]:
    refs = load_all_software_profiles(repo_profiles_dir)
    if not refs:
        logger.error(f"No software profiles found under: {repo_profiles_dir}")
        return []

    source_repo = getattr(vulnerability_profile, "repo_name", "") or args.vuln_repo
    source_commit_hint = getattr(vulnerability_profile, "affected_version", None)
    source_ref = select_profile_ref(refs, source_repo, source_commit_hint)
    if not source_ref:
        logger.error(
            "Unable to find source software profile for auto-target selection: "
            f"{source_repo}@{(source_commit_hint or '')[:12]}"
        )
        return []

    logger.info(f"Auto-target source profile: {source_ref.label}")

    ablations = ablation_config_from_args(args)
    evaluation_mode = bool(getattr(args, "evaluation_mode", False))
    embedding_provenance: Dict[str, Any] = {}
    similarity_weights = None
    if ablations["repo_semantics"]:
        signature = embedding_model_artifact_signature(args.similarity_model_name)
        artifact_hash = str(signature.get("artifact_hash", "") or "").strip()
        embedding_provenance.update(
            {
                "backend": None,
                "model": args.similarity_model_name,
                "revision": artifact_hash or None,
                "revision_source": signature.get("fingerprint_type") if artifact_hash else None,
                "resolved_model_path": signature.get("resolved_model_path") or None,
                "device": args.similarity_device,
                "required": False,
                "fallback_used": False,
                "fallback_reason": None,
                "disabled_reason": "repo_semantics_ablation",
            }
        )
        text_retriever = None
        similarity_weights = REPO_STRUCTURE_ONLY_WEIGHTS
    else:
        text_retriever = build_text_retriever(
            model_name=args.similarity_model_name,
            device=args.similarity_device,
            require_embedding=evaluation_mode,
            provenance=embedding_provenance,
        )
    similarity_threshold = getattr(args, "similarity_threshold", None)
    ranked = rank_similar_profiles(
        source_ref=source_ref,
        candidate_refs=refs,
        top_k=args.top_k,
        min_overall_similarity=float(similarity_threshold or 0.0),
        text_retriever=text_retriever,
        weights=similarity_weights,
        require_embedding=evaluation_mode and not ablations["repo_semantics"],
        embedding_provenance=embedding_provenance,
        exclude_same_repo=not args.include_same_repo,
    )
    if not ranked:
        logger.error("No similar profiles found for auto-target mode")
        return []

    if similarity_threshold is None:
        logger.info(f"Selected top-{len(ranked)} similar targets:")
    else:
        logger.info(
            f"Selected {len(ranked)} similar targets with overall similarity >= {similarity_threshold:.3f}:"
        )
    for index, candidate in enumerate(ranked, 1):
        metrics = candidate.metrics
        logger.info(
            f"{index}. {candidate.profile_ref.label} "
            f"(overall={metrics.overall_sim:.4f}, "
            f"desc={metrics.description_sim:.4f}, "
            f"apps={metrics.target_application_sim:.4f}, "
            f"users={metrics.target_user_sim:.4f}, "
            f"module={metrics.module_jaccard_sim:.4f}, "
            f"dep/import={metrics.module_dependency_import_sim:.4f})"
        )

    return [
        ScanTarget(
            repo_name=candidate.profile_ref.repo_name,
            commit_hash=candidate.profile_ref.commit_hash,
            similarity=candidate,
            selection_provenance={
                "embedding": dict(embedding_provenance),
                "ablations": dict(ablations),
                "evaluation_mode": evaluation_mode,
            },
        )
        for candidate in ranked
    ]


def _build_run_provenance(
    *,
    target: ScanTarget,
    llm_client: Any,
    max_iterations: int,
    started_at: datetime,
    finished_at: Optional[datetime],
    actual_repo_commit: Optional[str],
    status: str,
    termination: Optional[str] = None,
    results: Optional[Dict[str, Any]] = None,
    quality: Optional[Dict[str, Any]] = None,
    usage_summary: Optional[Dict[str, Any]] = None,
    failure_reason: Optional[str] = None,
    ablation_config: Optional[Dict[str, Any]] = None,
    evaluation_mode: bool = False,
    model_revision: Optional[str] = None,
    model_revision_attestation_binding: Optional[Dict[str, str]] = None,
    endpoint_snapshot: Optional[Dict[str, str]] = None,
    endpoint_snapshot_sha256: Optional[str] = None,
    decoding_config_requested: Optional[Dict[str, Any]] = None,
    decoding_config_requested_sha256: Optional[str] = None,
    decoding_config_effective: Optional[Dict[str, Any]] = None,
    decoding_config_effective_sha256: Optional[str] = None,
    run_id: Optional[str] = None,
    scan_fingerprint: Optional[Dict[str, Any]] = None,
    frozen_input_hashes: Optional[Dict[str, Optional[str]]] = None,
    config_hashes: Optional[Dict[str, Optional[str]]] = None,
    reference_id: Optional[str] = None,
) -> Dict[str, Any]:
    """生成机器可读运行记录，未知值保留为 null。"""
    if status not in RUN_EXECUTION_STATUSES:
        raise ValueError(f"Invalid run provenance status: {status!r}")
    resolved_run_id = str(run_id or uuid.uuid4().hex)
    resolved_scan_fingerprint = (
        dict(scan_fingerprint) if isinstance(scan_fingerprint, dict) else None
    )
    llm_config = getattr(llm_client, "config", None)
    resolved_model_revision_attestation_binding = (
        validate_model_revision_attestation_binding(
            model_revision_attestation_binding
        )
        if model_revision_attestation_binding is not None
        else {}
    )
    result_payload = results if isinstance(results, dict) else {}
    quality_payload = quality if isinstance(quality, dict) else {}
    coverage_status = str(quality_payload.get("coverage_status", "unknown"))
    has_partial_output = status == "partial" or (
        status == "failed" and coverage_status in {"partial", "complete"}
    )
    has_reported_usage = bool(
        isinstance(usage_summary, dict)
        and (
            to_int(usage_summary.get("calls_total")) > 0
            or to_int(usage_summary.get("sessions_total")) > 0
            or to_int(usage_summary.get("turns_total")) > 0
        )
    )
    duration_seconds = (
        round((finished_at - started_at).total_seconds(), 6)
        if finished_at is not None
        else None
    )
    resolved_termination = result_payload.get("termination_reason") or termination
    if status in {"complete", "partial"} and not resolved_termination:
        resolved_termination = "finished"
    return {
        "run_id": resolved_run_id,
        "reference_id": reference_id,
        "schema_version": RUN_PROVENANCE_SCHEMA_VERSION,
        "kind": "scanner_run",
        "config_hashes": (
            dict(config_hashes)
            if isinstance(config_hashes, dict)
            else _scanner_config_hashes()
        ),
        "repo": {
            "name": target.repo_name,
            "requested_commit": target.commit_hash or None,
            "actual_commit": actual_repo_commit or None,
        },
        "llm": {
            "provider": getattr(llm_config, "provider", None),
            "model": getattr(llm_config, "model", None),
            "model_revision": model_revision,
            "model_revision_attestation": dict(
                resolved_model_revision_attestation_binding
            ),
            "endpoint_snapshot": dict(endpoint_snapshot or {}),
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "decoding_config_requested": dict(
                decoding_config_requested or {}
            ),
            "decoding_config_requested_sha256": (
                decoding_config_requested_sha256
            ),
            "decoding_config_effective": dict(
                decoding_config_effective or {}
            ),
            "decoding_config_effective_sha256": (
                decoding_config_effective_sha256
            ),
            "reasoning_effort": getattr(llm_config, "reasoning_effort", None),
            "enable_thinking": getattr(llm_config, "enable_thinking", None),
            "service_tier": getattr(llm_config, "service_tier", None),
            "fallback_on_retry_exhausted": bool(
                getattr(llm_config, "fallback_on_retry_exhausted", False)
            ),
            "exact_decoding_enforced": bool(
                getattr(llm_config, "enforce_exact_decoding", False)
            ),
        },
        "execution": {
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat() if finished_at is not None else None,
            "duration_seconds": duration_seconds,
            "iterations_requested": int(max_iterations),
            "iterations_completed": result_payload.get("iterations"),
            "iteration_durations_seconds": result_payload.get("iteration_durations_seconds"),
            "termination": resolved_termination,
            "status": status,
            "partial": has_partial_output,
            "failure_reason": failure_reason,
        },
        "coverage": quality_payload or None,
        "scan_fingerprint": resolved_scan_fingerprint,
        "input_hashes": {
            **dict(frozen_input_hashes or {}),
            "vulnerability_profile": (
                resolved_scan_fingerprint.get("vulnerability_profile_hash")
                if resolved_scan_fingerprint
                else None
            ),
            "target_software_profile": (
                resolved_scan_fingerprint.get("target_software_profile_hash")
                if resolved_scan_fingerprint
                else None
            ),
        },
        "usage": usage_summary if has_reported_usage else None,
        "usage_unavailable_reason": (
            None if has_reported_usage else "LLM client/provider did not report usage for this run"
        ),
        "evaluation_mode": bool(evaluation_mode),
        "ablations": normalize_ablation_config(ablation_config),
        "ablation_scope": {
            "repo_semantics": "target-selection semantic text features only",
            "reference_semantics": (
                "model-visible opaque CWE card only; full reference profile loading disabled; "
                "host priority plan retained as frozen control input"
            ),
            "candidate_priority": (
                "module ranking disabled; contiguous pages first-presented in an exact "
                "externally frozen global order; current structured repository-path "
                "enumeration and tool eligibility limited to active pending files; "
                "within-page visitation remains model-controlled and durably measured"
            ),
            "memory": (
                "functional LLM-visible shared public memory, semantic resume guidance, "
                "and explicit scanned/findings/progress prompt state; host cursor, page "
                "completion, first-presentation, reached-work, and finding-dedup control-plane "
                "ledgers retained"
            ),
            "verifier": (
                "scanner claim contract and same-vulnerability-type report gate only; "
                "external exploitability verification is controlled separately"
            ),
        },
        "selection_similarity": target.selection_provenance,
        "module_similarity": result_payload.get("module_similarity_provenance"),
        "candidate_order": result_payload.get("candidate_order_provenance"),
        "host_coverage_ledger": result_payload.get("host_coverage_ledger"),
        "host_coverage_evidence": result_payload.get("host_coverage_evidence"),
    }


def _fsync_directory(directory: Path) -> None:
    """持久提交同目录 rename 或 unlink。"""
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise ScanOutputCommitError(
            "durable scanner output writes are unsupported"
        )
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(directory, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_atomic_text_durable(path: Path, content: str) -> None:
    """原子替换文件并 fsync 所在目录。"""
    write_atomic_text(path, content)
    _fsync_directory(path.parent)


def _unlink_output_locator_durable(path: Path) -> None:
    """删除指定 scanner 定位符并持久记录。"""
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _invalidate_scan_output_commit(output_dir: Path) -> None:
    """新尝试前使旧终态输出失效。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    _unlink_output_locator_durable(
        output_dir / SCAN_OUTPUT_COMMIT_FILENAME
    )


def _write_run_state(
    output_dir: Path,
    provenance: Dict[str, Any],
) -> None:
    """在最终 provenance 外保存非终态运行状态。"""
    _invalidate_scan_output_commit(output_dir)
    _unlink_output_locator_durable(
        output_dir / SCAN_RUN_FAILURE_FILENAME
    )
    _write_atomic_text_durable(
        output_dir / SCAN_RUN_STATE_FILENAME,
        json.dumps(provenance, indent=2, ensure_ascii=False),
    )


def _write_run_failure(
    output_dir: Path,
    provenance: Dict[str, Any],
) -> None:
    """保存不能伪装成终态的显式失败 sidecar。"""
    _invalidate_scan_output_commit(output_dir)
    _unlink_output_locator_durable(
        output_dir / SCAN_RUN_STATE_FILENAME
    )
    _write_atomic_text_durable(
        output_dir / SCAN_RUN_FAILURE_FILENAME,
        json.dumps(provenance, indent=2, ensure_ascii=False),
    )


def _clear_nonfinal_run_records(output_dir: Path) -> None:
    """写终态 marker 前删除旧状态和失败记录。"""
    _unlink_output_locator_durable(
        output_dir / SCAN_RUN_STATE_FILENAME
    )
    _unlink_output_locator_durable(
        output_dir / SCAN_RUN_FAILURE_FILENAME
    )


def _write_run_provenance(
    output_dir: Path,
    provenance_text: str,
) -> None:
    """写最终 provenance；调用方必须最后发布 marker。"""
    _write_atomic_text_durable(
        output_dir / SCAN_PROVENANCE_FILENAME,
        provenance_text,
    )


_PREFLIGHT_INPUT_HASH_KEYS = (
    "target_software_profile_artifact",
    "target_path_projection_artifact",
    "reference_context_artifact",
    "unprioritized_file_schedule_artifact",
    "model_input_invariant_stage",
    "model_input_policy_stage",
    "model_input_control",
    "model_revision_attestation_file",
    "model_revision_attestation_payload",
    "endpoint_snapshot",
    "decoding_config_requested",
    "decoding_config_effective",
)


def _safe_preflight_path_component(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 200:
        return False
    allowed = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789._-"
    )
    return value not in {".", ".."} and all(char in allowed for char in value)


def _safe_preflight_commit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(char in "0123456789abcdef" for char in value)
    )


def _portable_preflight_run_id(value: Any) -> str:
    raw_value = str(value or uuid.uuid4().hex)
    allowed = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789._:-"
    )
    if (
        0 < len(raw_value) <= 256
        and all(char in allowed for char in raw_value)
    ):
        return raw_value
    digest = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    return f"preflight-{digest[:24]}"


def _preflight_failure_output_dir(
    *,
    output_base: Optional[str | Path],
    cve_id: Any,
    target: ScanTarget,
    run_id: str,
) -> Path:
    try:
        output_root = (
            resolve_cli_path(output_base, base_dir=_path_config["repo_root"])
            if output_base is not None
            else _path_config["results_base_path"] / "scan-results"
        )
    except (OSError, TypeError, ValueError):
        output_root = _path_config["results_base_path"] / "scan-results"
    if (
        _safe_preflight_path_component(cve_id)
        and _safe_preflight_path_component(target.repo_name)
        and _safe_preflight_commit(target.commit_hash)
    ):
        return output_root / str(cve_id) / (
            f"{target.repo_name}-{target.commit_hash[:12]}"
        )
    fallback_key = hashlib.sha256(run_id.encode("utf-8")).hexdigest()
    return output_root / "_preflight" / fallback_key


def _fixed_preflight_hashes(
    values: Optional[Dict[str, Any]] = None,
) -> Dict[str, Optional[str]]:
    raw = values if isinstance(values, dict) else {}
    return {
        key: raw.get(key) if is_lowercase_sha256(raw.get(key)) else None
        for key in _PREFLIGHT_INPUT_HASH_KEYS
    }


def _observed_inline_sha256(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_preflight_failure_provenance(
    *,
    cve_id: Any,
    output_base: Optional[str | Path],
    target: ScanTarget,
    llm_client: Any,
    llm_provider: Any,
    llm_model: Any,
    max_iterations: int,
    started_at: datetime,
    run_id: Any,
    error: Exception,
    stage: str,
    termination: str,
    failure_control: str,
    vulnerability_profile: Any = None,
    ablation_config: Optional[Dict[str, Any]] = None,
    evaluation_mode: bool = False,
    model_revision: Optional[str] = None,
    model_revision_attestation_binding: Optional[Dict[str, str]] = None,
    endpoint_snapshot: Optional[Dict[str, str]] = None,
    endpoint_snapshot_sha256: Optional[str] = None,
    decoding_config_requested: Optional[Dict[str, Any]] = None,
    decoding_config_requested_sha256: Optional[str] = None,
    decoding_config_effective: Optional[Dict[str, Any]] = None,
    decoding_config_effective_sha256: Optional[str] = None,
    verified_input_hashes: Optional[Dict[str, Any]] = None,
    declared_input_hashes: Optional[Dict[str, Any]] = None,
    observed_input_hashes: Optional[Dict[str, Any]] = None,
) -> Path:
    portable_run_id = _portable_preflight_run_id(run_id)
    safe_repo = (
        target.repo_name
        if _safe_preflight_path_component(target.repo_name)
        else ""
    )
    safe_commit = (
        target.commit_hash
        if _safe_preflight_commit(target.commit_hash)
        else ""
    )
    safe_target = ScanTarget(
        repo_name=safe_repo,
        commit_hash=safe_commit,
        selection_provenance=None,
    )
    frozen_hashes = _fixed_preflight_hashes(verified_input_hashes)
    # 投影可声明目标画像绑定，但这些失败点尚未加载画像字节。
    frozen_hashes["target_software_profile_artifact"] = None
    failure_reason = f"{type(error).__name__}: {termination}"
    provenance = _build_run_provenance(
        target=safe_target,
        llm_client=llm_client,
        max_iterations=max_iterations,
        started_at=started_at,
        finished_at=datetime.now(),
        actual_repo_commit=None,
        status="failed",
        termination=termination,
        failure_reason=failure_reason,
        ablation_config=ablation_config,
        evaluation_mode=evaluation_mode,
        model_revision=model_revision,
        model_revision_attestation_binding=(
            model_revision_attestation_binding
        ),
        endpoint_snapshot=endpoint_snapshot,
        endpoint_snapshot_sha256=endpoint_snapshot_sha256,
        decoding_config_requested=decoding_config_requested,
        decoding_config_requested_sha256=decoding_config_requested_sha256,
        decoding_config_effective=decoding_config_effective,
        decoding_config_effective_sha256=decoding_config_effective_sha256,
        run_id=portable_run_id,
        scan_fingerprint=None,
        frozen_input_hashes=frozen_hashes,
        config_hashes=_failure_scanner_config_hashes(),
        reference_id=(
            cve_id
            if _safe_preflight_path_component(cve_id)
            else None
        ),
    )
    provenance["llm"]["provider"] = (
        llm_provider if isinstance(llm_provider, str) else None
    )
    provenance["llm"]["model"] = (
        llm_model if isinstance(llm_model, str) else None
    )
    provenance["execution"].update(
        {
            "stage": stage,
            "failure_control": failure_control,
            "failure_class": type(error).__name__,
            "blocker_code": (
                MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE
                if (
                    failure_control == "module_similarity_embedding"
                    and isinstance(
                        error,
                        EvaluationEvidenceUnavailableError,
                    )
                )
                else None
            ),
        }
    )
    provenance["input_hashes"].update(
        {
            "endpoint_snapshot": (
                endpoint_snapshot_sha256
                if is_lowercase_sha256(endpoint_snapshot_sha256)
                else None
            ),
            "decoding_config_requested": (
                decoding_config_requested_sha256
                if is_lowercase_sha256(decoding_config_requested_sha256)
                else None
            ),
            "decoding_config_effective": (
                decoding_config_effective_sha256
                if is_lowercase_sha256(decoding_config_effective_sha256)
                else None
            ),
        }
    )
    try:
        provenance["input_hashes"]["vulnerability_profile"] = (
            _profile_hash(vulnerability_profile)
            if vulnerability_profile is not None
            else None
        )
    except (TypeError, ValueError):
        provenance["input_hashes"]["vulnerability_profile"] = None
    provenance["input_hashes"]["target_software_profile"] = None
    provenance["declared_input_hashes"] = _fixed_preflight_hashes(
        declared_input_hashes
    )
    provenance["observed_input_hashes"] = _fixed_preflight_hashes(
        observed_input_hashes
    )
    output_dir = _preflight_failure_output_dir(
        output_base=output_base,
        cve_id=cve_id,
        target=safe_target,
        run_id=portable_run_id,
    )
    _write_run_failure(output_dir, provenance)
    return output_dir / SCAN_RUN_FAILURE_FILENAME


def _durable_preflight_failure(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        call_kwargs = dict(kwargs)
        call_kwargs["run_id"] = str(
            call_kwargs.get("run_id") or uuid.uuid4().hex
        )
        started_at = datetime.now()
        try:
            return func(*args, **call_kwargs)
        except (OSError, ValueError) as exc:
            target = call_kwargs.get("target")
            if not isinstance(target, ScanTarget):
                target = ScanTarget("", "")
            target_path_projection = call_kwargs.get("target_path_projection")
            verified_hashes: Dict[str, Any] = {}
            if isinstance(target_path_projection, dict):
                try:
                    _validate_verified_model_input_control(
                        target_path_projection
                    )
                    verified_hashes.update(
                        _frozen_control_input_hashes(
                            target_path_projection
                        )
                    )
                except ValueError:
                    pass
            verified_hashes["target_software_profile_artifact"] = None

            endpoint_snapshot = None
            endpoint_snapshot_sha256 = None
            if (
                call_kwargs.get("endpoint_snapshot") is not None
                or call_kwargs.get("endpoint_snapshot_sha256") is not None
            ):
                try:
                    (
                        endpoint_snapshot,
                        endpoint_snapshot_sha256,
                    ) = validate_endpoint_snapshot_payload(
                        call_kwargs.get("endpoint_snapshot"),
                        call_kwargs.get("endpoint_snapshot_sha256"),
                    )
                except ValueError:
                    endpoint_snapshot = None
                    endpoint_snapshot_sha256 = None

            decoding_config_requested = None
            decoding_config_requested_sha256 = None
            if (
                call_kwargs.get("decoding_config_requested") is not None
                or call_kwargs.get("decoding_config_requested_sha256")
                is not None
            ):
                try:
                    (
                        decoding_config_requested,
                        decoding_config_requested_sha256,
                    ) = validate_decoding_config_payload(
                        call_kwargs.get("decoding_config_requested"),
                        call_kwargs.get(
                            "decoding_config_requested_sha256"
                        ),
                    )
                except ValueError:
                    decoding_config_requested = None
                    decoding_config_requested_sha256 = None

            decoding_config_effective = None
            decoding_config_effective_sha256 = None
            llm_client = call_kwargs.get("llm_client")
            try:
                effective = _effective_client_decoding_config(llm_client)
                effective_json = json.dumps(
                    effective,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                effective_sha256 = hashlib.sha256(
                    effective_json.encode("utf-8")
                ).hexdigest()
                (
                    decoding_config_effective,
                    decoding_config_effective_sha256,
                ) = validate_decoding_config_payload(
                    effective,
                    effective_sha256,
                )
            except (TypeError, ValueError):
                decoding_config_effective = None
                decoding_config_effective_sha256 = None

            projection_provenance = (
                target_path_projection.get("provenance", {})
                if isinstance(target_path_projection, dict)
                else {}
            )
            stage_hashes = (
                projection_provenance.get(
                    "model_input_stage_hashes",
                    {},
                )
                if isinstance(projection_provenance, dict)
                else {}
            )
            declared_hashes = {
                "target_software_profile_artifact": (
                    projection_provenance.get(
                        "bound_target_software_profile_sha256"
                    )
                    if isinstance(projection_provenance, dict)
                    else None
                ),
                "target_path_projection_artifact": (
                    projection_provenance.get("artifact_sha256")
                    if isinstance(projection_provenance, dict)
                    else None
                ),
                "model_input_invariant_stage": (
                    stage_hashes.get("invariant_preprocessing")
                    if isinstance(stage_hashes, dict)
                    else None
                ),
                "model_input_policy_stage": (
                    stage_hashes.get("policy_specific_eligibility")
                    if isinstance(stage_hashes, dict)
                    else None
                ),
                "model_input_control": (
                    projection_provenance.get(
                        "model_input_control_sha256"
                    )
                    if isinstance(projection_provenance, dict)
                    else None
                ),
                "endpoint_snapshot": call_kwargs.get(
                    "endpoint_snapshot_sha256"
                ),
                "decoding_config_requested": call_kwargs.get(
                    "decoding_config_requested_sha256"
                ),
                "decoding_config_effective": (
                    decoding_config_effective_sha256
                ),
            }
            raw_model_revision_attestation = call_kwargs.get(
                "model_revision_attestation"
            )
            raw_attestation_binding = (
                raw_model_revision_attestation.get("binding", {})
                if isinstance(raw_model_revision_attestation, dict)
                else {}
            )
            declared_hashes.update(
                {
                    "model_revision_attestation_file": (
                        raw_attestation_binding.get("file_sha256")
                        if isinstance(raw_attestation_binding, dict)
                        else None
                    ),
                    "model_revision_attestation_payload": (
                        raw_attestation_binding.get("payload_sha256")
                        if isinstance(raw_attestation_binding, dict)
                        else None
                    ),
                }
            )
            model_revision_attestation_binding: Dict[str, str] = {}
            llm_config = getattr(llm_client, "config", None)
            if raw_model_revision_attestation is not None:
                try:
                    resolved_attestation = (
                        validate_model_revision_attestation_payload(
                            raw_model_revision_attestation,
                            provider=getattr(
                                llm_config,
                                "provider",
                                None,
                            ),
                            model_name=getattr(
                                llm_config,
                                "model",
                                None,
                            ),
                            model_revision=call_kwargs.get(
                                "model_revision"
                            ),
                            endpoint_snapshot_sha256=(
                                endpoint_snapshot_sha256
                            ),
                        )
                    )
                    model_revision_attestation_binding = dict(
                        resolved_attestation["binding"]
                    )
                    verified_hashes[
                        "model_revision_attestation_file"
                    ] = model_revision_attestation_binding[
                        "file_sha256"
                    ]
                    verified_hashes[
                        "model_revision_attestation_payload"
                    ] = model_revision_attestation_binding[
                        "payload_sha256"
                    ]
                except ValueError:
                    model_revision_attestation_binding = {}
            observed_hashes = {
                **verified_hashes,
                "endpoint_snapshot": endpoint_snapshot_sha256,
                "decoding_config_requested": (
                    decoding_config_requested_sha256
                ),
                "decoding_config_effective": (
                    decoding_config_effective_sha256
                ),
            }
            evaluation_mode = bool(
                call_kwargs.get("evaluation_mode", False)
            )
            try:
                _write_preflight_failure_provenance(
                    cve_id=call_kwargs.get("cve_id"),
                    output_base=call_kwargs.get("output_base"),
                    target=target,
                    llm_client=llm_client,
                    llm_provider=getattr(llm_config, "provider", None),
                    llm_model=getattr(llm_config, "model", None),
                    max_iterations=int(
                        call_kwargs.get("max_iterations", 0)
                    ),
                    started_at=started_at,
                    run_id=call_kwargs["run_id"],
                    error=exc,
                    stage=(
                        "evaluation_precheck"
                        if evaluation_mode
                        else "scan_preflight"
                    ),
                    termination=(
                        "evaluation_precheck_failure"
                        if evaluation_mode
                        else "preflight_validation_failure"
                    ),
                    failure_control=(
                        "module_similarity_embedding"
                        if isinstance(
                            exc,
                            EvaluationEvidenceUnavailableError,
                        )
                        else (
                            "evaluation_contract"
                            if evaluation_mode
                            else "scan_contract"
                        )
                    ),
                    vulnerability_profile=call_kwargs.get(
                        "vulnerability_profile"
                    ),
                    ablation_config=call_kwargs.get("ablation_config"),
                    evaluation_mode=evaluation_mode,
                    model_revision=call_kwargs.get("model_revision"),
                    model_revision_attestation_binding=(
                        model_revision_attestation_binding or None
                    ),
                    endpoint_snapshot=endpoint_snapshot,
                    endpoint_snapshot_sha256=(
                        endpoint_snapshot_sha256
                    ),
                    decoding_config_requested=(
                        decoding_config_requested
                    ),
                    decoding_config_requested_sha256=(
                        decoding_config_requested_sha256
                    ),
                    decoding_config_effective=(
                        decoding_config_effective
                    ),
                    decoding_config_effective_sha256=(
                        decoding_config_effective_sha256
                    ),
                    verified_input_hashes=verified_hashes,
                    declared_input_hashes=declared_hashes,
                    observed_input_hashes=observed_hashes,
                )
            except Exception as provenance_exc:  # pylint: disable=broad-except
                logger.error(
                    "Failed to persist sanitized preflight provenance: %s",
                    type(provenance_exc).__name__,
                )
            raise

    return wrapped


def _write_target_selection_failure_provenance(
    *,
    args: argparse.Namespace,
    vulnerability_profile: Any,
    started_at: datetime,
    run_id: str,
    error: EmbeddingUnavailableError,
    model_revision_attestation_binding: Optional[Dict[str, str]] = None,
) -> Path:
    """尚无目标时保存根级失败关闭记录。"""
    finished_at = datetime.now()
    resolved_model_revision_attestation_binding = (
        validate_model_revision_attestation_binding(
            model_revision_attestation_binding
        )
        if model_revision_attestation_binding is not None
        else {}
    )
    embedding = dict(getattr(error, "embedding_provenance", {}) or {})
    if not embedding:
        signature = embedding_model_artifact_signature(
            getattr(args, "similarity_model_name", None)
        )
        artifact_hash = str(signature.get("artifact_hash", "") or "").strip()
        embedding = {
            "backend": None,
            "model": getattr(args, "similarity_model_name", None),
            "revision": artifact_hash or None,
            "revision_source": (
                signature.get("fingerprint_type") if artifact_hash else None
            ),
            "resolved_model_path": signature.get("resolved_model_path") or None,
            "device": getattr(args, "similarity_device", None),
            "required": True,
            "fallback_used": False,
            "fallback_reason": f"{type(error).__name__}: {error}",
        }
    output_arg = getattr(args, "output", None)
    output_root = (
        resolve_cli_path(output_arg, base_dir=_path_config["repo_root"])
        if output_arg
        else _path_config["results_base_path"] / "scan-results"
    )
    endpoint_snapshot: Optional[Dict[str, str]] = None
    endpoint_snapshot_sha256: Optional[str] = None
    decoding_config_requested: Optional[Dict[str, Any]] = None
    decoding_config_requested_sha256: Optional[str] = None
    if getattr(args, "endpoint_snapshot_json", None) is not None:
        endpoint_snapshot, endpoint_snapshot_sha256 = (
            validate_endpoint_snapshot_contract(
                args.endpoint_snapshot_json,
                args.endpoint_snapshot_sha256,
            )
        )
    if getattr(args, "decoding_config_json", None) is not None:
        (
            decoding_config_requested,
            decoding_config_requested_sha256,
        ) = validate_decoding_config_contract(
            args.decoding_config_json,
            args.decoding_config_sha256,
        )
    provenance = {
        "schema_version": RUN_PROVENANCE_SCHEMA_VERSION,
        "config_hashes": _failure_scanner_config_hashes(),
        "kind": "scanner_target_selection",
        "run_id": run_id,
        "target": None,
        "input_hashes": {
            "vulnerability_profile": _profile_hash(vulnerability_profile),
            "target_software_profile": None,
            "model_revision_attestation_file": (
                resolved_model_revision_attestation_binding.get(
                    "file_sha256"
                )
            ),
            "model_revision_attestation_payload": (
                resolved_model_revision_attestation_binding.get(
                    "payload_sha256"
                )
            ),
        },
        "llm": {
            "provider": getattr(args, "llm_provider", None),
            "model": getattr(args, "llm_name", None),
            "model_revision": getattr(args, "model_revision", None),
            "model_revision_attestation": dict(
                resolved_model_revision_attestation_binding
            ),
            "endpoint_snapshot": dict(endpoint_snapshot or {}),
            "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
            "decoding_config_requested": dict(
                decoding_config_requested or {}
            ),
            "decoding_config_requested_sha256": (
                decoding_config_requested_sha256
            ),
            "decoding_config_effective": dict(
                decoding_config_requested or {}
            ),
            "decoding_config_effective_sha256": (
                decoding_config_requested_sha256
            ),
        },
        "embedding": embedding,
        "evaluation_mode": bool(getattr(args, "evaluation_mode", False)),
        "ablations": ablation_config_from_args(args),
        "execution": {
            "stage": "target_selection",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
            "status": "failed",
            "partial": False,
            "termination": "embedding_unavailable",
            "error": f"{type(error).__name__}: {error}",
        },
    }
    _write_run_failure(output_root, provenance)
    return output_root / SCAN_RUN_FAILURE_FILENAME


def _save_scan_outputs(
    output_dir: Path,
    finder: AgenticVulnFinder,
    results: Dict[str, object],
    target: ScanTarget,
    scan_fingerprint: Optional[Dict[str, Any]] = None,
    run_provenance: Optional[Dict[str, Any]] = None,
    quality_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """发布一组终态结果，最后写提交 marker。"""
    if not isinstance(scan_fingerprint, dict):
        raise ScanOutputCommitError(
            "scan fingerprint must be a JSON object"
        )
    if not isinstance(run_provenance, dict):
        raise ScanOutputCommitError(
            "run provenance must be a JSON object"
        )
    provenance_fingerprint = run_provenance.get("scan_fingerprint")
    if (
        not isinstance(provenance_fingerprint, dict)
        or provenance_fingerprint != scan_fingerprint
    ):
        raise ScanOutputCommitError(
            "scan fingerprint mismatch between findings and run provenance"
        )
    fingerprint_payload = dict(scan_fingerprint)
    fingerprint_hash = fingerprint_payload.pop("hash", None)
    if (
        not is_lowercase_sha256(fingerprint_hash)
        or stable_data_hash(fingerprint_payload) != fingerprint_hash
    ):
        raise ScanOutputCommitError(
            "scan fingerprint self-hash is invalid"
        )
    run_id = run_provenance.get("run_id")
    execution = run_provenance.get("execution")
    scan_config = scan_fingerprint.get("scan_config")
    terminal_status = (
        execution.get("status") if isinstance(execution, dict) else None
    )
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(scan_config, dict)
        or scan_config.get("run_id") != run_id
        or terminal_status not in {"complete", "partial"}
    ):
        raise ScanOutputCommitError(
            "scan run identity or terminal status is invalid"
        )

    results_payload: Dict[str, Any] = dict(results)
    results_payload.update(
        dict(quality_metadata)
        if isinstance(quality_metadata, dict)
        else _build_scan_quality_metadata(finder)
    )
    results_payload["run_provenance"] = run_provenance
    results_payload["scan_fingerprint"] = scan_fingerprint
    if (
        results_payload.get("scan_fingerprint")
        != results_payload["run_provenance"].get("scan_fingerprint")
    ):
        raise ScanOutputCommitError(
            "scan fingerprint copies disagree before serialization"
        )

    provenance_text = json.dumps(
        run_provenance,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    findings_text = json.dumps(
        results_payload,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    conversation_text = json.dumps(
        make_serializable(finder.conversation_history),
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    similarity_text: Optional[str] = None
    if target.similarity:
        similarity_text = json.dumps(
            target.similarity.to_dict(),
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )

    _invalidate_scan_output_commit(output_dir)
    _unlink_output_locator_durable(
        output_dir / SCAN_FINGERPRINT_FILENAME
    )
    if similarity_text is None:
        _unlink_output_locator_durable(
            output_dir / SCAN_SIMILARITY_FILENAME
        )

    _write_run_provenance(output_dir, provenance_text)
    output_path = output_dir / SCAN_FINDINGS_FILENAME
    _write_atomic_text_durable(output_path, findings_text)
    conversation_path = output_dir / SCAN_CONVERSATION_FILENAME
    _write_atomic_text_durable(conversation_path, conversation_text)
    if similarity_text is not None:
        _write_atomic_text_durable(
            output_dir / SCAN_SIMILARITY_FILENAME,
            similarity_text,
        )

    artifact_bytes: Dict[str, bytes] = {
        SCAN_PROVENANCE_FILENAME: provenance_text.encode("utf-8"),
        SCAN_FINDINGS_FILENAME: findings_text.encode("utf-8"),
        SCAN_CONVERSATION_FILENAME: conversation_text.encode("utf-8"),
    }
    if similarity_text is not None:
        artifact_bytes[SCAN_SIMILARITY_FILENAME] = (
            similarity_text.encode("utf-8")
        )
    memory_path = output_dir / SCAN_MEMORY_FILENAME
    try:
        memory_path.lstat()
    except FileNotFoundError:
        pass
    else:
        artifact_bytes[SCAN_MEMORY_FILENAME] = read_stable_scan_artifact(
            output_dir,
            SCAN_MEMORY_FILENAME,
        )

    marker = build_scan_output_commit(
        reference_id=run_provenance.get("reference_id"),
        terminal_status=terminal_status,
        run_id=run_id,
        scan_fingerprint_hash=fingerprint_hash,
        artifact_bytes=artifact_bytes,
    )
    marker_text = json.dumps(
        marker,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    marker_sha256 = hashlib.sha256(
        marker_text.encode("utf-8")
    ).hexdigest()
    _clear_nonfinal_run_records(output_dir)
    _write_atomic_text_durable(
        output_dir / SCAN_OUTPUT_COMMIT_FILENAME,
        marker_text,
    )
    try:
        validate_committed_scan_outputs(
            output_dir,
            expected_commit_sha256=marker_sha256,
            require_complete=terminal_status == "complete",
        )
    except ScanOutputCommitError:
        # 校验失败时立即撤销 marker；旧文件仍可用于排查，但不能被当成终态。
        _invalidate_scan_output_commit(output_dir)
        raise

    logger.info(f"Results saved to: {output_path}")
    logger.info(f"Conversation history saved to: {conversation_path}")
    logger.info(
        "Terminal scanner output commit saved to: %s",
        output_dir / SCAN_OUTPUT_COMMIT_FILENAME,
    )
    return {
        "path": output_dir / SCAN_OUTPUT_COMMIT_FILENAME,
        "sha256": marker_sha256,
        "terminal_status": terminal_status,
    }


def _profile_hash(profile: Any) -> str:
    """Prefer persisted profile fingerprints; fall back to a stable profile hash."""
    persisted_fingerprint = extract_profile_fingerprint(profile)
    persisted_hash = str(persisted_fingerprint.get("hash", "")).strip()
    if persisted_hash:
        return persisted_hash
    profile_payload = profile.to_dict() if hasattr(profile, "to_dict") else profile
    return stable_data_hash(profile_payload)


def build_scan_fingerprint(
    *,
    vulnerability_profile: Any,
    software_profile: Any,
    llm_client: Any,
    max_iterations: int,
    stop_when_critical_complete: bool,
    critical_stop_mode: str,
    critical_stop_max_priority: int,
    require_full_universe_completion: bool = False,
    scan_languages: List[str],
    codeql_database_names: Dict[str, str],
    shared_public_memory_scope: Optional[Dict[str, Any]] = None,
    module_similarity_config: Optional[Dict[str, Any]] = None,
    ablation_config: Optional[Dict[str, Any]] = None,
    reference_context_provenance: Optional[Dict[str, Any]] = None,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
    target_path_projection: Optional[Dict[str, Any]] = None,
    model_visible_input_runtime_projection: Optional[Dict[str, Any]] = None,
    model_revision: Optional[str] = None,
    model_revision_attestation_binding: Optional[Dict[str, str]] = None,
    endpoint_snapshot: Optional[Dict[str, str]] = None,
    endpoint_snapshot_sha256: Optional[str] = None,
    decoding_config_requested: Optional[Dict[str, Any]] = None,
    decoding_config_requested_sha256: Optional[str] = None,
    decoding_config_effective: Optional[Dict[str, Any]] = None,
    decoding_config_effective_sha256: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a reproducibility fingerprint for one target scan result."""
    llm_config = getattr(llm_client, "config", None)
    cli_root = Path(__file__).resolve().parent
    source_root = cli_root.parent
    shared_memory_scope = shared_public_memory_scope or {}
    resolved_module_similarity_config = resolve_module_similarity_config(
        module_similarity_config
    )
    resolved_module_similarity_model = str(
        resolved_module_similarity_config.get("model_name", "")
    ).strip()
    observed_module_similarity = observed_module_similarity_metadata(
        resolved_module_similarity_config,
        embedding_model_artifact_signature(
            resolved_module_similarity_model or None
        ),
    )
    normalized_ablation_config = normalize_ablation_config(ablation_config)
    resolved_model_revision_attestation_binding = (
        validate_model_revision_attestation_binding(
            model_revision_attestation_binding
        )
        if model_revision_attestation_binding is not None
        else {}
    )
    schedule_provenance = (
        unprioritized_file_schedule.get("provenance", {})
        if isinstance(unprioritized_file_schedule, dict)
        else {}
    )
    projection_metadata = (
        dict(target_path_projection.get("provenance", {}))
        if isinstance(target_path_projection, dict)
        and isinstance(target_path_projection.get("provenance"), dict)
        else dict(target_path_projection or {})
    )
    runtime_projection_metadata = dict(
        model_visible_input_runtime_projection or {}
    )
    if endpoint_snapshot is not None or endpoint_snapshot_sha256 is not None:
        (
            resolved_endpoint_snapshot,
            resolved_endpoint_snapshot_sha256,
        ) = validate_endpoint_snapshot_payload(
            endpoint_snapshot,
            endpoint_snapshot_sha256,
        )
    else:
        resolved_endpoint_snapshot = {}
        resolved_endpoint_snapshot_sha256 = None
    if (
        decoding_config_requested is not None
        or decoding_config_requested_sha256 is not None
    ):
        (
            resolved_decoding_config_requested,
            resolved_decoding_config_requested_sha256,
        ) = validate_decoding_config_payload(
            decoding_config_requested,
            decoding_config_requested_sha256,
        )
    else:
        resolved_decoding_config_requested = {}
        resolved_decoding_config_requested_sha256 = None
    if (
        decoding_config_effective is not None
        or decoding_config_effective_sha256 is not None
    ):
        (
            resolved_decoding_config_effective,
            resolved_decoding_config_effective_sha256,
        ) = validate_decoding_config_payload(
            decoding_config_effective,
            decoding_config_effective_sha256,
        )
    else:
        resolved_decoding_config_effective = {}
        resolved_decoding_config_effective_sha256 = None
    target_profile_artifact_sha256 = str(
        projection_metadata.get("bound_target_software_profile_sha256", "")
        or projection_metadata.get("target_software_profile_sha256", "")
        or (
            schedule_provenance.get("target_software_profile_sha256", "")
            if isinstance(schedule_provenance, dict)
            else ""
        )
    ).strip()
    payload = {
        "schema_version": SCAN_FINGERPRINT_SCHEMA_VERSION,
        "kind": "scan_result",
        "vulnerability_profile_hash": _profile_hash(vulnerability_profile),
        "target_software_profile_hash": _profile_hash(software_profile),
        "target_software_profile_artifact_sha256": (
            target_profile_artifact_sha256 or None
        ),
        "target_path_projection_artifact_sha256": (
            projection_metadata.get("artifact_sha256") or None
        ),
        "llm": {
            "provider": getattr(llm_config, "provider", ""),
            "model": getattr(llm_config, "model", ""),
            "model_revision": model_revision,
            "model_revision_attestation": dict(
                resolved_model_revision_attestation_binding
            ),
            "endpoint_snapshot": resolved_endpoint_snapshot,
            "endpoint_snapshot_sha256": resolved_endpoint_snapshot_sha256,
            "decoding_config_requested": (
                resolved_decoding_config_requested
            ),
            "decoding_config_requested_sha256": (
                resolved_decoding_config_requested_sha256
            ),
            "decoding_config_effective": (
                resolved_decoding_config_effective
            ),
            "decoding_config_effective_sha256": (
                resolved_decoding_config_effective_sha256
            ),
            "base_url": getattr(llm_config, "base_url", ""),
            "temperature": getattr(llm_config, "temperature", None),
            "top_p": getattr(llm_config, "top_p", None),
            "max_tokens": getattr(llm_config, "max_tokens", None),
            "enable_thinking": getattr(llm_config, "enable_thinking", None),
            "reasoning_effort": getattr(llm_config, "reasoning_effort", None),
            "service_tier": getattr(llm_config, "service_tier", None),
            "fallback_on_retry_exhausted": bool(
                getattr(llm_config, "fallback_on_retry_exhausted", False)
            ),
            "exact_decoding_enforced": bool(
                getattr(llm_config, "enforce_exact_decoding", False)
            ),
        },
        "scan_config": {
            "run_id": str(run_id or ""),
            "max_iterations": int(max_iterations),
            "stop_when_critical_complete": bool(stop_when_critical_complete),
            "critical_stop_mode": str(critical_stop_mode),
            "critical_stop_max_priority": int(critical_stop_max_priority),
            "require_full_universe_completion": bool(
                require_full_universe_completion
            ),
            "scan_languages": list(scan_languages or []),
            "codeql_database_names": dict(codeql_database_names or {}),
            "shared_public_memory": {
                "enabled": bool(shared_memory_scope.get("enabled", False)),
                "root_hash": str(shared_memory_scope.get("root_hash", "")).strip(),
                "scope_key": str(shared_memory_scope.get("scope_key", "")).strip(),
                "state_hash": str(shared_memory_scope.get("state_hash", "")).strip(),
            },
            "model_visible_input_projection": projection_metadata,
            "model_revision_attestation": dict(
                resolved_model_revision_attestation_binding
            ),
            "model_visible_input_runtime_projection": (
                runtime_projection_metadata
            ),
            "endpoint_snapshot": resolved_endpoint_snapshot,
            "endpoint_snapshot_sha256": resolved_endpoint_snapshot_sha256,
            "decoding_config_requested": (
                resolved_decoding_config_requested
            ),
            "decoding_config_requested_sha256": (
                resolved_decoding_config_requested_sha256
            ),
            "decoding_config_effective": (
                resolved_decoding_config_effective
            ),
            "decoding_config_effective_sha256": (
                resolved_decoding_config_effective_sha256
            ),
            "model_input_stage_hashes": dict(
                projection_metadata.get("model_input_stage_hashes", {})
            ),
            "module_similarity": observed_module_similarity,
            "module_similarity_byte_binding": (
                module_similarity_byte_binding()
            ),
            "ablations": normalized_ablation_config,
            "reference_context": dict(reference_context_provenance or {}),
            "unprioritized_file_schedule": dict(unprioritized_file_schedule or {}),
        },
        "config_hashes": _scanner_config_hashes(),
        "source_hashes": hash_python_source_tree(source_root),
    }
    return {
        **payload,
        "hash": stable_data_hash(payload),
    }


def _build_scan_quality_metadata(finder: AgenticVulnFinder) -> Dict[str, Any]:
    """Summarize scan coverage quality for result files and batch summaries."""
    memory = getattr(finder, "memory", None)
    if memory is None:
        return {
            "coverage_status": "unknown",
            "critical_scope_present": False,
            "critical_complete": False,
            "critical_scope_total_files": 0,
            "critical_scope_completed_files": 0,
            "scan_progress": {},
        }

    progress = memory.get_progress()
    priority_1 = progress.get("priority_1", {})
    priority_2 = progress.get("priority_2", {})
    critical_stop_max_priority = int(getattr(finder, "critical_stop_max_priority", 2))
    if critical_stop_max_priority not in {1, 2}:
        critical_stop_max_priority = 2
    critical_scope_total = int(priority_1.get("total", 0))
    critical_scope_completed = int(priority_1.get("completed", 0))
    if critical_stop_max_priority >= 2:
        critical_scope_total += int(priority_2.get("total", 0))
        critical_scope_completed += int(priority_2.get("completed", 0))
    completed_files = int(progress.get("completed", 0))
    total_files = int(progress.get("total_files", 0))
    findings = int(progress.get("findings", 0))
    critical_complete = (
        critical_scope_total > 0
        and bool(
            memory.is_critical_complete(
                max_priority=critical_stop_max_priority
            )
        )
    )
    full_universe_required = bool(
        getattr(finder, "require_full_universe_completion", False)
    )
    full_universe_check = getattr(
        finder,
        "_is_full_universe_complete",
        None,
    )
    full_universe_complete = (
        bool(full_universe_check())
        if callable(full_universe_check)
        else total_files > 0 and completed_files == total_files
    )

    # Coverage status should reflect the configured critical scan scope rather
    # than all lower-priority pending files.
    if critical_scope_total <= 0:
        coverage_status = (
            "partial" if completed_files > 0 or findings > 0 else "empty"
        )
    elif full_universe_required:
        coverage_status = "complete" if full_universe_complete else "partial"
    elif critical_complete:
        coverage_status = "complete"
    elif completed_files > 0 or findings > 0:
        coverage_status = "partial"
    else:
        coverage_status = "empty"

    return {
        "coverage_status": coverage_status,
        "critical_scope_present": critical_scope_total > 0,
        "critical_complete": critical_complete,
        "critical_scope_total_files": critical_scope_total,
        "critical_scope_completed_files": critical_scope_completed,
        "full_universe_required": full_universe_required,
        "full_universe_complete": full_universe_complete,
        "full_universe_total_files": total_files,
        "full_universe_completed_files": completed_files,
        "scan_progress": progress,
    }


def _resolve_soft_profiles_dir_for_scan(
    profile_base_path: Optional[str],
    software_profile_dirname: Optional[str],
) -> Path:
    return resolve_profile_dirs(
        profile_base_path=profile_base_path,
        software_profile_dirname=software_profile_dirname,
        vuln_profile_dirname=None,
    )[0]


def _resolve_scheduled_target_profile_sha256(
    unprioritized_file_schedule: Optional[Dict[str, Any]],
) -> str:
    """解析冻结 schedule 携带的严格画像原始哈希。"""
    schedule = unprioritized_file_schedule or {}
    provenance = schedule.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError(
            "candidate-priority ablation schedule provenance must be an object"
        )
    expected_sha256 = str(
        provenance.get("target_software_profile_sha256", "") or ""
    ).strip()
    if (
        not is_lowercase_sha256(expected_sha256)
        or expected_sha256 != expected_sha256.lower()
    ):
        raise ValueError(
            "candidate-priority ablation requires a hash-bound target software profile"
        )
    return expected_sha256


def _load_hash_bound_software_profile(
    *,
    repo_name: str,
    commit_hash: str,
    base_dir: Path,
    expected_sha256: str,
) -> SoftwareProfile:
    """画像只加载一次，并用同一份哈希校验 payload 扫描。"""
    profile_path = base_dir / repo_name / commit_hash / "software_profile.json"
    _artifact_path, payload, _actual_sha256 = _load_frozen_json_artifact(
        str(profile_path),
        expected_sha256,
        label="target software profile",
    )
    software_profile = SoftwareProfile.from_dict(payload)
    normalized_payload = software_profile.to_dict()
    if normalized_payload != payload:
        raise ValueError(
            "target software profile payload is not losslessly represented by SoftwareProfile"
        )
    if software_profile.name != repo_name or software_profile.version != commit_hash:
        raise ValueError(
            "target software profile identity does not match the requested repository/commit"
        )
    return software_profile


@_durable_preflight_failure
def run_single_target_scan(
    *,
    cve_id: str,
    output_base: str | Path,
    repo_base_path: str | Path,
    max_iterations: int,
    vulnerability_profile,
    llm_client,
    target: ScanTarget,
    verbose: bool = False,
    stop_when_critical_complete: bool = False,
    critical_stop_mode: str = "max",
    critical_stop_max_priority: int = 2,
    require_full_universe_completion: bool = False,
    profile_base_path: Optional[str] = None,
    software_profile_dirname: Optional[str] = None,
    shared_public_memory_dir: Optional[str | Path] = None,
    ablation_config: Optional[Dict[str, Any]] = None,
    evaluation_mode: bool = False,
    model_revision: Optional[str] = None,
    model_revision_attestation: Optional[Dict[str, Any]] = None,
    endpoint_snapshot: Optional[Dict[str, str]] = None,
    endpoint_snapshot_sha256: Optional[str] = None,
    decoding_config_requested: Optional[Dict[str, Any]] = None,
    decoding_config_requested_sha256: Optional[str] = None,
    decoding_config_effective: Optional[Dict[str, Any]] = None,
    decoding_config_effective_sha256: Optional[str] = None,
    run_id: Optional[str] = None,
    scan_fingerprint: Optional[Dict[str, Any]] = None,
    selection_similarity_provenance: Optional[Dict[str, Any]] = None,
    module_similarity_config: Optional[Dict[str, Any]] = None,
    host_priority_plan: Optional[Dict[str, Any]] = None,
    reference_context_provenance: Optional[Dict[str, Any]] = None,
    unprioritized_file_schedule: Optional[Dict[str, Any]] = None,
    target_path_projection: Optional[Dict[str, Any]] = None,
    return_terminal_receipt: bool = False,
) -> bool | Dict[str, Any]:
    """运行单目标扫描；batch 可请求不可自锚定的终态 receipt。"""
    cve_id = canonical_scan_reference_id(cve_id)
    target.repo_name = canonical_scan_repo_name(target.repo_name)
    target.commit_hash = canonical_scan_commit(target.commit_hash)
    normalized_ablation_config = normalize_ablation_config(ablation_config)
    if endpoint_snapshot is not None or endpoint_snapshot_sha256 is not None:
        (
            resolved_endpoint_snapshot,
            resolved_endpoint_snapshot_sha256,
        ) = validate_endpoint_snapshot_payload(
            endpoint_snapshot,
            endpoint_snapshot_sha256,
        )
    else:
        resolved_endpoint_snapshot = {}
        resolved_endpoint_snapshot_sha256 = None

    if (
        decoding_config_requested is not None
        or decoding_config_requested_sha256 is not None
    ):
        (
            resolved_decoding_config_requested,
            resolved_decoding_config_requested_sha256,
        ) = validate_decoding_config_payload(
            decoding_config_requested,
            decoding_config_requested_sha256,
        )
    else:
        resolved_decoding_config_requested = {}
        resolved_decoding_config_requested_sha256 = None

    decoding_binding_required = bool(evaluation_mode) or any(
        value is not None
        for value in (
            decoding_config_requested,
            decoding_config_requested_sha256,
            decoding_config_effective,
            decoding_config_effective_sha256,
        )
    )
    if decoding_binding_required:
        actual_decoding_config_effective = _effective_client_decoding_config(
            llm_client
        )
        actual_decoding_config_effective_json = json.dumps(
            actual_decoding_config_effective,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        actual_decoding_config_effective_sha256 = hashlib.sha256(
            actual_decoding_config_effective_json.encode("utf-8")
        ).hexdigest()
        (
            actual_decoding_config_effective,
            actual_decoding_config_effective_sha256,
        ) = validate_decoding_config_payload(
            actual_decoding_config_effective,
            actual_decoding_config_effective_sha256,
        )
        if (
            decoding_config_effective is not None
            or decoding_config_effective_sha256 is not None
        ):
            (
                resolved_decoding_config_effective,
                resolved_decoding_config_effective_sha256,
            ) = validate_decoding_config_payload(
                decoding_config_effective,
                decoding_config_effective_sha256,
            )
            if (
                resolved_decoding_config_effective
                != actual_decoding_config_effective
                or resolved_decoding_config_effective_sha256
                != actual_decoding_config_effective_sha256
            ):
                raise ValueError(
                    "declared effective decoding config does not match the LLM client"
                )
        else:
            resolved_decoding_config_effective = (
                actual_decoding_config_effective
            )
            resolved_decoding_config_effective_sha256 = (
                actual_decoding_config_effective_sha256
            )
    else:
        resolved_decoding_config_effective = {}
        resolved_decoding_config_effective_sha256 = None
    if resolved_decoding_config_requested and (
        resolved_decoding_config_requested
        != resolved_decoding_config_effective
        or resolved_decoding_config_requested_sha256
        != resolved_decoding_config_effective_sha256
    ):
        raise ValueError(
            "requested decoding config does not match the effective LLM client config"
        )

    if model_revision is not None and (
        not isinstance(model_revision, str)
        or not model_revision
        or model_revision != model_revision.strip()
    ):
        raise ValueError("model_revision must be a non-empty exact string")
    resolved_model_revision_attestation: Dict[str, Any] = {}
    if model_revision_attestation is not None:
        llm_config = getattr(llm_client, "config", None)
        resolved_model_revision_attestation = (
            validate_model_revision_attestation_payload(
                model_revision_attestation,
                provider=getattr(llm_config, "provider", None),
                model_name=getattr(llm_config, "model", None),
                model_revision=model_revision,
                endpoint_snapshot_sha256=(
                    resolved_endpoint_snapshot_sha256
                ),
            )
        )
    if evaluation_mode:
        if model_revision is None:
            raise ValueError(
                "evaluation scan requires an explicit model_revision"
            )
        if not resolved_endpoint_snapshot:
            raise ValueError(
                "evaluation scan requires an explicit immutable endpoint snapshot"
            )
        if not resolved_decoding_config_requested:
            raise ValueError(
                "evaluation scan requires an explicit decoding config"
            )
        explicit_decoding_fields = getattr(
            getattr(llm_client, "config", None),
            "_explicit_config_fields",
            None,
        )
        if (
            not isinstance(explicit_decoding_fields, (set, frozenset))
            or not DECODING_CONFIG_KEYS.issubset(explicit_decoding_fields)
        ):
            raise ValueError(
                "evaluation LLM client must explicitly bind every decoding field"
            )
        llm_config = getattr(llm_client, "config", None)
        if (
            getattr(llm_config, "provider", None) != "lab"
            or getattr(llm_config, "model", None) != "GLM-5.2"
            or resolved_endpoint_snapshot.get("base_url")
            != "https://llm.shtech.org/v1"
        ):
            raise ValueError(
                "evaluation scan requires lab/GLM-5.2 on the frozen shtech endpoint"
            )
        if bool(
            getattr(llm_config, "fallback_on_retry_exhausted", False)
        ):
            raise ValueError(
                "evaluation scan prohibits provider fallback"
            )
        if not bool(
            getattr(llm_config, "enforce_exact_decoding", False)
        ):
            raise ValueError(
                "evaluation scan requires exact decoding enforcement"
            )
        if (
            getattr(llm_config, "max_retries", None) != 3
            or getattr(llm_client, "sdk_max_retries", None) != 0
        ):
            raise ValueError(
                "evaluation scan requires three total request attempts and zero SDK retries"
            )
        client_model_revision = getattr(
            getattr(llm_client, "config", None),
            "model_revision",
            None,
        )
        if (
            not isinstance(client_model_revision, str)
            or not client_model_revision
            or client_model_revision != client_model_revision.strip()
            or client_model_revision != model_revision
        ):
            raise ValueError(
                "evaluation model_revision does not match the LLM client configuration"
            )
        if not resolved_model_revision_attestation:
            raise ValueError(
                "evaluation scan requires a verified operator model revision attestation"
            )
        client_base_url = getattr(
            getattr(llm_client, "config", None),
            "base_url",
            None,
        )
        if client_base_url != resolved_endpoint_snapshot["base_url"]:
            raise ValueError(
                "evaluation endpoint snapshot does not match the LLM client configuration"
            )
        if not isinstance(target_path_projection, dict):
            raise ValueError("evaluation scan requires a frozen target path projection")
        projection_provenance = target_path_projection.get("provenance", {})
        if (
            not isinstance(projection_provenance, dict)
            or projection_provenance.get("target_repository") != target.repo_name
            or projection_provenance.get("target_commit") != target.commit_hash
        ):
            raise ValueError("evaluation target projection identity mismatch")
        bound_profile_sha256 = projection_provenance.get(
            "bound_target_software_profile_sha256"
        )
        if not is_lowercase_sha256(bound_profile_sha256):
            raise ValueError("evaluation target profile binding is invalid")
        _validate_evaluation_model_input_policy_binding(
            target_path_projection=target_path_projection,
            normalized_ablation_config=normalized_ablation_config,
            reference_context_provenance=reference_context_provenance,
            unprioritized_file_schedule=unprioritized_file_schedule,
            bound_profile_sha256=bound_profile_sha256,
        )
        require_evaluation_embedding_byte_binding(True)
    resolved_module_similarity_config = resolve_module_similarity_config(module_similarity_config)
    resolved_module_similarity_config["require_embedding"] = bool(evaluation_mode)
    if selection_similarity_provenance is not None:
        target.selection_provenance = dict(selection_similarity_provenance)
    frozen_input_hashes = _frozen_control_input_hashes(target_path_projection)
    resolved_model_revision_attestation_binding = dict(
        resolved_model_revision_attestation.get("binding", {})
    )
    if resolved_model_revision_attestation_binding:
        frozen_input_hashes.update(
            {
                "model_revision_attestation_file": (
                    resolved_model_revision_attestation_binding[
                        "file_sha256"
                    ]
                ),
                "model_revision_attestation_payload": (
                    resolved_model_revision_attestation_binding[
                        "payload_sha256"
                    ]
                ),
            }
        )
    scan_started_at = datetime.now()
    run_id = str(run_id or uuid.uuid4().hex)
    finder: Optional[AgenticVulnFinder] = None
    target_output_dir = resolve_output_dir(
        cve_id=cve_id,
        target_repo=target.repo_name,
        target_commit=target.commit_hash,
        output_base=output_base,
    )
    results_payload: Optional[Dict[str, Any]] = None
    quality_payload: Optional[Dict[str, Any]] = None
    usage_summary: Optional[Dict[str, Any]] = None
    failure_reason: Optional[str] = None
    usage_snapshot: Optional[int] = None
    recorded_actual_commit: Optional[str] = None
    provenance_persisted = False
    terminal_commit: Optional[Dict[str, Any]] = None

    def scan_outcome(succeeded: bool) -> bool | Dict[str, Any]:
        if not return_terminal_receipt:
            return succeeded
        return {
            "succeeded": succeeded,
            "cve_id": cve_id,
            "repo_name": target.repo_name,
            "commit": target.commit_hash,
            "scan_output_commit_sha256": (
                terminal_commit.get("sha256")
                if isinstance(terminal_commit, dict)
                else None
            ),
            "terminal_status": (
                terminal_commit.get("terminal_status")
                if isinstance(terminal_commit, dict)
                else None
            ),
        }

    def persist_provenance(
        status: str,
        termination: Optional[str],
        finished_at: Optional[datetime],
        *,
        write_record: bool = True,
    ) -> Dict[str, Any]:
        actual_commit = recorded_actual_commit
        if actual_commit is None and target_repo_path.exists():
            actual_commit = get_git_commit(str(target_repo_path))
        provenance = _build_run_provenance(
            target=target,
            llm_client=llm_client,
            max_iterations=max_iterations,
            started_at=scan_started_at,
            finished_at=finished_at,
            actual_repo_commit=actual_commit,
            status=status,
            termination=termination,
            results=results_payload,
            quality=quality_payload,
            usage_summary=usage_summary,
            failure_reason=failure_reason,
            ablation_config=normalized_ablation_config,
            evaluation_mode=evaluation_mode,
            model_revision=model_revision,
            model_revision_attestation_binding=(
                resolved_model_revision_attestation_binding or None
            ),
            endpoint_snapshot=resolved_endpoint_snapshot,
            endpoint_snapshot_sha256=resolved_endpoint_snapshot_sha256,
            decoding_config_requested=resolved_decoding_config_requested,
            decoding_config_requested_sha256=(
                resolved_decoding_config_requested_sha256
            ),
            decoding_config_effective=resolved_decoding_config_effective,
            decoding_config_effective_sha256=(
                resolved_decoding_config_effective_sha256
            ),
            run_id=run_id,
            scan_fingerprint=scan_fingerprint,
            frozen_input_hashes=frozen_input_hashes,
            reference_id=cve_id,
        )
        if write_record:
            if status == "running":
                _write_run_state(target_output_dir, provenance)
            elif status == "failed":
                _write_run_failure(target_output_dir, provenance)
            else:
                raise ScanOutputCommitError(
                    "terminal success provenance must be committed with findings"
                )
        return provenance

    resolved_repo_base_path = Path(repo_base_path).expanduser()
    if not resolved_repo_base_path.is_absolute():
        resolved_repo_base_path = _path_config["repo_root"] / resolved_repo_base_path
    target_repo_path = resolved_repo_base_path / target.repo_name
    persist_provenance("running", None, None)
    if not target_repo_path.exists():
        logger.error(f"Repository not found: {target_repo_path}")
        failure_reason = f"Repository not found: {target_repo_path}"
        persist_provenance("failed", "preflight_failure", datetime.now())
        return scan_outcome(False)

    lock_purpose = f"agent_scan:{cve_id}:{target.commit_hash[:12]}"
    with hold_repo_lock(
        target_repo_path,
        purpose=lock_purpose,
        run_id=run_id,
    ):
        original_commit = get_git_commit(str(target_repo_path))
        original_restore_target = get_git_restore_target(str(target_repo_path))
        changed_commit = False
        scan_succeeded = False
        restore_failed = False
        repo_is_clean: Optional[bool] = None

        try:
            needs_checkout = original_commit != target.commit_hash
            target_commit_ready = not needs_checkout
            if needs_checkout and not original_restore_target:
                failure_reason = "Unable to resolve original git position for requested commit switch"
                logger.error(
                    "Unable to resolve original git position for %s; refuse commit switch to %s",
                    target.repo_name,
                    target.commit_hash[:12],
                )
            else:
                repo_is_clean = not has_uncommitted_changes(str(target_repo_path))
            if needs_checkout and original_restore_target and repo_is_clean:
                logger.info(f"Checking out {target.repo_name} to {target.commit_hash[:12]}...")
                if not checkout_commit(str(target_repo_path), target.commit_hash):
                    logger.error(f"Failed to checkout to {target.commit_hash}")
                    failure_reason = f"Failed to checkout requested commit {target.commit_hash}"
                else:
                    changed_commit = True
                    recorded_actual_commit = get_git_commit(str(target_repo_path))
                    target_commit_ready = (
                        recorded_actual_commit == target.commit_hash
                    )
                    if not target_commit_ready:
                        failure_reason = (
                            "Checked-out repository commit does not match the requested target"
                        )
                        logger.error(
                            "Repository %s resolved to %s after checkout, expected %s",
                            target.repo_name,
                            recorded_actual_commit,
                            target.commit_hash,
                        )
            elif repo_is_clean is False:
                failure_reason = "Repository has local changes; scan requires a clean working tree"
                logger.error(
                    "Repository %s has local changes; scan requires a clean working tree.",
                    target.repo_name,
                )

            if (
                target_commit_ready
                and repo_is_clean is True
                and (not needs_checkout or original_restore_target)
            ):
                if target_path_projection is not None:
                    _validate_target_projection_against_git_tree(
                        target_path_projection,
                        target_repo_path,
                        target_repository=target.repo_name,
                        target_commit=target.commit_hash,
                    )
                logger.info(f"Loading software profile: {target.repo_name}@{target.commit_hash[:12]}...")
                soft_profiles_dir = _resolve_soft_profiles_dir_for_scan(
                    profile_base_path=profile_base_path,
                    software_profile_dirname=software_profile_dirname,
                )
                if target_path_projection is not None:
                    expected_profile_sha256 = str(
                        target_path_projection.get("provenance", {}).get(
                            "bound_target_software_profile_sha256",
                            "",
                        )
                    )
                    software_profile = _load_hash_bound_software_profile(
                        repo_name=target.repo_name,
                        commit_hash=target.commit_hash,
                        base_dir=soft_profiles_dir,
                        expected_sha256=expected_profile_sha256,
                    )
                elif normalized_ablation_config["candidate_priority"]:
                    expected_profile_sha256 = _resolve_scheduled_target_profile_sha256(
                        unprioritized_file_schedule
                    )
                    software_profile = _load_hash_bound_software_profile(
                        repo_name=target.repo_name,
                        commit_hash=target.commit_hash,
                        base_dir=soft_profiles_dir,
                        expected_sha256=expected_profile_sha256,
                    )
                else:
                    software_profile = load_software_profile(
                        target.repo_name,
                        target.commit_hash,
                        base_dir=soft_profiles_dir,
                    )
                if not software_profile:
                    failure_reason = "Required software profile is unavailable"
                    logger.error(
                        f"Failed to load software profile for {target.repo_name}@{target.commit_hash[:12]}"
                    )
                else:
                    if normalized_ablation_config["reference_semantics"] and host_priority_plan is None:
                        raise ValueError(
                            "reference-semantics ablation requires a frozen host priority plan"
                        )
                    if (
                        normalized_ablation_config["candidate_priority"]
                        and unprioritized_file_schedule is None
                    ):
                        raise ValueError(
                            "candidate-priority ablation requires a frozen file schedule"
                        )
                    validate_frozen_scan_controls(
                        software_profile,
                        (
                            None
                            if normalized_ablation_config["candidate_priority"]
                            else host_priority_plan
                        ),
                        (
                            unprioritized_file_schedule
                            if normalized_ablation_config["candidate_priority"]
                            else None
                        ),
                        target_path_projection,
                    )

                    target_output_dir = resolve_output_dir(
                        cve_id=cve_id,
                        target_repo=target.repo_name,
                        target_commit=target.commit_hash,
                        output_base=output_base,
                    )
                    target_output_dir.mkdir(parents=True, exist_ok=True)
                    shared_public_memory_root: Optional[Path] = None
                    if (
                        shared_public_memory_dir is not None
                        and not normalized_ablation_config["memory"]
                    ):
                        shared_public_memory_root = Path(shared_public_memory_dir).expanduser()
                        if not shared_public_memory_root.is_absolute():
                            shared_public_memory_root = _path_config["repo_root"] / shared_public_memory_root

                    scan_languages = _resolve_scan_languages(target_repo_path, software_profile)
                    codeql_database_names = _resolve_codeql_database_names(
                        target,
                        scan_languages,
                        software_profile,
                    )

                    logger.info(
                        "Target languages: %s",
                        ", ".join(scan_languages) if scan_languages else "none",
                    )
                    if codeql_database_names:
                        logger.info(
                            "CodeQL databases: %s",
                            ", ".join(
                                f"{lang}={db_name}"
                                for lang, db_name in sorted(codeql_database_names.items())
                            ),
                        )
                    else:
                        logger.info("CodeQL databases: none (CodeQL tools may be unavailable)")

                    output_lock_info = None
                    output_lock_purpose = f"scan_output:{cve_id}:{target.repo_name}:{target.commit_hash[:12]}"
                    try:
                        # Serialize finder lifecycle for a shared output directory, since finder
                        # initialization and run both write scan_memory.json.
                        output_lock_info = acquire_repo_lock(
                            target_output_dir,
                            purpose=output_lock_purpose,
                            run_id=run_id,
                        )
                        memory_reference_id = cve_id
                        if normalized_ablation_config["reference_semantics"]:
                            memory_reference_id = str(
                                vulnerability_profile.get("card_id", "")
                                if isinstance(vulnerability_profile, dict)
                                else ""
                            )
                        shared_public_memory_visibility_scope_id = build_shared_public_memory_visibility_scope_id(
                            cve_id=memory_reference_id,
                            target_repo=target.repo_name,
                            target_commit=target.commit_hash,
                            target_output_dir=target_output_dir,
                        )
                        shared_public_memory_producer_key = stable_data_hash(
                            {
                                "visibility_scope_id": shared_public_memory_visibility_scope_id,
                                "scan_started_at": datetime.now().isoformat(timespec="microseconds"),
                            }
                        )[:16]
                        shared_public_memory_producer_id = (
                            f"{memory_reference_id}:"
                            f"{shared_public_memory_producer_key}"
                        )
                        shared_public_memory_manager = (
                            SharedPublicMemoryManager(
                                root_dir=shared_public_memory_root,
                                repo_name=target.repo_name,
                                repo_commit=target.commit_hash,
                                repo_scope_key=stable_data_hash(str(target_repo_path.resolve()))[:12],
                                producer_id=shared_public_memory_producer_id,
                                visibility_scope_id=shared_public_memory_visibility_scope_id,
                            )
                            if shared_public_memory_root is not None
                            else None
                        )
                        shared_public_memory_scope = (
                            shared_public_memory_manager.describe_scope()
                            if shared_public_memory_manager is not None
                            else {"enabled": False, "root_hash": "", "scope_key": "", "state_hash": ""}
                        )
                        recorded_actual_commit = get_git_commit(str(target_repo_path))
                        usage_snapshot = capture_llm_usage_snapshot(llm_client)
                        finder = AgenticVulnFinder(
                            llm_client=llm_client,
                            repo_path=target_repo_path,
                            software_profile=software_profile,
                            vulnerability_profile=vulnerability_profile,
                            max_iterations=max_iterations,
                            stop_when_critical_complete=stop_when_critical_complete,
                            critical_stop_mode=critical_stop_mode,
                            critical_stop_max_priority=critical_stop_max_priority,
                            require_full_universe_completion=(
                                require_full_universe_completion
                            ),
                            verbose=verbose,
                            output_dir=target_output_dir,
                            languages=scan_languages,
                            codeql_database_names=codeql_database_names,
                            shared_public_memory_manager=shared_public_memory_manager,
                            shared_public_memory_scope=shared_public_memory_scope,
                            module_similarity_config=resolved_module_similarity_config,
                            ablation_config=normalized_ablation_config,
                            host_priority_plan=host_priority_plan,
                            unprioritized_file_schedule=unprioritized_file_schedule,
                            target_path_projection=target_path_projection,
                            model_revision=model_revision,
                            model_revision_attestation_binding=(
                                resolved_model_revision_attestation_binding
                                or None
                            ),
                            endpoint_snapshot=(
                                resolved_endpoint_snapshot
                                if resolved_endpoint_snapshot_sha256 is not None
                                else None
                            ),
                            endpoint_snapshot_sha256=(
                                resolved_endpoint_snapshot_sha256
                            ),
                            decoding_config_requested=(
                                resolved_decoding_config_requested
                                if resolved_decoding_config_requested_sha256
                                is not None
                                else None
                            ),
                            decoding_config_requested_sha256=(
                                resolved_decoding_config_requested_sha256
                            ),
                            decoding_config_effective=(
                                resolved_decoding_config_effective
                                if resolved_decoding_config_effective_sha256
                                is not None
                                else None
                            ),
                            decoding_config_effective_sha256=(
                                resolved_decoding_config_effective_sha256
                            ),
                        )
                        (
                            base_projection_metadata,
                            runtime_projection_metadata,
                        ) = _split_model_visible_input_projection_provenance(
                            target_path_projection,
                            getattr(
                                finder,
                                "model_visible_input_projection_provenance",
                                None,
                            ),
                        )
                        scan_fingerprint = build_scan_fingerprint(
                            vulnerability_profile=vulnerability_profile,
                            software_profile=software_profile,
                            llm_client=llm_client,
                            max_iterations=max_iterations,
                            stop_when_critical_complete=stop_when_critical_complete,
                            critical_stop_mode=critical_stop_mode,
                            critical_stop_max_priority=critical_stop_max_priority,
                            require_full_universe_completion=(
                                require_full_universe_completion
                            ),
                            scan_languages=scan_languages,
                            codeql_database_names=codeql_database_names,
                            shared_public_memory_scope=shared_public_memory_scope,
                            module_similarity_config=resolved_module_similarity_config,
                            ablation_config=normalized_ablation_config,
                            run_id=run_id,
                            reference_context_provenance=reference_context_provenance,
                            target_path_projection=base_projection_metadata,
                            model_visible_input_runtime_projection=(
                                runtime_projection_metadata
                            ),
                            model_revision=model_revision,
                            model_revision_attestation_binding=(
                                resolved_model_revision_attestation_binding
                                or None
                            ),
                            endpoint_snapshot=(
                                resolved_endpoint_snapshot
                                if resolved_endpoint_snapshot_sha256 is not None
                                else None
                            ),
                            endpoint_snapshot_sha256=(
                                resolved_endpoint_snapshot_sha256
                            ),
                            decoding_config_requested=(
                                resolved_decoding_config_requested
                                if resolved_decoding_config_requested_sha256
                                is not None
                                else None
                            ),
                            decoding_config_requested_sha256=(
                                resolved_decoding_config_requested_sha256
                            ),
                            decoding_config_effective=(
                                resolved_decoding_config_effective
                                if resolved_decoding_config_effective_sha256
                                is not None
                                else None
                            ),
                            decoding_config_effective_sha256=(
                                resolved_decoding_config_effective_sha256
                            ),
                            unprioritized_file_schedule=unprioritized_file_schedule,
                        )
                        results = finder.run()
                        recorded_actual_commit = get_git_commit(
                            str(target_repo_path)
                        )
                        repo_is_clean = not has_uncommitted_changes(
                            str(target_repo_path)
                        )
                        if recorded_actual_commit != target.commit_hash:
                            raise RuntimeError(
                                "Repository commit changed during the scan: "
                                f"expected {target.commit_hash}, got "
                                f"{recorded_actual_commit or 'unknown'}"
                            )
                        if not repo_is_clean:
                            raise RuntimeError(
                                "Repository working tree changed during the scan"
                            )
                        results_payload = dict(results) if isinstance(results, dict) else {}
                        usage_summary = aggregate_llm_usage_since(llm_client, usage_snapshot)
                        if evaluation_mode:
                            require_evaluation_response_identity_usage(
                                usage_summary
                            )
                        quality_payload = _build_scan_quality_metadata(finder)
                        run_status = (
                            "complete"
                            if quality_payload.get("coverage_status") == "complete"
                            else "partial"
                        )
                        run_provenance = persist_provenance(
                            run_status,
                            results_payload.get("termination_reason"),
                            datetime.now(),
                            write_record=False,
                        )
                        terminal_commit = _save_scan_outputs(
                            target_output_dir,
                            finder,
                            results_payload,
                            target,
                            scan_fingerprint=scan_fingerprint,
                            run_provenance=run_provenance,
                            quality_metadata=quality_payload,
                        )
                        provenance_persisted = True
                    finally:
                        release_repo_lock(
                            output_lock_info,
                            target_output_dir,
                            output_lock_purpose,
                        )

                    vulnerabilities = results.get("vulnerabilities", []) if isinstance(results, dict) else []
                    logger.info(
                        f"Target {target.repo_name}@{target.commit_hash[:12]} finished: "
                        f"{len(vulnerabilities)} potential vulnerabilities, "
                        f"coverage={quality_payload['coverage_status']}, "
                        f"critical={quality_payload['critical_scope_completed_files']}/"
                        f"{quality_payload['critical_scope_total_files']}"
                    )
                    if quality_payload["coverage_status"] != "complete":
                        logger.error(
                            "Target %s@%s did not finish with complete coverage (%s)",
                            target.repo_name,
                            target.commit_hash[:12],
                            quality_payload["coverage_status"],
                        )
                    else:
                        scan_succeeded = True
        except Exception as exc:  # pylint: disable=broad-except
            failure_reason = f"{type(exc).__name__}: {exc}"
            if usage_snapshot is not None:
                usage_summary = aggregate_llm_usage_since(llm_client, usage_snapshot)
            if finder is not None:
                try:
                    quality_payload = _build_scan_quality_metadata(finder)
                except Exception as quality_exc:  # pylint: disable=broad-except
                    logger.warning(
                        "Failed to recover partial scan coverage after runtime failure: %s",
                        quality_exc,
                    )
            logger.error(f"Scan failed for {target.repo_name}@{target.commit_hash[:12]}: {exc}")
            persist_provenance(
                "failed",
                "embedding_unavailable"
                if isinstance(exc, EmbeddingUnavailableError)
                else "runtime_failure",
                datetime.now(),
            )
            provenance_persisted = True
            scan_succeeded = False
        finally:
            if changed_commit and original_restore_target:
                logger.info(
                    "Restoring %s to original position %s...",
                    target.repo_name,
                    original_restore_target,
                )
                restored = restore_git_position(str(target_repo_path), original_restore_target)
                if not restored:
                    logger.error(
                        "Failed to restore %s to original position %s",
                        target.repo_name,
                        original_restore_target,
                    )
                    restore_failed = True
        if restore_failed:
            failure_reason = f"Failed to restore repository to {original_restore_target}"
            persist_provenance("failed", "restore_failure", datetime.now())
            return scan_outcome(False)
        if not provenance_persisted:
            persist_provenance("failed", "preflight_failure", datetime.now())
        return scan_outcome(scan_succeeded)


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    if not _validate_args(args):
        return 1
    repo_profiles_dir, vuln_profiles_dir = _resolve_profile_dirs(args)

    logger.info(f"Resolved software profile dir: {repo_profiles_dir}")
    preflight_started_at = datetime.now()
    preflight_run_id = str(
        getattr(args, "run_id", None) or uuid.uuid4().hex
    )
    control_stage = "scanner_config_snapshot"
    reference_context: Optional[Dict[str, Any]] = None
    unprioritized_schedule: Optional[Dict[str, Any]] = None
    target_path_projection: Optional[Dict[str, Any]] = None
    model_revision_attestation: Optional[Dict[str, Any]] = None
    endpoint_snapshot: Optional[Dict[str, str]] = None
    endpoint_snapshot_sha256: Optional[str] = None
    decoding_config_requested: Optional[Dict[str, Any]] = None
    decoding_config_requested_sha256: Optional[str] = None
    try:
        _scanner_config_hashes()
        control_stage = "module_similarity_embedding"
        require_evaluation_embedding_byte_binding(
            bool(getattr(args, "evaluation_mode", False))
        )
        control_stage = "endpoint_snapshot"
        if getattr(args, "endpoint_snapshot_json", None) is not None:
            endpoint_snapshot, endpoint_snapshot_sha256 = (
                validate_endpoint_snapshot_contract(
                    args.endpoint_snapshot_json,
                    args.endpoint_snapshot_sha256,
                )
            )
        control_stage = "model_revision_attestation"
        if getattr(args, "model_revision_attestation", None) is not None:
            model_revision_attestation = load_model_revision_attestation(
                args.model_revision_attestation,
                args.model_revision_attestation_sha256,
                args.model_revision_attestation_binding_path,
                provider=args.llm_provider,
                model_name=args.llm_name,
                model_revision=args.model_revision,
                endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            )
        control_stage = "decoding_config"
        if getattr(args, "decoding_config_json", None) is not None:
            (
                decoding_config_requested,
                decoding_config_requested_sha256,
            ) = validate_decoding_config_contract(
                args.decoding_config_json,
                args.decoding_config_sha256,
            )
        control_stage = "reference_context"
        if getattr(args, "reference_card", None):
            reference_context = load_reference_context_envelope(
                args.reference_card,
                args.reference_card_sha256,
                getattr(args, "reference_card_binding_path", None),
            )
        control_stage = "target_path_projection"
        if getattr(args, "target_path_projection", None):
            target_path_projection = load_target_path_projection(
                args.target_path_projection,
                args.target_path_projection_sha256,
                target_repository=args.target_repo,
                target_commit=args.target_commit,
                target_software_profile_sha256=(
                    args.target_software_profile_sha256
                ),
                binding_path=getattr(
                    args,
                    "target_path_projection_binding_path",
                    None,
                ),
            )
        control_stage = "unprioritized_file_schedule"
        if getattr(args, "unprioritized_file_order", None):
            unprioritized_schedule = load_unprioritized_file_schedule(
                args.unprioritized_file_order,
                args.unprioritized_file_order_sha256,
                target_commit=args.target_commit,
                binding_path=getattr(
                    args,
                    "unprioritized_file_order_binding_path",
                    None,
                ),
            )
            unprioritized_schedule = {
                "files": list(unprioritized_schedule["files"]),
                "provenance": {
                    **dict(unprioritized_schedule["provenance"]),
                    "target_software_profile_sha256": (
                        args.target_software_profile_sha256
                    ),
                },
            }
        control_stage = "model_input_stage_binding"
        if getattr(args, "model_input_invariant_stage_sha256", None):
            if target_path_projection is None:
                raise ValueError("model-input stages require a target path projection")
            target_path_projection = bind_verified_model_input_control(
                target_path_projection,
                reference_context=reference_context,
                unprioritized_schedule=unprioritized_schedule,
                expected_invariant_stage_sha256=(
                    args.model_input_invariant_stage_sha256
                ),
                expected_policy_stage_sha256=args.model_input_policy_stage_sha256,
            )
    except (OSError, ValueError) as exc:
        logger.error("Frozen scanner control validation failed: %s", exc)
        verified_hashes: Dict[str, Any] = {}
        if isinstance(reference_context, dict):
            reference_provenance = reference_context.get("provenance", {})
            if isinstance(reference_provenance, dict):
                verified_hashes["reference_context_artifact"] = (
                    reference_provenance.get("artifact_sha256")
                )
        if isinstance(unprioritized_schedule, dict):
            schedule_provenance = unprioritized_schedule.get(
                "provenance",
                {},
            )
            if isinstance(schedule_provenance, dict):
                verified_hashes[
                    "unprioritized_file_schedule_artifact"
                ] = schedule_provenance.get("artifact_sha256")
        if isinstance(target_path_projection, dict):
            projection_provenance = target_path_projection.get(
                "provenance",
                {},
            )
            if isinstance(projection_provenance, dict):
                verified_hashes[
                    "target_path_projection_artifact"
                ] = projection_provenance.get("artifact_sha256")
            try:
                _validate_verified_model_input_control(
                    target_path_projection
                )
                verified_hashes.update(
                    _frozen_control_input_hashes(
                        target_path_projection
                    )
                )
            except ValueError:
                pass
        if isinstance(model_revision_attestation, dict):
            attestation_binding = model_revision_attestation.get(
                "binding",
                {},
            )
            if isinstance(attestation_binding, dict):
                verified_hashes[
                    "model_revision_attestation_file"
                ] = attestation_binding.get("file_sha256")
                verified_hashes[
                    "model_revision_attestation_payload"
                ] = attestation_binding.get("payload_sha256")
        verified_hashes["target_software_profile_artifact"] = None
        declared_hashes = {
            "target_software_profile_artifact": getattr(
                args,
                "target_software_profile_sha256",
                None,
            ),
            "target_path_projection_artifact": getattr(
                args,
                "target_path_projection_sha256",
                None,
            ),
            "reference_context_artifact": getattr(
                args,
                "reference_card_sha256",
                None,
            ),
            "unprioritized_file_schedule_artifact": getattr(
                args,
                "unprioritized_file_order_sha256",
                None,
            ),
            "model_input_invariant_stage": getattr(
                args,
                "model_input_invariant_stage_sha256",
                None,
            ),
            "model_input_policy_stage": getattr(
                args,
                "model_input_policy_stage_sha256",
                None,
            ),
            "model_revision_attestation_file": getattr(
                args,
                "model_revision_attestation_sha256",
                None,
            ),
            "model_revision_attestation_payload": None,
            "endpoint_snapshot": getattr(
                args,
                "endpoint_snapshot_sha256",
                None,
            ),
            "decoding_config_requested": getattr(
                args,
                "decoding_config_sha256",
                None,
            ),
        }
        observed_hashes = {
            "target_software_profile_artifact": None,
            "target_path_projection_artifact": verified_hashes.get(
                "target_path_projection_artifact"
            ),
            "reference_context_artifact": verified_hashes.get(
                "reference_context_artifact"
            ),
            "unprioritized_file_schedule_artifact": (
                verified_hashes.get(
                    "unprioritized_file_schedule_artifact"
                )
            ),
            "model_input_invariant_stage": verified_hashes.get(
                "model_input_invariant_stage"
            ),
            "model_input_policy_stage": verified_hashes.get(
                "model_input_policy_stage"
            ),
            "model_input_control": verified_hashes.get(
                "model_input_control"
            ),
            "model_revision_attestation_file": (
                verified_hashes.get(
                    "model_revision_attestation_file"
                )
            ),
            "model_revision_attestation_payload": (
                verified_hashes.get(
                    "model_revision_attestation_payload"
                )
            ),
            "endpoint_snapshot": _observed_inline_sha256(
                getattr(args, "endpoint_snapshot_json", None)
            ),
            "decoding_config_requested": _observed_inline_sha256(
                getattr(args, "decoding_config_json", None)
            ),
        }
        try:
            failure_path = _write_preflight_failure_provenance(
                cve_id=getattr(args, "cve", None),
                output_base=getattr(args, "output", None),
                target=ScanTarget(
                    str(getattr(args, "target_repo", "") or ""),
                    str(getattr(args, "target_commit", "") or ""),
                ),
                llm_client=None,
                llm_provider=getattr(args, "llm_provider", None),
                llm_model=getattr(args, "llm_name", None),
                max_iterations=int(
                    getattr(args, "max_iterations", 0)
                ),
                started_at=preflight_started_at,
                run_id=preflight_run_id,
                error=exc,
                stage="frozen_control_loading",
                termination="frozen_control_validation_failure",
                failure_control=control_stage,
                vulnerability_profile=None,
                ablation_config=ablation_config_from_args(args),
                evaluation_mode=bool(
                    getattr(args, "evaluation_mode", False)
                ),
                model_revision=getattr(args, "model_revision", None),
                model_revision_attestation_binding=(
                    model_revision_attestation.get("binding")
                    if isinstance(
                        model_revision_attestation,
                        dict,
                    )
                    else None
                ),
                endpoint_snapshot=endpoint_snapshot,
                endpoint_snapshot_sha256=(
                    endpoint_snapshot_sha256
                ),
                decoding_config_requested=(
                    decoding_config_requested
                ),
                decoding_config_requested_sha256=(
                    decoding_config_requested_sha256
                ),
                decoding_config_effective=None,
                decoding_config_effective_sha256=None,
                verified_input_hashes=verified_hashes,
                declared_input_hashes=declared_hashes,
                observed_input_hashes=observed_hashes,
            )
            logger.error(
                "Frozen scanner control failure provenance saved to: %s",
                failure_path,
            )
        except Exception as provenance_exc:  # pylint: disable=broad-except
            logger.error(
                "Failed to persist sanitized control failure provenance: %s",
                type(provenance_exc).__name__,
            )
        return 1

    if bool(getattr(args, "ablate_reference_semantics", False)):
        vulnerability_profile = dict(reference_context["model_card"])
        logger.info(
            "Reference-semantics ablation: full vulnerability profile loading is disabled; card=%s",
            vulnerability_profile["card_id"],
        )
    else:
        logger.info(f"Resolved vulnerability profile dir: {vuln_profiles_dir}")
        logger.info(f"Loading vulnerability profile from {args.vuln_repo}@{args.cve}...")
        vulnerability_profile = load_vulnerability_profile(
            args.vuln_repo,
            args.cve,
            base_dir=vuln_profiles_dir,
        )
        if not vulnerability_profile:
            logger.error("Failed to load vulnerability profile")
            return 1

    selection_started_at = datetime.now()
    selection_run_id = str(getattr(args, "run_id", None) or uuid.uuid4().hex)
    try:
        if args.target_repo:
            targets = _resolve_manual_targets(args, vulnerability_profile, repo_profiles_dir)
        else:
            targets = _resolve_auto_targets(args, vulnerability_profile, repo_profiles_dir)
    except EmbeddingUnavailableError as exc:
        failure_path = _write_target_selection_failure_provenance(
            args=args,
            vulnerability_profile=vulnerability_profile,
            started_at=selection_started_at,
            run_id=selection_run_id,
            error=exc,
            model_revision_attestation_binding=(
                model_revision_attestation.get("binding")
                if isinstance(model_revision_attestation, dict)
                else None
            ),
        )
        logger.error("Selection failure provenance saved to: %s", failure_path)
        logger.error("Evaluation target selection failed closed: %s", exc)
        return 1

    if not targets:
        logger.error("No scan targets resolved")
        return 1

    llm_config_kwargs: Dict[str, Any] = {
        "provider": args.llm_provider,
        "model": args.llm_name,
        "model_revision": getattr(args, "model_revision", None),
    }
    if getattr(args, "llm_max_attempts", None) is not None:
        llm_config_kwargs["max_retries"] = args.llm_max_attempts
    if getattr(args, "llm_timeout_seconds", None) is not None:
        llm_config_kwargs["timeout"] = args.llm_timeout_seconds
    if decoding_config_requested is not None:
        llm_config_kwargs.update(decoding_config_requested)
    if bool(getattr(args, "evaluation_mode", False)):
        llm_config_kwargs.update({
            "fallback_provider": None,
            "fallback_on_retry_exhausted": False,
            "enforce_exact_decoding": True,
        })
    llm_client = create_llm_client(LLMConfig(**llm_config_kwargs))
    logger.info(f"Using LLM provider: {args.llm_provider}")

    success_count = 0
    for idx, target in enumerate(targets, 1):
        logger.info("")
        logger.info("=" * 80)
        logger.info(
            f"[{idx}/{len(targets)}] Scanning target: "
            f"{target.repo_name}@{target.commit_hash[:12]}"
        )
        logger.info("=" * 80)
        success = run_single_target_scan(
            cve_id=args.cve,
            output_base=args.output,
            repo_base_path=getattr(args, "repo_base_path", _path_config["repo_base_path"]),
            max_iterations=args.max_iterations,
            vulnerability_profile=vulnerability_profile,
            llm_client=llm_client,
            target=target,
            verbose=args.verbose,
            stop_when_critical_complete=getattr(args, "stop_when_critical_complete", False),
            critical_stop_mode=getattr(args, "critical_stop_mode", "max"),
            critical_stop_max_priority=getattr(args, "critical_stop_max_priority", 2),
            require_full_universe_completion=bool(
                getattr(args, "require_full_universe_completion", False)
            ),
            profile_base_path=getattr(args, "profile_base_path", None),
            software_profile_dirname=getattr(args, "software_profile_dirname", None),
            shared_public_memory_dir=getattr(args, "shared_public_memory_dir", None),
            run_id=getattr(args, "run_id", None),
            host_priority_plan=(
                reference_context["host_priority_plan"]
                if reference_context is not None
                else None
            ),
            reference_context_provenance=(
                reference_context["provenance"]
                if reference_context is not None
                else None
            ),
            unprioritized_file_schedule=unprioritized_schedule,
            target_path_projection=target_path_projection,
            ablation_config=ablation_config_from_args(args),
            evaluation_mode=bool(getattr(args, "evaluation_mode", False)),
            model_revision=getattr(args, "model_revision", None),
            model_revision_attestation=model_revision_attestation,
            endpoint_snapshot=endpoint_snapshot,
            endpoint_snapshot_sha256=endpoint_snapshot_sha256,
            decoding_config_requested=decoding_config_requested,
            decoding_config_requested_sha256=(
                decoding_config_requested_sha256
            ),
            selection_similarity_provenance=target.selection_provenance,
            module_similarity_config={
                "model_name": getattr(args, "similarity_model_name", None),
                "device": getattr(args, "similarity_device", None),
            },
        )
        success_count += int(bool(success))

    logger.info(
        f"Scan finished: {success_count}/{len(targets)} target scans succeeded"
    )
    return 0 if success_count == len(targets) else 1


if __name__ == "__main__":
    raise SystemExit(main())
