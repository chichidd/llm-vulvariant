"""Software profile similarity retrieval helpers.

This module implements the similarity strategy used in
`experiments/rq-software-and-module-similarity/similarity.ipynb`:
- description similarity
- target application similarity
- target user similarity
- module-name Jaccard similarity

Additionally, it introduces a module dependency/import similarity metric based on
module-level dependency and import features:
- internal dependencies (`internal_dependencies`, `calls_modules`, `called_by_modules`)
- external imports (`external_dependencies`)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
import json
import math
import re

from profiler.software.models import ModuleInfo, SoftwareProfile, is_valid_software_basic_info
from scanner.similarity.embedding import (
    DEFAULT_EMBEDDING_MODEL_NAME,
    EmbeddingRetriever,
    embedding_model_artifact_signature,
    get_cached_embedding_retriever,
)
from utils.logger import get_logger
from utils.number_utils import to_int

logger = get_logger(__name__)

class EmbeddingUnavailableError(RuntimeError):
    """Raised when a run that requires embeddings cannot use the configured backend."""

    def __init__(self, message: str, provenance: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.embedding_provenance = dict(provenance or {})


def _update_embedding_provenance(
    provenance: Optional[Dict[str, Any]],
    *,
    model_name: Optional[str],
    device: Optional[str],
    required: bool,
    backend: Optional[str] = None,
    fallback_used: bool = False,
    fallback_reason: Optional[str] = None,
) -> None:
    """Populate caller-owned embedding provenance without inventing missing values."""
    if provenance is None:
        return
    signature = embedding_model_artifact_signature(model_name)
    artifact_hash = str(signature.get("artifact_hash", "") or "").strip()
    provenance.clear()
    provenance.update(
        {
            "backend": backend,
            "model": model_name or DEFAULT_EMBEDDING_MODEL_NAME,
            "revision": artifact_hash or None,
            "revision_source": signature.get("fingerprint_type") if artifact_hash else None,
            "resolved_model_path": str(signature.get("resolved_model_path", "") or "") or None,
            "device": str(device or "cpu").strip() or "cpu",
            "required": bool(required),
            "fallback_used": bool(fallback_used),
            "fallback_reason": fallback_reason,
        }
    )


DEFAULT_SIMILARITY_WEIGHTS: Dict[str, float] = {
    "description": 1.0,
    "target_application": 1.0,
    "target_user": 1.0,
    "module_jaccard": 1.0,
    "module_dependency_import": 1.0,
}


@dataclass(frozen=True)
class ProfileRef:
    """A loaded software profile with repository identity."""

    repo_name: str
    commit_hash: str
    profile: SoftwareProfile
    profile_path: Optional[Path] = None

    @property
    def label(self) -> str:
        return f"{self.repo_name}-{self.commit_hash[:12]}"


@dataclass(frozen=True)
class ProfileSimilarityMetrics:
    """Per-dimension similarity scores."""

    description_sim: float
    target_application_sim: float
    target_user_sim: float
    module_jaccard_sim: float
    module_dependency_import_sim: float
    overall_sim: float

    def to_dict(self) -> Dict[str, float]:
        return {
            "description_sim": self.description_sim,
            "target_application_sim": self.target_application_sim,
            "target_user_sim": self.target_user_sim,
            "module_jaccard_sim": self.module_jaccard_sim,
            "module_dependency_import_sim": self.module_dependency_import_sim,
            "overall_sim": self.overall_sim,
        }


@dataclass(frozen=True)
class SimilarProfileCandidate:
    """A candidate target profile with similarity metrics."""

    profile_ref: ProfileRef
    metrics: Optional[ProfileSimilarityMetrics]

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_name": self.profile_ref.repo_name,
            "commit_hash": self.profile_ref.commit_hash,
            "label": self.profile_ref.label,
            "similarity_computed": self.metrics is not None,
            "metrics": self.metrics.to_dict() if self.metrics is not None else None,
        }


def load_all_software_profiles(repo_profiles_dir: Path) -> List[ProfileRef]:
    """Load all software profiles under `repo_profiles_dir`.

    Expected layout:
      repo_profiles_dir/{repo_name}/{commit_hash}/software_profile.json
    """
    refs: List[ProfileRef] = []
    repo_profiles_dir = Path(repo_profiles_dir)
    if not repo_profiles_dir.exists():
        logger.warning(f"Profile directory not found: {repo_profiles_dir}")
        return refs

    for repo_dir in sorted(repo_profiles_dir.iterdir()):
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        for commit_dir in sorted(repo_dir.iterdir()):
            if not commit_dir.is_dir():
                continue
            profile_path = commit_dir / "software_profile.json"
            if not profile_path.exists():
                continue
            try:
                data = json.loads(profile_path.read_text(encoding="utf-8"))
                profile = SoftwareProfile.from_dict(data)
                if not is_valid_software_basic_info(profile.to_dict().get("basic_info", {})):
                    logger.warning("Skipping incomplete software profile %s", profile_path)
                    continue
                refs.append(
                    ProfileRef(
                        repo_name=repo_name,
                        commit_hash=commit_dir.name,
                        profile=profile,
                        profile_path=profile_path,
                    )
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(f"Failed to load profile {profile_path}: {exc}")
    return refs


def _profile_mtime_ns(profile_path: Optional[Path]) -> int:
    """Return profile mtime for latest-profile selection with safe fallbacks."""
    if profile_path is None:
        return -1
    try:
        return profile_path.stat().st_mtime_ns
    except OSError:
        return -1


def _profile_is_parseable(profile_path: Path) -> bool:
    """Return whether one persisted software profile can be parsed successfully."""
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
        profile = SoftwareProfile.from_dict(data)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(f"Failed to load profile {profile_path}: {exc}")
        return False
    if not is_valid_software_basic_info(profile.to_dict().get("basic_info", {})):
        logger.warning("Skipping incomplete software profile %s", profile_path)
        return False
    return True


def _select_latest_profile_ref(profile_refs: Sequence[ProfileRef]) -> Optional[ProfileRef]:
    """Pick the newest profile reference using persisted profile mtimes."""
    if not profile_refs:
        return None
    return max(
        profile_refs,
        key=lambda ref: (
            _profile_mtime_ns(ref.profile_path),
            ref.commit_hash,
        ),
    )


def resolve_profile_commit(
    repo_profiles_dir: Path,
    repo_name: str,
    commit_hint: Optional[str] = None,
) -> Optional[str]:
    """Resolve a profile commit hash by optional full/prefix hint."""
    repo_dir = Path(repo_profiles_dir) / repo_name
    if not repo_dir.exists() or not repo_dir.is_dir():
        return None

    profile_candidates = []
    for commit_dir in repo_dir.iterdir():
        if not commit_dir.is_dir():
            continue
        profile_path = commit_dir / "software_profile.json"
        if not profile_path.exists():
            continue
        profile_candidates.append((commit_dir.name, profile_path))

    if not profile_candidates:
        return None

    if commit_hint:
        exact_matches = [candidate for candidate in profile_candidates if candidate[0] == commit_hint]
        if exact_matches:
            parseable_matches = [candidate for candidate in exact_matches if _profile_is_parseable(candidate[1])]
            if not parseable_matches:
                return None
            return parseable_matches[0][0]

        prefix_matches = [
            candidate for candidate in profile_candidates
            if candidate[0].startswith(commit_hint)
        ]
        if prefix_matches:
            parseable_matches = [candidate for candidate in prefix_matches if _profile_is_parseable(candidate[1])]
            if not parseable_matches:
                return None
            selected = max(
                parseable_matches,
                key=lambda item: (_profile_mtime_ns(item[1]), item[0]),
            )
            return selected[0]
        return None

    parseable_candidates = [candidate for candidate in profile_candidates if _profile_is_parseable(candidate[1])]
    if not parseable_candidates:
        return None
    selected = max(
        parseable_candidates,
        key=lambda item: (_profile_mtime_ns(item[1]), item[0]),
    )
    return selected[0]


def select_profile_ref(
    profile_refs: Sequence[ProfileRef],
    repo_name: str,
    commit_hint: Optional[str] = None,
) -> Optional[ProfileRef]:
    """Select a profile reference by repo name and optional commit/prefix."""
    by_repo = [r for r in profile_refs if r.repo_name == repo_name]
    if not by_repo:
        return None

    if commit_hint:
        exact_matches = [ref for ref in by_repo if ref.commit_hash == commit_hint]
        if exact_matches:
            return exact_matches[0]

        prefix_matches = [ref for ref in by_repo if ref.commit_hash.startswith(commit_hint)]
        if prefix_matches:
            return _select_latest_profile_ref(prefix_matches)
        return None

    return _select_latest_profile_ref(by_repo)


def build_text_retriever(
    model_name: Optional[str] = None,
    device: str = "cpu",
    *,
    require_embedding: bool = False,
    provenance: Optional[Dict[str, Any]] = None,
) -> Optional[EmbeddingRetriever]:
    """Build an embedding retriever for text similarity.

    Returns ``None`` when the configured model path or backend cannot be
    loaded so compatibility callers can fall back to lexical similarity.
    Evaluation callers set ``require_embedding=True`` to fail closed.
    """
    try:
        retriever = get_cached_embedding_retriever(model_name=model_name, device=device)
        _update_embedding_provenance(
            provenance,
            model_name=model_name,
            device=device,
            required=require_embedding,
            backend=getattr(retriever, "backend", None),
        )
        return retriever
    except Exception as exc:  # pylint: disable=broad-except
        reason = f"{type(exc).__name__}: {exc}"
        _update_embedding_provenance(
            provenance,
            model_name=model_name,
            device=device,
            required=require_embedding,
            fallback_used=not require_embedding,
            fallback_reason=reason,
        )
        if require_embedding:
            raise EmbeddingUnavailableError(
                "Embedding backend is required for evaluation mode but could not be loaded: "
                f"model_name={model_name or DEFAULT_EMBEDDING_MODEL_NAME!r}, "
                f"device={device!r}, error={reason}",
                provenance=provenance,
            ) from exc
        logger.warning(
            "Failed to build embedding retriever for auto-target similarity; "
            "falling back to lexical similarity. model_name=%r, device=%r, error=%s",
            model_name or DEFAULT_EMBEDDING_MODEL_NAME,
            device,
            exc,
        )
        return None


def compute_profile_similarity(
    source_profile: SoftwareProfile,
    target_profile: SoftwareProfile,
    text_retriever: Optional[EmbeddingRetriever] = None,
    weights: Optional[Dict[str, float]] = None,
    require_embedding: bool = False,
    embedding_provenance: Optional[Dict[str, Any]] = None,
) -> ProfileSimilarityMetrics:
    """Compute profile similarity with five dimensions.

    Metrics:
    1) description similarity (embedding when configured, lexical otherwise)
    2) target application similarity (embedding when configured, lexical otherwise)
    3) target user similarity (embedding when configured, lexical otherwise)
    4) module-name Jaccard similarity
    5) module dependency/import Jaccard similarity
    """
    weights = weights or DEFAULT_SIMILARITY_WEIGHTS

    source_description_text = _profile_description_text(source_profile)
    target_description_text = _profile_description_text(target_profile)
    description_sim = _text_similarity(
        source_description_text,
        target_description_text,
        text_retriever=text_retriever,
        require_embedding=require_embedding,
        embedding_provenance=embedding_provenance,
    )
    target_application_sim = _text_similarity(
        " | ".join(source_profile.target_application or []),
        " | ".join(target_profile.target_application or []),
        text_retriever=text_retriever,
        require_embedding=require_embedding,
        embedding_provenance=embedding_provenance,
    )
    target_user_sim = _text_similarity(
        " | ".join(source_profile.target_user or []),
        " | ".join(target_profile.target_user or []),
        text_retriever=text_retriever,
        require_embedding=require_embedding,
        embedding_provenance=embedding_provenance,
    )
    module_jaccard_sim = _jaccard_similarity(
        _module_name_set(source_profile),
        _module_name_set(target_profile),
    )
    module_dependency_import_sim = _jaccard_similarity(
        _module_dependency_import_tokens(source_profile),
        _module_dependency_import_tokens(target_profile),
    )

    weighted_items = {
        "description": description_sim,
        "target_application": target_application_sim,
        "target_user": target_user_sim,
        "module_jaccard": module_jaccard_sim,
        "module_dependency_import": module_dependency_import_sim,
    }
    denom = sum(max(0.0, float(weights.get(k, 0.0))) for k in weighted_items)
    if denom <= 0:
        overall_sim = sum(weighted_items.values()) / len(weighted_items)
    else:
        overall_sim = sum(
            float(weights.get(key, 0.0)) * value
            for key, value in weighted_items.items()
        ) / denom

    return ProfileSimilarityMetrics(
        description_sim=description_sim,
        target_application_sim=target_application_sim,
        target_user_sim=target_user_sim,
        module_jaccard_sim=module_jaccard_sim,
        module_dependency_import_sim=module_dependency_import_sim,
        overall_sim=overall_sim,
    )


def _profile_description_text(profile: SoftwareProfile) -> str:
    """Build description text from semantic repo-level basic-info fields only."""
    parts: List[str] = []
    for value in (
        profile.description,
        profile.evidence_summary,
    ):
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())

    for values in (
        profile.capabilities or [],
        profile.interfaces or [],
        profile.deployment_style or [],
        profile.operator_inputs or [],
        profile.external_surfaces or [],
    ):
        for item in values:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())

    return "\n".join(parts)


def rank_similar_profiles(
    source_ref: ProfileRef,
    candidate_refs: Sequence[ProfileRef],
    *,
    top_k: int = 3,
    min_overall_similarity: float = 0.0,
    text_retriever: Optional[EmbeddingRetriever] = None,
    weights: Optional[Dict[str, float]] = None,
    require_embedding: bool = False,
    embedding_provenance: Optional[Dict[str, Any]] = None,
    exclude_same_repo: bool = True,
) -> List[SimilarProfileCandidate]:
    """Rank candidate profiles by similarity to source profile."""
    if top_k <= 0:
        return []

    ranked: List[SimilarProfileCandidate] = []
    for candidate_ref in candidate_refs:
        if candidate_ref.repo_name == source_ref.repo_name and exclude_same_repo:
            continue
        if (
            candidate_ref.repo_name == source_ref.repo_name
            and candidate_ref.commit_hash == source_ref.commit_hash
        ):
            continue

        similarity_kwargs: Dict[str, Any] = {
            "text_retriever": text_retriever,
            "weights": weights,
        }
        if require_embedding or embedding_provenance is not None:
            similarity_kwargs.update(
                {
                    "require_embedding": require_embedding,
                    "embedding_provenance": embedding_provenance,
                }
            )
        metrics = compute_profile_similarity(
            source_ref.profile,
            candidate_ref.profile,
            **similarity_kwargs,
        )
        if metrics.overall_sim < min_overall_similarity:
            continue
        ranked.append(SimilarProfileCandidate(profile_ref=candidate_ref, metrics=metrics))

    ranked.sort(
        key=lambda item: (
            item.metrics.overall_sim,
            item.metrics.module_dependency_import_sim,
            item.metrics.module_jaccard_sim,
        ),
        reverse=True,
    )
    return ranked[: min(top_k, len(ranked))]


def _module_name_set(profile: SoftwareProfile) -> Set[str]:
    names: Set[str] = set()
    for module in _iter_modules(profile):
        module_name = _normalize_token(module.name)
        if module_name:
            names.add(module_name)
    return names


def _module_dependency_import_tokens(profile: SoftwareProfile) -> Set[str]:
    """Build module-level dependency/import tokens for Jaccard comparison."""
    tokens: Set[str] = set()
    for module in _iter_modules(profile):
        module_name = _normalize_token(module.name)
        if not module_name:
            continue

        internal_dep_lists = [
            module.dependencies,
            module.internal_dependencies,
            module.calls_modules,
            module.called_by_modules,
        ]
        for dep in _flatten_list(internal_dep_lists):
            dep_name = _normalize_token(dep)
            if dep_name and dep_name != module_name:
                tokens.add(f"dep::{module_name}->{dep_name}")

        for imp in _flatten_list([module.external_dependencies]):
            import_name = _normalize_token(imp)
            if import_name:
                tokens.add(f"import::{module_name}::{import_name}")

    for dep_name in profile.dependency_usage_count.keys():
        normalized = _normalize_token(dep_name)
        if normalized:
            tokens.add(f"project_import::{normalized}")

    for dep_name in profile.third_party_libraries:
        normalized = _normalize_token(dep_name)
        if normalized:
            tokens.add(f"project_import::{normalized}")

    return tokens


def _iter_modules(profile: SoftwareProfile) -> Iterable[ModuleInfo]:
    modules = profile.modules or []
    for module in modules:
        if isinstance(module, ModuleInfo):
            yield module
        elif isinstance(module, dict):
            yield ModuleInfo.from_dict(module)


def _flatten_list(values: Sequence[Sequence[str]]) -> Iterable[str]:
    for seq in values:
        for item in seq or []:
            if isinstance(item, str):
                yield item


def _normalize_token(value: str) -> str:
    if not isinstance(value, str):
        return ""
    normalized = " ".join(value.strip().lower().split())
    return normalized


def _module_embedding_text(module: ModuleInfo | Dict[str, Any]) -> str:
    """Build the v1 module text used for semantic embedding similarity."""
    if isinstance(module, ModuleInfo):
        module_data = module.to_dict()
    elif isinstance(module, dict):
        module_data = module
    else:
        return ""

    parts = [
        str(module_data.get("name", "") or "").strip(),
        str(module_data.get("category", "") or "").strip(),
        str(module_data.get("description", "") or "").strip(),
    ]
    return "\n".join(part for part in parts if part)


def _tokenize_text(value: str) -> Set[str]:
    if not value:
        return set()
    # Keep `-` at the end of the character class to avoid range parsing issues
    # across Python regex engines (e.g. 3.13).
    return set(re.findall(r"[a-zA-Z0-9_./-]+", value.lower()))


def _jaccard_similarity(left: Set[str], right: Set[str]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _text_similarity(
    left: str,
    right: str,
    *,
    text_retriever: Optional[EmbeddingRetriever] = None,
    require_embedding: bool = False,
    embedding_provenance: Optional[Dict[str, Any]] = None,
) -> float:
    left = left or ""
    right = right or ""
    if not left.strip() or not right.strip():
        if embedding_provenance is not None:
            embedding_provenance["skipped_empty_inputs"] = (
                to_int(embedding_provenance.get("skipped_empty_inputs")) + 1
            )
            embedding_provenance["last_event"] = "skipped_empty_input"
        return 0.0

    if text_retriever is not None:
        try:
            score = float(text_retriever.similarity(left, right))
            if not math.isfinite(score):
                raise ValueError(f"non-finite embedding similarity score: {score!r}")
            if embedding_provenance is not None:
                embedding_provenance["backend"] = (
                    getattr(text_retriever, "backend", None)
                    or embedding_provenance.get("backend")
                )
                embedding_provenance["successful_similarity_calls"] = (
                    to_int(embedding_provenance.get("successful_similarity_calls")) + 1
                )
                embedding_provenance["last_event"] = "embedding_similarity"
            return score
        except Exception as exc:  # pylint: disable=broad-except
            reason = f"{type(exc).__name__}: {exc}"
            if embedding_provenance is not None:
                embedding_provenance["fallback_used"] = not require_embedding
                embedding_provenance["fallback_reason"] = reason
                embedding_provenance["last_event"] = (
                    "embedding_failure" if require_embedding else "lexical_fallback"
                )
            if require_embedding:
                raise EmbeddingUnavailableError(
                    f"Embedding similarity failed during evaluation mode: {reason}",
                    provenance=embedding_provenance,
                ) from exc
            logger.warning(
                "Embedding similarity failed at runtime; falling back to lexical similarity. error=%s",
                exc,
            )
    elif require_embedding:
        reason = "embedding retriever is unavailable"
        if embedding_provenance is not None:
            embedding_provenance["fallback_used"] = False
            embedding_provenance["fallback_reason"] = reason
        raise EmbeddingUnavailableError(
            "Embedding similarity is required for evaluation mode, but the retriever is unavailable",
            provenance=embedding_provenance,
        )

    return _jaccard_similarity(_tokenize_text(left), _tokenize_text(right))


def _embedding_only_text_similarity(
    left: str,
    right: str,
    *,
    text_retriever: Optional[EmbeddingRetriever] = None,
    require_embedding: bool = False,
    embedding_provenance: Optional[Dict[str, Any]] = None,
) -> float:
    """Compute embedding similarity without lexical fallback."""
    left = left or ""
    right = right or ""
    if not left.strip() or not right.strip():
        if embedding_provenance is not None:
            embedding_provenance["skipped_empty_inputs"] = (
                to_int(embedding_provenance.get("skipped_empty_inputs")) + 1
            )
            embedding_provenance["last_event"] = "skipped_empty_input"
        return 0.0
    if text_retriever is None:
        if require_embedding:
            reason = "embedding retriever is unavailable"
            if embedding_provenance is not None:
                embedding_provenance["fallback_used"] = False
                embedding_provenance["fallback_reason"] = reason
            raise EmbeddingUnavailableError(reason, provenance=embedding_provenance)
        return 0.0

    try:
        score = float(text_retriever.similarity(left, right))
        if not math.isfinite(score):
            raise ValueError(f"non-finite embedding similarity score: {score!r}")
        if embedding_provenance is not None:
            embedding_provenance["backend"] = (
                getattr(text_retriever, "backend", None)
                or embedding_provenance.get("backend")
            )
            embedding_provenance["successful_similarity_calls"] = (
                to_int(embedding_provenance.get("successful_similarity_calls")) + 1
            )
            embedding_provenance["last_event"] = "embedding_similarity"
        return score
    except Exception as exc:  # pylint: disable=broad-except
        reason = f"{type(exc).__name__}: {exc}"
        if embedding_provenance is not None:
            embedding_provenance["fallback_used"] = not require_embedding
            embedding_provenance["fallback_reason"] = reason
            embedding_provenance["last_event"] = (
                "embedding_failure" if require_embedding else "zero_fallback"
            )
        if require_embedding:
            raise EmbeddingUnavailableError(
                f"Embedding-only similarity failed during evaluation mode: {reason}",
                provenance=embedding_provenance,
            ) from exc
        logger.warning("Embedding-only similarity failed at runtime; treating score as 0. error=%s", exc)
        return 0.0
