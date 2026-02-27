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
from typing import Dict, Iterable, List, Optional, Sequence, Set
import json
import re

from profiler.software.models import ModuleInfo, SoftwareProfile
from scanner.similarity.embedding import EmbeddingRetrievalConfig, EmbeddingRetriever
from utils.logger import get_logger

logger = get_logger(__name__)


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
    metrics: ProfileSimilarityMetrics

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_name": self.profile_ref.repo_name,
            "commit_hash": self.profile_ref.commit_hash,
            "label": self.profile_ref.label,
            "metrics": self.metrics.to_dict(),
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
                refs.append(
                    ProfileRef(
                        repo_name=repo_name,
                        commit_hash=commit_dir.name,
                        profile=profile,
                    )
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning(f"Failed to load profile {profile_path}: {exc}")
    return refs


def resolve_profile_commit(
    repo_profiles_dir: Path,
    repo_name: str,
    commit_hint: Optional[str] = None,
) -> Optional[str]:
    """Resolve a profile commit hash by optional full/prefix hint."""
    repo_dir = Path(repo_profiles_dir) / repo_name
    if not repo_dir.exists() or not repo_dir.is_dir():
        return None

    commits = sorted([p.name for p in repo_dir.iterdir() if p.is_dir()])
    if not commits:
        return None

    if commit_hint:
        for commit in commits:
            if commit == commit_hint or commit.startswith(commit_hint):
                return commit
        return None

    # No hint: pick the lexicographically latest commit directory.
    return commits[-1]


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
        for ref in by_repo:
            if ref.commit_hash == commit_hint or ref.commit_hash.startswith(commit_hint):
                return ref
        return None

    return sorted(by_repo, key=lambda r: r.commit_hash)[-1]


def build_text_retriever(
    model_name: str = "BAAI--bge-large-en-v1.5",
    device: str = "cpu",
) -> Optional[EmbeddingRetriever]:
    """Build an embedding retriever for text similarity.

    Falls back to `None` when the model cannot be loaded.
    """
    config = EmbeddingRetrievalConfig(
        model_name=model_name,
        device=device,
        batch_size=32,
        normalize=True,
    )
    try:
        return EmbeddingRetriever(config=config)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(f"Falling back to lexical text similarity: {exc}")
        return None


def compute_profile_similarity(
    source_profile: SoftwareProfile,
    target_profile: SoftwareProfile,
    text_retriever: Optional[EmbeddingRetriever] = None,
    weights: Optional[Dict[str, float]] = None,
) -> ProfileSimilarityMetrics:
    """Compute profile similarity with five dimensions.

    Metrics:
    1) description similarity (embedding or lexical fallback)
    2) target application similarity (embedding or lexical fallback)
    3) target user similarity (embedding or lexical fallback)
    4) module-name Jaccard similarity
    5) module dependency/import Jaccard similarity
    """
    weights = weights or DEFAULT_SIMILARITY_WEIGHTS

    description_sim = _text_similarity(
        source_profile.description,
        target_profile.description,
        text_retriever=text_retriever,
    )
    target_application_sim = _text_similarity(
        " | ".join(source_profile.target_application or []),
        " | ".join(target_profile.target_application or []),
        text_retriever=text_retriever,
    )
    target_user_sim = _text_similarity(
        " | ".join(source_profile.target_user or []),
        " | ".join(target_profile.target_user or []),
        text_retriever=text_retriever,
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


def rank_similar_profiles(
    source_ref: ProfileRef,
    candidate_refs: Sequence[ProfileRef],
    *,
    top_k: int = 3,
    text_retriever: Optional[EmbeddingRetriever] = None,
    weights: Optional[Dict[str, float]] = None,
    exclude_same_repo: bool = True,
) -> List[SimilarProfileCandidate]:
    """Rank candidate profiles by similarity to source profile."""
    if top_k <= 0:
        return []

    ranked: List[SimilarProfileCandidate] = []
    for candidate_ref in candidate_refs:
        if candidate_ref.repo_name == source_ref.repo_name and exclude_same_repo:
            continue
        if candidate_ref.repo_name == source_ref.repo_name and candidate_ref.commit_hash == source_ref.commit_hash:
            continue

        metrics = compute_profile_similarity(
            source_ref.profile,
            candidate_ref.profile,
            text_retriever=text_retriever,
            weights=weights,
        )
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


def _tokenize_text(value: str) -> Set[str]:
    if not value:
        return set()
    return set(re.findall(r"[a-zA-Z0-9_\\.\\-/]+", value.lower()))


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
) -> float:
    left = left or ""
    right = right or ""
    if not left.strip() or not right.strip():
        return 0.0

    if text_retriever is not None:
        try:
            return float(text_retriever.similarity(left, right))
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug(f"Embedding similarity failed, using lexical fallback: {exc}")

    return _jaccard_similarity(_tokenize_text(left), _tokenize_text(right))


class SimilarityRetriever:
    """Backward-compatible wrapper around `compute_profile_similarity`."""

    def __init__(self, embedding_config: Optional[EmbeddingRetrievalConfig] = None):
        self.embedding_config = embedding_config or EmbeddingRetrievalConfig(
            model_name="BAAI--bge-large-en-v1.5",
            device="cpu",
            batch_size=32,
            normalize=True,
        )
        self.text_retriever: Optional[EmbeddingRetriever]
        try:
            self.text_retriever = EmbeddingRetriever(config=self.embedding_config)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(f"SimilarityRetriever falls back to lexical mode: {exc}")
            self.text_retriever = None

    def compute_profile_similarity(
        self,
        profile1: SoftwareProfile,
        profile2: SoftwareProfile,
    ) -> Dict[str, float]:
        metrics = compute_profile_similarity(
            source_profile=profile1,
            target_profile=profile2,
            text_retriever=self.text_retriever,
        )
        return metrics.to_dict()
