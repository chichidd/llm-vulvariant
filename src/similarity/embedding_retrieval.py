"""llm-vulvariant.src.similarity.embedding_retrieval

Use a local embedding model specified in `config/paths.yaml` to generate embeddings
for code snippets and perform similarity comparison.

Configuration
-------------
- `config/paths.yaml`:
  - `paths.embedding_model_path`: base directory that contains embedding models.
	If it points directly to a model directory, it will be used as-is.
  - (optional) `paths.embedding_model`: explicit model directory/name.

- Defaults:
  - If not specified, uses `models/jinaai--jina-code-embeddings-1.5b`.
  - Environment variable `LLM_VULVARIANT_EMBEDDING_MODEL` overrides everything.

Backends
--------
Prefers `sentence-transformers` when available; falls back to `transformers + torch`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import os
import math

import yaml


DEFAULT_MODEL_SUBDIR = "jinaai--jina-code-embeddings-1.5b"
DEFAULT_MODEL_RELATIVE = Path("models") / DEFAULT_MODEL_SUBDIR


def _repo_root_from_here() -> Path:
	# .../llm-vulvariant/src/similarity/embedding_retrieval.py -> .../llm-vulvariant
	return Path(__file__).resolve().parents[2]


def _load_paths_yaml(config_path: Optional[Path] = None) -> Dict[str, Any]:
	if config_path is None:
		config_path = _repo_root_from_here() / "config" / "paths.yaml"
	if not config_path.exists():
		return {}
	with open(config_path, "r", encoding="utf-8") as f:
		return yaml.safe_load(f) or {}


def resolve_embedding_model_path(
	*,
	config_path: Optional[Path] = None,
	model_path: Optional[str | Path] = None,
) -> Path:
	"""Resolve the embedding model directory.

	Priority:
	1) explicit `model_path` argument
	2) env var `LLM_VULVARIANT_EMBEDDING_MODEL`
	3) `paths.embedding_model` in `config/paths.yaml` (explicit model)
	4) `paths.embedding_model_path` in `config/paths.yaml` + default subdir
	5) repo-root relative default `models/jinaai--jina-code-embeddings-1.5b`
	"""

	if model_path is not None:
		return Path(model_path).expanduser()

	env_override = os.environ.get("LLM_VULVARIANT_EMBEDDING_MODEL")
	if env_override:
		return Path(env_override).expanduser()

	config = _load_paths_yaml(config_path)
	paths = (config.get("paths") or {}) if isinstance(config, dict) else {}

	explicit_model = paths.get("embedding_model")
	if isinstance(explicit_model, str) and explicit_model.strip():
		# allow either an absolute/local path or a model subdir name
		candidate = Path(explicit_model).expanduser()
		if candidate.is_absolute() or candidate.exists():
			return candidate

		base = paths.get("embedding_model_path")
		if isinstance(base, str) and base.strip():
			return (Path(base).expanduser() / explicit_model).expanduser()

	base_dir = paths.get("embedding_model_path")
	if isinstance(base_dir, str) and base_dir.strip():
		base_path = Path(base_dir).expanduser()
		# If base points to a model directory already (heuristic), use it.
		if _looks_like_model_dir(base_path):
			return base_path
		# Otherwise treat it as a directory containing models.
		candidate = base_path / DEFAULT_MODEL_SUBDIR
		if candidate.exists():
			return candidate

	return (_repo_root_from_here() / DEFAULT_MODEL_RELATIVE).expanduser()


def _looks_like_model_dir(path: Path) -> bool:
	if not path.exists() or not path.is_dir():
		return False
	# Common local HF/transformers artifacts
	markers = [
		"config.json",
		"tokenizer.json",
		"tokenizer_config.json",
		"pytorch_model.bin",
		"model.safetensors",
		"sentence_bert_config.json",
	]
	return any((path / m).exists() for m in markers)


def _l2_normalize(vec: Sequence[float]) -> List[float]:
	denom = math.sqrt(sum(v * v for v in vec))
	if denom == 0.0:
		return [0.0 for _ in vec]
	return [v / denom for v in vec]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
	"""Cosine similarity between two vectors."""
	denom_a = math.sqrt(sum(x * x for x in a))
	denom_b = math.sqrt(sum(x * x for x in b))
	if denom_a == 0.0 or denom_b == 0.0:
		return 0.0
	return sum(x * y for x, y in zip(a, b)) / (denom_a * denom_b)


@dataclass
class EmbeddingRetrievalConfig:
	model_path: Optional[Path] = None
	device: Optional[str] = None
	batch_size: int = 16
	max_length: int = 1024
	normalize: bool = True
	trust_remote_code: bool = True


class EmbeddingRetriever:
	"""Generate embeddings for code snippets and perform similarity retrieval."""

	def __init__(
		self,
		config: Optional[EmbeddingRetrievalConfig] = None,
		*,
		config_path: Optional[Path] = None,
	):
		self.config = config or EmbeddingRetrievalConfig()
		self._paths_yaml = config_path

		resolved = self.config.model_path or resolve_embedding_model_path(config_path=config_path)
		self.model_path = resolved

		self._backend: Optional[str] = None
		self._model: Any = None
		self._tokenizer: Any = None

	def _ensure_loaded(self) -> None:
		if self._model is not None:
			return

		model_path = self.model_path
		if not model_path.exists():
			raise FileNotFoundError(
				f"Embedding model path not found: {model_path}. "
				f"Set `LLM_VULVARIANT_EMBEDDING_MODEL` or update config/paths.yaml."
			)

		# Backend 1: sentence-transformers
		try:
			from sentence_transformers import SentenceTransformer  # type: ignore

			device = self.config.device
			self._model = SentenceTransformer(
				str(model_path),
				device=device,
				trust_remote_code=self.config.trust_remote_code,
			)
			self._backend = "sentence-transformers"
			return
		except Exception:
			pass

		# Backend 2: transformers + torch
		try:
			import torch  # type: ignore
			from transformers import AutoModel, AutoTokenizer  # type: ignore

			device = self.config.device
			if device is None:
				device = "cuda" if torch.cuda.is_available() else "cpu"

			self._tokenizer = AutoTokenizer.from_pretrained(
				str(model_path),
				trust_remote_code=self.config.trust_remote_code,
			)
			self._model = AutoModel.from_pretrained(
				str(model_path),
				trust_remote_code=self.config.trust_remote_code,
			).to(device)
			self._model.eval()
			self._backend = "transformers"
			return
		except Exception as e:
			raise RuntimeError(
				"No embedding backend available. Install one of:\n"
				"- sentence-transformers\n"
				"- transformers + torch\n"
				f"Original error: {e}"
			)

	def embed(self, snippets: Sequence[str]) -> List[List[float]]:
		"""Generate embeddings for code snippets."""
		self._ensure_loaded()

		cleaned = [s if isinstance(s, str) else "" for s in snippets]
		if self._backend == "sentence-transformers":
			return self._embed_sentence_transformers(cleaned)
		if self._backend == "transformers":
			return self._embed_transformers(cleaned)
		raise RuntimeError("Embedding model is not loaded")

	def similarity(self, a: str, b: str) -> float:
		"""Compute similarity between two snippets."""
		va, vb = self.embed([a, b])
		if self.config.normalize:
			# When embeddings already normalized, cosine reduces to dot product.
			return sum(x * y for x, y in zip(va, vb))
		return cosine_similarity(va, vb)

	def retrieve_top_k(
		self,
		query: str,
		candidates: Sequence[str],
		*,
		top_k: int = 5,
	) -> List[Dict[str, Any]]:
		"""Return top-k most similar candidates.

		Returns a list of dicts: {"index": int, "score": float, "snippet": str}
		"""
		if top_k <= 0:
			return []

		query_vec = self.embed([query])[0]
		cand_vecs = self.embed(list(candidates))

		scored: List[Tuple[int, float]] = []
		if self.config.normalize:
			for i, v in enumerate(cand_vecs):
				scored.append((i, sum(x * y for x, y in zip(query_vec, v))))
		else:
			for i, v in enumerate(cand_vecs):
				scored.append((i, cosine_similarity(query_vec, v)))

		scored.sort(key=lambda t: t[1], reverse=True)
		results = []
		for idx, score in scored[: min(top_k, len(scored))]:
			results.append({"index": idx, "score": float(score), "snippet": candidates[idx]})
		return results

	def _embed_sentence_transformers(self, snippets: Sequence[str]) -> List[List[float]]:
		# SentenceTransformer can handle batching/normalization natively.
		normalize = bool(self.config.normalize)
		emb = self._model.encode(
			list(snippets),
			batch_size=self.config.batch_size,
			normalize_embeddings=normalize,
			show_progress_bar=False,
		)

		# Ensure JSON-serializable Python lists.
		try:
			return emb.tolist()  # type: ignore[attr-defined]
		except Exception:
			return [list(map(float, row)) for row in emb]

	def _embed_transformers(self, snippets: Sequence[str]) -> List[List[float]]:
		import torch  # type: ignore

		device = self.config.device
		if device is None:
			device = "cuda" if torch.cuda.is_available() else "cpu"

		outputs: List[List[float]] = []
		bs = max(1, int(self.config.batch_size))

		with torch.no_grad():
			for start in range(0, len(snippets), bs):
				batch = snippets[start : start + bs]
				encoded = self._tokenizer(
					list(batch),
					padding=True,
					truncation=True,
					max_length=self.config.max_length,
					return_tensors="pt",
				)
				encoded = {k: v.to(device) for k, v in encoded.items()}
				model_out = self._model(**encoded)

				# Mean pooling with attention mask.
				last_hidden = model_out.last_hidden_state
				mask = encoded.get("attention_mask")
				if mask is None:
					pooled = last_hidden.mean(dim=1)
				else:
					mask = mask.unsqueeze(-1).expand(last_hidden.size()).float()
					summed = (last_hidden * mask).sum(dim=1)
					denom = mask.sum(dim=1).clamp(min=1e-9)
					pooled = summed / denom

				pooled = pooled.detach().cpu().tolist()
				if self.config.normalize:
					pooled = [_l2_normalize(vec) for vec in pooled]
				outputs.extend([list(map(float, vec)) for vec in pooled])

		return outputs

