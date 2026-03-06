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

"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Sequence
import math
import logging

from config import _path_config

logger = logging.getLogger(__name__)


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
	"""Cosine similarity between two vectors."""
	denom_a = math.sqrt(sum(x * x for x in a))
	denom_b = math.sqrt(sum(x * x for x in b))
	if denom_a == 0.0 or denom_b == 0.0:
		return 0.0
	return sum(x * y for x, y in zip(a, b)) / (denom_a * denom_b)


@dataclass
class EmbeddingRetrievalConfig:
	model_name: Optional[str] = 'jinaai--jina-code-embeddings-1.5b'
	device: Optional[str] = 'cpu'
	batch_size: int = 32
	max_length: int = 65536
	normalize: bool = True
	trust_remote_code: bool = True


class EmbeddingRetriever:
	"""Generate embeddings for code snippets and compare their similarity."""

	def __init__(
		self,
		config: Optional[EmbeddingRetrievalConfig] = None,
	):
		self.config = config or EmbeddingRetrievalConfig()
		self.model_path = Path(_path_config['embedding_model_path']) / self.config.model_name

		if not self.model_path.exists():
			raise FileNotFoundError(
				f"Embedding model path not found: {self.model_path}. Update config/paths.yaml.")
		
		self._model: Any = None
		self._backend: Optional[str] = None
		self._tokenizer: Any = None

	def _ensure_loaded(self) -> None:
		if self._model is not None:
			return

		# Backend 1: sentence-transformers
		try:
			from sentence_transformers import SentenceTransformer  # type: ignore

			self._model = SentenceTransformer(
				str(self.model_path),
				device=self.config.device,
				trust_remote_code=self.config.trust_remote_code,
			)
			self._backend = "sentence-transformers"
			return
		except Exception as e:
			logger.debug(f"Failed to load sentence-transformers model: {e}")

			# Backend 2: transformers
			try:
				import torch  # type: ignore
				from transformers import AutoModel, AutoTokenizer

				device = self.config.device
				if device is None:
					device = "cuda" if torch.cuda.is_available() else "cpu"

				self._tokenizer = AutoTokenizer.from_pretrained(
					str(self.model_path),
					trust_remote_code=self.config.trust_remote_code,
				)
				self._model = AutoModel.from_pretrained(
					str(self.model_path),
					trust_remote_code=self.config.trust_remote_code,
				).to(device)
				self._model.eval()
				self._backend = "transformers"
				return
			except Exception as e2:
				raise RuntimeError(
					"No embedding backend available. Install one of:\n"
					"- sentence-transformers\n"
					"- transformers + torch\n"
					f"Original errors:\n  sentence-transformers: {e}\n  transformers: {e2}"
				)

	def embed(self, snippets: Sequence[str]) -> List[List[float]]:
		"""Generate embeddings for code snippets."""
		self._ensure_loaded()

		cleaned = [s if isinstance(s, str) else "" for s in snippets]
		if self._backend == "sentence-transformers":
			return self._embed_sentence_transformers(cleaned)
		elif self._backend == "transformers":
			return self._embed_transformers(cleaned)
		raise RuntimeError("Embedding model is not loaded")

	def similarity(self, a: str, b: str) -> float:
		"""Compute similarity between two snippets."""
		va, vb = self.embed([a, b])
		if self.config.normalize:
			# When embeddings already normalized, cosine reduces to dot product.
			return sum(x * y for x, y in zip(va, vb))
		return cosine_similarity(va, vb)

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

		def _l2_normalize(vec: Sequence[float]) -> List[float]:
			denom = math.sqrt(sum(v * v for v in vec))
			if denom == 0.0:
				return [0.0 for _ in vec]
			return [v / denom for v in vec]

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
