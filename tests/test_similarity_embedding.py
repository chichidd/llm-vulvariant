from scanner.similarity.embedding import (
    DEFAULT_EMBEDDING_MODEL_NAME,
    EmbeddingRetrievalConfig,
    EmbeddingRetriever,
    embedding_model_artifact_signature,
    cosine_similarity,
    get_cached_embedding_retriever,
)
from scanner.similarity import embedding as embedding_module
from scanner.similarity import retriever as similarity_retriever


def _make_retriever(normalize: bool):
    retriever = object.__new__(EmbeddingRetriever)
    retriever.config = EmbeddingRetrievalConfig(normalize=normalize)
    retriever._backend = "mock"
    return retriever


def test_cosine_similarity_handles_zero_vector():
    assert cosine_similarity([0.0, 0.0], [1.0, 2.0]) == 0.0
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0


def test_similarity_uses_dot_product_when_normalized(monkeypatch):
    retriever = _make_retriever(normalize=True)
    monkeypatch.setattr(retriever, "embed", lambda snippets: [[1.0, 0.0], [0.5, 0.5]])

    score = retriever.similarity("left", "right")
    assert score == 0.5


def test_similarity_uses_cosine_when_not_normalized(monkeypatch):
    retriever = _make_retriever(normalize=False)
    monkeypatch.setattr(retriever, "embed", lambda snippets: [[1.0, 1.0], [2.0, 2.0]])

    score = retriever.similarity("left", "right")
    assert abs(score - 1.0) < 1e-9


def test_embedding_retriever_accepts_direct_model_directory_as_default(monkeypatch, tmp_path):
    model_dir = tmp_path / "embedding-model"
    model_dir.mkdir()
    (model_dir / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(model_dir))

    retriever = EmbeddingRetriever(config=EmbeddingRetrievalConfig(model_name=None))

    assert retriever.model_path == model_dir


def test_embedding_retriever_respects_model_name_when_base_path_is_direct_model_dir(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    default_model_dir = model_base / "default-model"
    override_model_dir = model_base / "override-model"
    default_model_dir.mkdir(parents=True)
    override_model_dir.mkdir(parents=True)
    (default_model_dir / "config.json").write_text("{}", encoding="utf-8")
    (override_model_dir / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(default_model_dir))

    retriever = EmbeddingRetriever(config=EmbeddingRetrievalConfig(model_name="override-model"))

    assert retriever.model_path == override_model_dir


def test_embedding_retriever_keeps_direct_model_directory_as_default(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    direct_model_dir = model_base / "direct-model"
    sibling_default_dir = model_base / DEFAULT_EMBEDDING_MODEL_NAME
    direct_model_dir.mkdir(parents=True)
    sibling_default_dir.mkdir(parents=True)
    (direct_model_dir / "config.json").write_text("{}", encoding="utf-8")
    (sibling_default_dir / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(direct_model_dir))

    retriever = EmbeddingRetriever(config=EmbeddingRetrievalConfig(model_name=None))

    assert retriever.model_path == direct_model_dir


def test_embedding_retriever_defaults_model_name_when_none(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    model_dir = model_base / DEFAULT_EMBEDDING_MODEL_NAME
    model_dir.mkdir(parents=True)
    (model_dir / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(model_base))

    retriever = EmbeddingRetriever(config=EmbeddingRetrievalConfig(model_name=None))

    assert retriever.config.model_name == DEFAULT_EMBEDDING_MODEL_NAME
    assert retriever.model_path == model_dir


def test_get_cached_embedding_retriever_reuses_loaded_instance(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    model_dir = model_base / DEFAULT_EMBEDDING_MODEL_NAME
    model_dir.mkdir(parents=True)
    (model_dir / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(model_base))
    monkeypatch.setattr(EmbeddingRetriever, "_ensure_loaded", lambda self: setattr(self, "_backend", "mock"))
    embedding_module._RETRIEVER_CACHE.clear()

    first = get_cached_embedding_retriever(model_name=None, device="cpu")
    second = get_cached_embedding_retriever(model_name=None, device="cpu")

    assert first is second


def test_get_cached_embedding_retriever_invalidates_when_model_artifact_changes(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    model_dir = model_base / DEFAULT_EMBEDDING_MODEL_NAME
    model_dir.mkdir(parents=True)
    config_path = model_dir / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(model_base))
    monkeypatch.setattr(EmbeddingRetriever, "_ensure_loaded", lambda self: setattr(self, "_backend", "mock"))
    embedding_module._RETRIEVER_CACHE.clear()

    first = get_cached_embedding_retriever(model_name=None, device="cpu")
    config_path.write_text("{\"updated\": true}", encoding="utf-8")
    second = get_cached_embedding_retriever(model_name=None, device="cpu")

    assert first is not second


def test_embedding_model_artifact_signature_changes_when_model_files_change(monkeypatch, tmp_path):
    model_base = tmp_path / "embedding-models"
    model_dir = model_base / DEFAULT_EMBEDDING_MODEL_NAME
    model_dir.mkdir(parents=True)
    config_path = model_dir / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.setitem(embedding_module._path_config, "embedding_model_path", str(model_base))

    first = embedding_model_artifact_signature(None)
    config_path.write_text("{\"updated\": true}", encoding="utf-8")
    second = embedding_model_artifact_signature(None)

    assert first["resolved_model_path"] == second["resolved_model_path"]
    assert first["artifact_hash"] != second["artifact_hash"]


def test_build_text_retriever_returns_none_on_load_failure(monkeypatch):
    class BrokenRetriever:
        def __init__(self, config):
            self.config = config

        def _ensure_loaded(self):
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(similarity_retriever, "EmbeddingRetriever", BrokenRetriever)

    assert similarity_retriever.build_text_retriever(model_name=None, device="cpu") is None
