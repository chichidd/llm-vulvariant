from scanner.similarity.embedding import (
    EmbeddingRetrievalConfig,
    EmbeddingRetriever,
    cosine_similarity,
)


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
