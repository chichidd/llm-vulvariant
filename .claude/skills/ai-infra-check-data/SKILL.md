---
name: ai-infra-check-data
description: Determine whether a repository contains data infra (ingestion, processing, datasets, embedding/indexing for RAG) and record evidence.
metadata:
  short-description: Check data/dataset/retrieval modules
---

# ai-infra-check-data

## Scope
Modules that ingest/prepare datasets or build retrieval indexes.

### Includes
- Dataset connectors, streaming ingestion, dataset format tooling (JSONL/Parquet/WebDataset).
- Cleaning/dedup/filtering, chunking/parsing (PDF/HTML/DOCX), labeling/annotation, synthetic data.
- Embedding generation and vector index build/refresh; adapters for vector DBs.

### Evidence checklist
Provide 2+ signals:
1. Directories: `data/`, `datasets/`, `ingest/`, `preprocess/`, `etl/`, `doc_loaders/`.
2. Libraries: `datasets`, `pyarrow`, `parquet`, `pandas`, `unstructured`, `pdfplumber`, `tiktoken`.
3. Retrieval: `embeddings`, `vectorstore`, `milvus`, `qdrant`, `weaviate`, `chroma`, `faiss`.
4. Scripts: `build_index*`, `embed*`, `chunk*`, `dedup*`.

### Fine-grained labels
- `data.ingestion_and_connectors.*`
- `data.processing_and_quality.*`
- `data.retrieval_and_index.*`

## Output
Record label, evidence file paths, and confidence.
