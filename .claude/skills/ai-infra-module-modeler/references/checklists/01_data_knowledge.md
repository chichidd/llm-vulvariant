# Checklist: Data & Knowledge

## Scope
Covers components that **ingest, transform, store, and retrieve** data/knowledge for training or for inference-time grounding.

## Include when you see
- Data ingestion: web scraping, ETL, connectors to S3/GCS/HDFS/DB/API.
- Dataset construction: filtering, dedup, mixing, sharding, streaming.
- Tokenization/feature extraction pipelines (text/image/audio).
- Storage formats: Arrow/Parquet/WebDataset, dataset indices/manifests.
- Knowledge stores for RAG: vector indexes, document stores, hybrid search.

## Exclude / avoid double counting
- Pure evaluation datasets/benchmarks: classify under **Eval & Benchmarking** unless it is a general data pipeline.
- Retrieval logic tightly coupled to a RAG framework can be split: storage/index under Data & Knowledge; orchestration under **RAG & Retrieval**.

## Common signals
- Directories: `data/`, `datasets/`, `preprocess/`, `tokenizer/`, `corpus/`, `etl/`, `ingest/`, `connectors/`.
- Files: `dataset.py`, `dataloader.py`, `*.parquet`, `*.arrow`, `manifest.jsonl`, `wds*`.
- Dependencies/keywords: `datasets`, `webdataset`, `pyarrow`, `parquet`, `tokenizers`, `sentencepiece`, `ffmpeg`, `torchaudio`, `opencv`, `faiss`, `qdrant`, `milvus`.

## Typical submodules
- Connectors & ingestion
- Preprocessing & tokenization
- Dataset packaging (streaming/shards)
- Indexing / vector store adapters

## Evidence to collect
- README sections describing datasets, ingestion, or indexing.
- Configs showing data sources, schemas, sharding.
- Code paths implementing loaders, tokenizers, index builders.
