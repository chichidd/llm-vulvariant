# Checklist: RAG & Tooling

## Scope
Covers inference-time grounding and context construction: document loaders, chunking, embedding, indexing, retrieval, reranking, citation/attribution, hybrid search, and tool/function calling used in RAG pipelines.

## Include when you see
- Vector DB clients or embedded index (FAISS/Milvus/Qdrant/Weaviate/Chroma), or BM25 + vectors.
- Document loaders and preprocessors (PDF/HTML/GitHub/Confluence, etc.).
- Retriever + re-ranker + prompt/context assembly pipeline.
- Tool/function calling used to fetch or ground context (tool schemas, tool execution for retrieval).

## Exclude / avoid double counting
- General data preprocessing for training goes in **Data & Knowledge** unless it's specifically retrieval-time.
- Agent planners and workflow orchestration are **Agent Orchestration & Workflows**; only tag this module for RAG-specific tool calling and context assembly.

## Common (but not all) signals
- Directories: `retrieval/`, `rag/`, `index/`, `embeddings/`, `vectorstore/`, `loaders/`, `chunking/`, `prompts/`.
- Dependencies/keywords: `faiss`, `milvus`, `qdrant`, `weaviate`, `chromadb`, `elasticsearch`, `bm25`, `rerank`, `embedding`, `top_k`, `tool_call`.
- Files: configs for chunk size, embedding model, index build scripts, prompt/context templates, citation logic.

## Typical submodules
- Document ingestion + parsing
- Chunking + embedding
- Index build + maintenance
- Query-time retrieval + reranking
- Prompt/context construction + citations
- RAG tool/function calling

## Evidence to collect
- The retriever entrypoint and how it binds to a store.
- Index build scripts and schema.
- README sections describing RAG flows.
