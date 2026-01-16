# Checklist: RAG & Retrieval

## Scope
Covers inference-time grounding over external knowledge: document loaders, chunking, embedding, indexing, retrieval, reranking, citation/attribution, hybrid search.

## Include when you see
- Vector DB clients or embedded index (FAISS/Milvus/Qdrant/Weaviate/Chroma), or BM25 + vectors.
- Document loaders and preprocessors (PDF/HTML/GitHub/Confluence, etc.).
- Retriever + re-ranker + prompt assembly pipeline.

## Exclude / avoid double counting
- General data preprocessing for training goes in **Data & Knowledge** unless it's specifically retrieval-time.
- Agent planners/tool execution is **Agents & Tooling**, even if it wraps retrieval as a tool.

## Common signals
- Directories: `retrieval/`, `rag/`, `index/`, `embeddings/`, `vectorstore/`, `loaders/`, `chunking/`.
- Dependencies/keywords: `faiss`, `milvus`, `qdrant`, `weaviate`, `chromadb`, `elasticsearch`, `bm25`, `rerank`, `embedding`, `top_k`.
- Files: configs for chunk size, embedding model, index build scripts, citation logic.

## Typical submodules
- Document ingestion + parsing
- Chunking + embedding
- Index build + maintenance
- Query-time retrieval + reranking
- Context assembly + citations

## Evidence to collect
- The retriever entrypoint and how it binds to a store.
- Index build scripts and schema.
- README sections describing RAG flows.
