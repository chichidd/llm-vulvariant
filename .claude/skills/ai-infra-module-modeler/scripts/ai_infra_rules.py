"""Rule definitions for AI infra module classification.

Keep this file dependency-free so it can be reused by other scripts or tooling.
"""

# Coarse module rules (used by scan_repo.py).
COARSE_RULES = {
    "platform_systems": {
        "keywords": [
            "triton", "cuda", "cudnn", "cutlass", "nvcc", "rocblas", "rocm", "hip",
            "kernel", "fused", "custom op", "torch extension", "cmake", "bazel",
            "ray", "slurm", "kubernetes operator", "scheduler",
        ],
        "path_hints": ["csrc", "kernels", "cuda", "triton", "cmake", "bazel", "runtime", "bindings"],
        "dep_hints": ["triton", "nvidia", "cupy", "jaxlib", "ray"],
    },
    "data_knowledge": {
        "keywords": [
            "dataset", "dataloader", "tokenizer", "tokenization", "preprocess", "dedup",
            "shard", "parquet", "arrow", "webdataset", "crawl", "scrape", "ingest",
            "s3", "gcs", "hdfs", "etl", "document loader", "connector",
        ],
        "path_hints": ["data", "datasets", "tokenizer", "preprocess", "ingest", "etl", "loaders", "connectors"],
        "dep_hints": ["datasets", "pyarrow", "webdataset", "tiktoken"],
    },
    "model_assets_loading": {
        "keywords": [
            "from_pretrained", "safetensors", "checkpoint", "model card", "config.json",
            "tokenizer.json", "processor", "gguf", "ggml", "onnx", "tensorrt", "export",
            "quantize", "adapter", "lora",
        ],
        "path_hints": ["models", "modeling", "checkpoints", "weights", "tokenizer", "export", "convert"],
        "dep_hints": ["transformers", "safetensors", "onnxruntime", "tensorrt"],
    },
    "training_optimization": {
        "keywords": [
            "train", "trainer", "pretrain", "finetune", "gradient", "optimizer",
            "lr schedule", "checkpointing", "ddp", "fsdp", "deepspeed", "zero",
            "tensor parallel", "pipeline parallel", "megatron", "moe",
        ],
        "path_hints": ["train", "training", "pretrain", "recipes", "configs", "hydra"],
        "dep_hints": ["deepspeed", "lightning", "accelerate", "megatron"],
    },
    "post_training_alignment": {
        "keywords": [
            "sft", "lora", "qlora", "peft", "dpo", "grpo", "kto", "orpo", "rlhf",
            "reward model", "preference", "ppo", "rlaif", "alignment",
        ],
        "path_hints": ["rlhf", "alignment", "dpo", "sft", "lora", "peft", "reward"],
        "dep_hints": ["trl", "peft", "trlx"],
    },
    "inference_acceleration": {
        "keywords": [
            "inference", "serving engine", "kv cache", "paged attention", "batching",
            "speculative decoding", "throughput", "latency", "token/s", "quantization",
        ],
        "path_hints": ["inference", "engine", "decoder", "kv", "cache", "benchmark"],
        "dep_hints": ["vllm", "sglang", "tgi", "llama.cpp"],
    },
    "serving_deployment": {
        "keywords": [
            "openai compatible", "chat/completions", "fastapi", "uvicorn", "grpc",
            "docker", "helm", "k8s", "kubernetes", "ingress", "autoscaling",
            "auth", "rate limit", "api server",
        ],
        "path_hints": ["serve", "server", "deployment", "deploy", "helm", "k8s", "docker"],
        "dep_hints": ["fastapi", "uvicorn", "grpcio", "kserve"],
    },
    "rag_retrieval": {
        "keywords": [
            "rag", "retrieval", "retriever", "embedding", "vector", "index",
            "rerank", "bm25", "hybrid search", "citation", "grounding",
        ],
        "path_hints": ["rag", "retrieval", "retriever", "embeddings", "vector", "index"],
        "dep_hints": ["faiss", "milvus", "qdrant", "weaviate", "chromadb"],
    },
    "agents_tooling": {
        "keywords": [
            "agent", "tool calling", "function calling", "planner", "executor",
            "workflow", "graph", "langgraph", "memory", "tool registry",
        ],
        "path_hints": ["agents", "tools", "tooling", "workflows", "graph"],
        "dep_hints": ["langchain", "llama_index"],
    },
    "eval_benchmarking": {
        "keywords": [
            "eval", "evaluation", "benchmark", "lm-eval", "score", "metric",
            "regression", "golden", "test suite", "perplexity",
        ],
        "path_hints": ["eval", "evaluation", "bench", "benchmark", "tests"],
        "dep_hints": ["evaluate", "lm_eval"],
    },
    "safety_security": {
        "keywords": [
            "security", "safety", "guardrail", "moderation", "pii", "redaction",
            "prompt injection", "sandbox", "sbom", "slsa", "cosign", "cve",
        ],
        "path_hints": ["security", "safety", "guardrails", "policies"],
        "dep_hints": [],
    },
    "observability_llmops": {
        "keywords": [
            "mlflow", "experiment tracking", "model registry", "trace", "tracing",
            "opentelemetry", "prometheus", "metrics", "logging", "dashboard",
            "cicd", "pipeline",
        ],
        "path_hints": ["mlops", "llmops", "observability", "monitor", "telemetry"],
        "dep_hints": ["mlflow", "opentelemetry", "prometheus_client"],
    },
    "ui_workflow": {
        "keywords": [
            "webui", "playground", "dashboard", "react", "nextjs", "gradio",
            "streamlit", "workflow builder", "react-flow", "ui",
        ],
        "path_hints": ["ui", "web", "frontend", "dashboard", "studio"],
        "dep_hints": ["gradio", "streamlit"],
    },
}

# Fine-grained rules by coarse category.
FINE_RULES = {
    "platform_systems": {
        "build_packaging": {
            "keywords": [
                "setup.py", "pyproject", "setup.cfg", "cmake", "bazel",
                "build", "package", "packaging", "wheel", "sdist",
            ],
            "path_hints": ["setup.py", "pyproject", "cmake", "bazel", "build", "packaging"],
        },
        "runtime_hardware": {
            "keywords": ["cuda", "rocm", "triton", "kernel", "gpu", "device", "cudnn"],
            "path_hints": ["cuda", "rocm", "triton", "kernels", "runtime"],
        },
        "distributed_orchestration": {
            "keywords": ["distributed", "orchestr", "cluster", "scheduler", "slurm", "ray", "kubernetes", "k8s"],
            "path_hints": ["distributed", "orchestr", "cluster", "scheduler", "slurm", "ray", "k8s", "kubernetes"],
        },
    },
    "data_knowledge": {
        "ingestion_connectors": {
            "keywords": ["ingest", "connector", "loader", "crawl", "scrape", "s3", "gcs", "hdfs", "api"],
            "path_hints": ["ingest", "connector", "loader", "crawl", "scrape", "s3", "gcs", "hdfs"],
        },
        "dataset_construction": {
            "keywords": ["dataset", "shard", "dedup", "sample", "mix", "corpus", "split"],
            "path_hints": ["dataset", "shard", "dedup", "sample", "mix"],
        },
        "preprocess_tokenization": {
            "keywords": ["preprocess", "token", "tokenizer", "normalize", "clean"],
            "path_hints": ["preprocess", "token", "tokenizer"],
        },
        "storage_formats": {
            "keywords": ["parquet", "arrow", "jsonl", "csv", "format", "storage", "webdataset"],
            "path_hints": ["parquet", "arrow", "jsonl", "csv", "format", "storage"],
        },
        "knowledge_stores": {
            "keywords": ["vector", "index", "store", "faiss", "milvus", "qdrant", "weaviate", "chromadb"],
            "path_hints": ["vector", "index", "store", "faiss", "milvus", "qdrant", "weaviate", "chromadb"],
        },
    },
    "model_assets_loading": {
        "model_definition": {
            "keywords": ["modeling", "architecture", "backbone", "layer", "transformer"],
            "path_hints": ["model", "modeling", "architecture", "backbone"],
        },
        "checkpoint_formats": {
            "keywords": ["checkpoint", "safetensors", "gguf", "ggml", "weights", "ckpt"],
            "path_hints": ["checkpoint", "safetensors", "gguf", "ggml", "weights"],
        },
        "loading_configuration": {
            "keywords": ["from_pretrained", "config", "model card", "load", "loader"],
            "path_hints": ["config", "load", "loader", "from_pretrained"],
        },
        "tokenizers_processors": {
            "keywords": ["tokenizer", "processor", "preprocess"],
            "path_hints": ["tokenizer", "processor"],
        },
        "export_interchange": {
            "keywords": ["export", "onnx", "tensorrt", "torchscript", "convert"],
            "path_hints": ["export", "onnx", "tensorrt", "torchscript", "convert"],
        },
    },
    "training_optimization": {
        "training_loop": {
            "keywords": ["train", "trainer", "training_step", "loss", "backward", "epoch"],
            "path_hints": ["train", "trainer", "training"],
        },
        "distributed_training": {
            "keywords": ["ddp", "fsdp", "deepspeed", "zero", "megatron", "tensor parallel", "pipeline parallel", "distributed"],
            "path_hints": ["ddp", "fsdp", "deepspeed", "megatron", "distributed", "parallel"],
        },
        "optim_schedules": {
            "keywords": ["optimizer", "lr", "schedule", "warmup", "adam", "adagrad", "adamw"],
            "path_hints": ["optimizer", "schedule", "lr", "warmup"],
        },
        "checkpoint_ft": {
            "keywords": ["checkpoint", "resume", "save", "load", "finetune", "fine-tune", "ft"],
            "path_hints": ["checkpoint", "resume", "finetune", "fine-tune", "ft"],
        },
        "experiment_configs": {
            "keywords": ["config", "yaml", "json", "hydra", "recipe"],
            "path_hints": ["config", "configs", "recipe", "hydra"],
        },
    },
    "post_training_alignment": {
        "sft": {
            "keywords": ["sft", "supervised fine-tuning", "finetune", "fine-tune"],
            "path_hints": ["sft", "finetune", "fine-tune"],
        },
        "peft": {
            "keywords": ["peft", "lora", "qlora", "adapter"],
            "path_hints": ["peft", "lora", "qlora", "adapter"],
        },
        "preference_learning": {
            "keywords": ["dpo", "grpo", "kto", "orpo", "preference", "reward"],
            "path_hints": ["dpo", "grpo", "kto", "orpo", "preference", "reward"],
        },
        "rlhf_rlaif": {
            "keywords": ["rlhf", "rlaif", "ppo", "rollout"],
            "path_hints": ["rlhf", "rlaif", "ppo", "rollout"],
        },
        "distillation_qaware": {
            "keywords": ["distill", "quant", "distillation", "qaware"],
            "path_hints": ["distill", "quant", "qaware"],
        },
    },
    "inference_acceleration": {
        "inference_runtime": {
            "keywords": ["inference", "decode", "stream", "generation", "engine"],
            "path_hints": ["inference", "decode", "engine", "runtime"],
        },
        "kv_cache_memory": {
            "keywords": ["kv", "cache", "memory", "paged"],
            "path_hints": ["kv", "cache", "memory", "paged"],
        },
        "inference_parallelism": {
            "keywords": ["parallel", "tensor", "pipeline", "speculative", "batch", "parallelism"],
            "path_hints": ["parallel", "tensor", "pipeline", "speculative", "batch"],
        },
        "quant_kernels": {
            "keywords": ["quant", "kernel", "gptq", "awq", "int8", "fp8", "quantization"],
            "path_hints": ["quant", "kernel", "gptq", "awq", "int8", "fp8"],
        },
        "perf_bench": {
            "keywords": ["benchmark", "perf", "latency", "throughput"],
            "path_hints": ["benchmark", "perf", "latency", "throughput"],
        },
    },
    "serving_deployment": {
        "serving_api": {
            "keywords": ["api", "server", "fastapi", "grpc", "openai", "rest", "http"],
            "path_hints": ["api", "server", "serve", "grpc", "fastapi"],
        },
        "deployment_artifacts": {
            "keywords": ["docker", "compose", "helm", "k8s", "kubernetes", "deployment", "manifest"],
            "path_hints": ["docker", "compose", "helm", "k8s", "kubernetes", "deployment", "manifest"],
        },
        "autoscaling_routing": {
            "keywords": ["autoscale", "routing", "load balancer", "canary", "traffic", "gateway"],
            "path_hints": ["autoscale", "routing", "load", "canary", "gateway"],
        },
        "auth_ratelimit": {
            "keywords": ["auth", "oauth", "rate", "quota", "token", "apikey", "api key"],
            "path_hints": ["auth", "oauth", "rate", "quota", "apikey", "api_key"],
        },
        "multi_tenant_isolation": {
            "keywords": ["tenant", "isolation", "namespace", "multi-tenant"],
            "path_hints": ["tenant", "isolation", "namespace", "multi-tenant"],
        },
    },
    "rag_retrieval": {
        "doc_loaders_chunking": {
            "keywords": ["loader", "document", "chunk", "pdf", "html", "parser"],
            "path_hints": ["loader", "document", "chunk", "pdf", "html", "parser"],
        },
        "embedding_indexing": {
            "keywords": ["embedding", "index", "vector", "faiss", "milvus", "qdrant", "weaviate", "chromadb"],
            "path_hints": ["embedding", "index", "vector", "faiss", "milvus", "qdrant", "weaviate", "chromadb"],
        },
        "retrieval_rerank": {
            "keywords": ["retrieval", "retriever", "rerank", "bm25", "search"],
            "path_hints": ["retrieval", "retriever", "rerank", "bm25", "search"],
        },
        "citation_attribution": {
            "keywords": ["citation", "attribution", "source", "grounding"],
            "path_hints": ["citation", "attribution", "grounding"],
        },
        "hybrid_search": {
            "keywords": ["hybrid", "bm25", "dense", "sparse"],
            "path_hints": ["hybrid", "bm25", "dense", "sparse"],
        },
    },
    "agents_tooling": {
        "tool_function_calling": {
            "keywords": ["tool", "function", "call", "schema"],
            "path_hints": ["tool", "function", "call", "schema"],
        },
        "planning_orchestration": {
            "keywords": ["planner", "planning", "orchestration", "workflow", "graph", "langgraph"],
            "path_hints": ["planner", "planning", "orchestr", "workflow", "graph", "langgraph"],
        },
        "memory_state": {
            "keywords": ["memory", "state", "checkpoint", "session", "history"],
            "path_hints": ["memory", "state", "session", "history"],
        },
        "integrations_plugins": {
            "keywords": ["integration", "plugin", "connector", "toolkit"],
            "path_hints": ["integration", "plugin", "connector", "toolkit"],
        },
    },
    "eval_benchmarking": {
        "quality_eval": {
            "keywords": ["eval", "evaluation", "metric", "score", "benchmark"],
            "path_hints": ["eval", "evaluation", "metric", "benchmark"],
        },
        "safety_eval": {
            "keywords": ["safety", "jailbreak", "redteam", "guardrail"],
            "path_hints": ["safety", "jailbreak", "redteam", "guardrail"],
        },
        "perf_eval": {
            "keywords": ["performance", "perf", "latency", "throughput"],
            "path_hints": ["performance", "perf", "latency", "throughput"],
        },
        "regression_tests": {
            "keywords": ["regression", "test", "unit", "integration"],
            "path_hints": ["regression", "test", "unit", "integration"],
        },
    },
    "safety_security": {
        "guardrails_policy": {
            "keywords": ["guardrail", "policy", "moderation", "filter"],
            "path_hints": ["guardrail", "policy", "moderation", "filter"],
        },
        "sandbox_permissioning": {
            "keywords": ["sandbox", "permission", "allowlist", "denylist"],
            "path_hints": ["sandbox", "permission", "allowlist", "denylist"],
        },
        "supply_chain": {
            "keywords": ["sbom", "slsa", "cosign", "supply"],
            "path_hints": ["sbom", "slsa", "cosign", "supply"],
        },
        "hardening_guidance": {
            "keywords": ["hardening", "secure", "security", "best practice"],
            "path_hints": ["hardening", "secure", "security", "best"],
        },
    },
    "observability_llmops": {
        "experiment_tracking": {
            "keywords": ["mlflow", "wandb", "tracking", "experiment"],
            "path_hints": ["mlflow", "wandb", "tracking", "experiment"],
        },
        "model_registry": {
            "keywords": ["registry", "artifact", "model registry"],
            "path_hints": ["registry", "artifact", "model_registry"],
        },
        "tracing_metrics_logs": {
            "keywords": ["trace", "tracing", "metrics", "logging", "opentelemetry", "prometheus"],
            "path_hints": ["trace", "tracing", "metrics", "logging", "opentelemetry", "prometheus"],
        },
        "cicd_governance": {
            "keywords": ["cicd", "governance", "pipeline", "release", "compliance"],
            "path_hints": ["cicd", "governance", "pipeline", "release"],
        },
    },
    "ui_workflow": {
        "web_ui": {
            "keywords": ["ui", "web", "frontend", "react", "gradio", "streamlit"],
            "path_hints": ["ui", "web", "frontend", "react", "gradio", "streamlit"],
        },
        "workflow_builder": {
            "keywords": ["workflow", "builder", "graph", "node", "canvas"],
            "path_hints": ["workflow", "builder", "graph", "node", "canvas"],
        },
        "cli_dx": {
            "keywords": ["cli", "sdk", "command", "tool"],
            "path_hints": ["cli", "sdk", "command"],
        },
        "templates_examples": {
            "keywords": ["template", "example", "sample", "demo"],
            "path_hints": ["template", "example", "sample", "demo"],
        },
    },
}

