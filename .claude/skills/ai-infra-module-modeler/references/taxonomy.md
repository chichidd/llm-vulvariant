# AI Infra Module Taxonomy (coarse → fine)

This taxonomy is designed for **LLM / multimodal AI infrastructure repositories**: training, post-training, inference, serving, RAG, agentic applications, and supporting systems.

## 0. Platform & Systems (optional but common)
- 0.1 Build & packaging
  - Python packaging (pyproject/setup), wheels, versioning
  - Multi-language builds (Rust/Go/C++), bindings
- 0.2 Runtime & hardware abstraction
  - CUDA/ROCm/Metal/oneAPI backends, kernels, Triton
  - Device discovery, mixed-precision, quantization backends
- 0.3 Distributed compute & orchestration
  - Launcher, cluster runtime, scheduling integration
  - Multi-node communication (NCCL, Gloo), topology awareness

## 1. Data & Knowledge
- 1.1 Data ingestion & connectors
  - Filesystems/object stores, web sources, databases, APIs
- 1.2 Dataset construction
  - Filtering, dedup, sampling, mixing, sharding
- 1.3 Preprocessing & tokenization
  - Tokenizers, feature extraction (audio/vision), packing
- 1.4 Data formats & storage
  - Arrow/Parquet/WebDataset, streaming IO
- 1.5 Knowledge stores (for RAG)
  - Vector indexes, hybrid search, document stores

## 2. Model Assets & Loading
- 2.1 Model definition & architecture
  - Transformer backbones, diffusion/ASR models, multimodal
- 2.2 Checkpoint & weight formats
  - safetensors, gguf/ggml, sharded ckpts
- 2.3 Model loading & configuration
  - HF `from_pretrained`, config/model cards, adapters
- 2.4 Tokenizers & processors
  - text tokenizer, image/audio processors
- 2.5 Export & interchange
  - ONNX, TensorRT, TorchScript, GGUF conversion

## 3. Training & Optimization
- 3.1 Training loop / trainer
  - epoch/step loop, gradient accumulation, logging
- 3.2 Distributed training
  - DDP/FSDP/ZeRO, tensor/pipeline parallel, MoE
- 3.3 Optimization & schedules
  - optimizers, LR schedules, clipping, EMA
- 3.4 Checkpointing & fault tolerance
  - save/restore, reshard, resume
- 3.5 Experiment configuration
  - YAML/JSON configs, Hydra/Argparse, recipes

## 4. Post-training & Alignment
- 4.1 Supervised fine-tuning (SFT)
- 4.2 Parameter-efficient tuning (LoRA/QLoRA/Adapters)
- 4.3 Preference learning
  - DPO/GRPO/KTO/ORPO, reward modeling
- 4.4 RLHF / RLAIF pipelines
  - rollout, reward, PPO-style alignment
- 4.5 Quantization-aware / distillation (optional)

## 5. Inference Engine & Acceleration
- 5.1 Inference runtime
  - decoding loops, batching, streaming
- 5.2 KV cache & memory management
  - paged attention, cache policies
- 5.3 Parallelism for inference
  - tensor parallel, speculative decoding
- 5.4 Quantization & kernels
  - GPTQ/AWQ/FP8/INT8, fused ops
- 5.5 Benchmarking & perf regression

## 6. Serving & Deployment
- 6.1 Serving API
  - OpenAI-compatible, REST/gRPC, chat/completions
- 6.2 Deployment artifacts
  - Docker/Compose, Helm/K8s manifests, systemd
- 6.3 Autoscaling & routing
  - load balancer, canary, A/B, multi-model routing
- 6.4 AuthN/AuthZ & rate limiting
- 6.5 Multi-tenant isolation (optional)

## 7. RAG & Tooling
- 7.1 Retrieval pipelines
  - embed → index → retrieve → rerank
- 7.2 Chunking & document understanding
  - OCR/parsing, layout-aware chunking
- 7.3 Prompt / context construction
  - templates, citations, guardrails
- 7.4 Tool/function calling
  - tool schema, execution sandboxes

## 8. Agent Orchestration & Workflows
- 8.1 Agent runtimes
  - planner/executor loops, memory
- 8.2 Graph/workflow composition
  - DAGs, state machines, LangGraph-style
- 8.3 Multi-agent coordination (optional)
- 8.4 Plugins & integrations

## 9. Evaluation, Testing & Benchmarking
- 9.1 Offline eval
  - harness, metrics, datasets
- 9.2 Online eval
  - shadow traffic, human eval
- 9.3 Safety eval
  - jailbreak/red-teaming, policy tests
- 9.4 Unit/integration tests for infra

## 10. Observability & LLMOps
- 10.1 Tracing & logs
  - OpenTelemetry, structured logs
- 10.2 Cost/latency monitoring
  - tokens, GPU, cache hit rates
- 10.3 Experiment tracking
  - runs, artifacts, registry
- 10.4 Prompt/version governance

## 11. UI & Developer Experience (optional)
- 11.1 Visual flow builders
  - node/graph UI, prompt playground
- 11.2 Admin consoles
  - model registry UI, dataset UI
- 11.3 CLIs & SDKs

