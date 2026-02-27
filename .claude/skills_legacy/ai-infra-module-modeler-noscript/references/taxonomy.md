# AI Infra Module Taxonomy (coarse → fine)

This taxonomy is designed for **LLM / multimodal AI infrastructure repositories**: training, post-training, inference, serving, RAG, agentic applications, and supporting systems.

## 0. Platform & Systems (optional but common) (`platform_systems`)
- 0.1 Build & packaging (`build_packaging`)
  - Python packaging (pyproject/setup), wheels, versioning
  - Multi-language builds (Rust/Go/C++), bindings
- 0.2 Runtime & hardware abstraction (`runtime_hardware`)
  - CUDA/ROCm/Metal/oneAPI backends, kernels, Triton
  - Device discovery, mixed-precision, quantization backends
- 0.3 Distributed compute & orchestration (`distributed_orchestration`)
  - Launcher, cluster runtime, scheduling integration
  - Multi-node communication (NCCL, Gloo), topology awareness

## 1. Data & Knowledge (`data_knowledge`)
- 1.1 Data ingestion & connectors (`ingestion_connectors`)
  - Filesystems/object stores, web sources, databases, APIs
- 1.2 Dataset construction (`dataset_construction`)
  - Filtering, dedup, sampling, mixing, sharding
- 1.3 Preprocessing & tokenization (`preprocess_tokenization`)
  - Tokenizers, feature extraction (audio/vision), packing
- 1.4 Data formats & storage (`storage_formats`)
  - Arrow/Parquet/WebDataset, streaming IO
- 1.5 Knowledge stores (for RAG) (`knowledge_stores`)
  - Vector indexes, hybrid search, document stores

## 2. Model Assets & Loading (`model_assets_loading`)
- 2.1 Model definition & architecture (`model_definition`)
  - Transformer backbones, diffusion/ASR models, multimodal
- 2.2 Checkpoint & weight formats (`checkpoint_formats`)
  - safetensors, gguf/ggml, sharded ckpts
- 2.3 Model loading & configuration (`loading_configuration`)
  - HF `from_pretrained`, config/model cards, adapters
- 2.4 Tokenizers & processors (`tokenizers_processors`)
  - text tokenizer, image/audio processors
- 2.5 Export & interchange (`export_interchange`)
  - ONNX, TensorRT, TorchScript, GGUF conversion

## 3. Training & Optimization (`training_optimization`)
- 3.1 Training loop / trainer (`training_loop`)
  - epoch/step loop, gradient accumulation, logging
- 3.2 Distributed training (`distributed_training`)
  - DDP/FSDP/ZeRO, tensor/pipeline parallel, MoE
- 3.3 Optimization & schedules (`optim_schedules`)
  - optimizers, LR schedules, clipping, EMA
- 3.4 Checkpointing & fault tolerance (`checkpoint_ft`)
  - save/restore, reshard, resume
- 3.5 Experiment configuration (`experiment_configs`)
  - YAML/JSON configs, Hydra/Argparse, recipes

## 4. Post-training & Alignment (`post_training_alignment`)
- 4.1 Supervised fine-tuning (SFT) (`sft`)
- 4.2 Parameter-efficient tuning (LoRA/QLoRA/Adapters) (`peft`)
- 4.3 Preference learning (`preference_learning`)
  - DPO/GRPO/KTO/ORPO, reward modeling
- 4.4 RLHF / RLAIF pipelines (`rlhf_rlaif`)
  - rollout, reward, PPO-style alignment
- 4.5 Quantization-aware / distillation (optional) (`distillation_qaware`)

## 5. Inference Engine & Acceleration (`inference_acceleration`)
- 5.1 Inference runtime (`inference_runtime`)
  - decoding loops, batching, streaming
- 5.2 KV cache & memory management (`kv_cache_memory`)
  - paged attention, cache policies
- 5.3 Parallelism for inference (`inference_parallelism`)
  - tensor parallel, speculative decoding
- 5.4 Quantization & kernels (`quant_kernels`)
  - GPTQ/AWQ/FP8/INT8, fused ops
- 5.5 Benchmarking & perf regression (`perf_bench`)

## 6. Serving & Deployment (`serving_deployment`)
- 6.1 Serving API (`serving_api`)
  - OpenAI-compatible, REST/gRPC, chat/completions
- 6.2 Deployment artifacts (`deployment_artifacts`)
  - Docker/Compose, Helm/K8s manifests, systemd
- 6.3 Autoscaling & routing (`autoscaling_routing`)
  - load balancer, canary, A/B, multi-model routing
- 6.4 AuthN/AuthZ & rate limiting (`auth_ratelimit`)
- 6.5 Multi-tenant isolation (optional) (`multi_tenant_isolation`)

## 7. RAG & Tooling (`rag_retrieval`)
- 7.1 Retrieval pipelines (`retrieval_rerank`)
  - embed → index → retrieve → rerank
- 7.2 Chunking & document understanding (`doc_loaders_chunking`)
  - OCR/parsing, layout-aware chunking
- 7.3 Prompt / context construction (`citation_attribution`)
  - templates, citations, guardrails
- 7.4 Tool/function calling (`tool_function_calling`)
  - tool schema, execution sandboxes

## 8. Agent Orchestration & Workflows (`agents_tooling`)
- 8.1 Agent runtimes (`planning_orchestration`)
  - planner/executor loops, memory
- 8.2 Graph/workflow composition (`planning_orchestration`)
  - DAGs, state machines, LangGraph-style
- 8.3 Multi-agent coordination (optional) (`memory_state`)
- 8.4 Plugins & integrations (`integrations_plugins`)

## 9. Evaluation, Testing & Benchmarking (`eval_benchmarking`)
- 9.1 Offline eval (`quality_eval`)
  - harness, metrics, datasets
- 9.2 Online eval (`quality_eval`)
  - shadow traffic, human eval
- 9.3 Safety eval (`safety_eval`)
  - jailbreak/red-teaming, policy tests
- 9.4 Unit/integration tests for infra (`regression_tests`)

## 10. Observability & LLMOps (`observability_llmops`)
- 10.1 Tracing & logs (`tracing_metrics_logs`)
  - OpenTelemetry, structured logs
- 10.2 Cost/latency monitoring (`tracing_metrics_logs`)
  - tokens, GPU, cache hit rates
- 10.3 Experiment tracking (`experiment_tracking`)
  - runs, artifacts, registry
- 10.4 Prompt/version governance (`cicd_governance`)

## 11. UI & Developer Experience (optional) (`ui_workflow`)
- 11.1 Web UI (`web_ui`)
- 11.2 Visual flow builders (`workflow_builder`)
  - node/graph UI, prompt playground
- 11.3 Admin consoles (`web_ui`)
  - model registry UI, dataset UI
- 11.4 CLIs & SDKs (`cli_dx`)

