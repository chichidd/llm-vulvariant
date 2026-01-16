"""
Canonical AI infra taxonomy (aligned with the skill scanner).

This file is meant for human consumption / downstream tooling.
The scanner's authoritative taxonomy lives at:
  .codex/skills/ai-infra-module-modeler/scripts/ai_infra_taxonomy.py

We mirror the same coarse/fine keys here to avoid confusion.
"""

from __future__ import annotations
from typing import Dict, List

# Coarse -> fine (same keys as the skill scanner taxonomy)
AI_INFRA_TAXONOMY: Dict[str, Dict[str, dict]] = {
    "platform_systems": {
        "build_packaging": {},
        "runtime_hardware": {},
        "distributed_orchestration": {},
    },
    "data_knowledge": {
        "ingestion_connectors": {},
        "dataset_construction": {},
        "preprocess_tokenization": {},
        "storage_formats": {},
        "knowledge_stores": {},
    },
    "model_assets_loading": {
        "model_definition": {},
        "checkpoint_formats": {},
        "loading_configuration": {},
        "tokenizers_processors": {},
        "export_interchange": {},
    },
    "training_optimization": {
        "training_loop": {},
        "distributed_training": {},
        "optim_schedules": {},
        "checkpoint_ft": {},
        "experiment_configs": {},
    },
    "post_training_alignment": {
        "sft": {},
        "peft": {},
        "preference_learning": {},
        "rlhf_rlaif": {},
        "distillation_qaware": {},
    },
    "inference_acceleration": {
        "inference_runtime": {},
        "kv_cache_memory": {},
        "inference_parallelism": {},
        "quant_kernels": {},
        "perf_bench": {},
    },
    "serving_deployment": {
        "serving_api": {},
        "deployment_artifacts": {},
        "autoscaling_routing": {},
        "auth_ratelimit": {},
        "multi_tenant_isolation": {},
    },
    "rag_retrieval": {
        "doc_loaders_chunking": {},
        "embedding_indexing": {},
        "retrieval_rerank": {},
        "citation_attribution": {},
        "hybrid_search": {},
    },
    "agents_tooling": {
        "tool_function_calling": {},
        "planning_orchestration": {},
        "memory_state": {},
        "integrations_plugins": {},
    },
    "eval_benchmarking": {
        "quality_eval": {},
        "safety_eval": {},
        "perf_eval": {},
        "regression_tests": {},
    },
    "safety_security": {
        "guardrails_policy": {},
        "sandbox_permissioning": {},
        "supply_chain": {},
        "hardening_guidance": {},
    },
    "observability_llmops": {
        "experiment_tracking": {},
        "model_registry": {},
        "tracing_metrics_logs": {},
        "cicd_governance": {},
    },
    "ui_workflow": {
        "web_ui": {},
        "workflow_builder": {},
        "cli_dx": {},
        "templates_examples": {},
    },
}

# Optional: anchors for humans or future rule refinement (path -> hints)
AI_INFRA_ANCHORS: Dict[str, List[str]] = {
    "model_assets_loading.loading_configuration": [
        "from_pretrained", "safetensors", "config.json", "tokenizer.json", "gguf", "onnx", "tensorrt"
    ],
    "training_optimization.distributed_training": [
        "ddp", "fsdp", "deepspeed", "zero", "tensor parallel", "pipeline parallel", "megatron"
    ],
    "inference_acceleration.inference_runtime": [
        "continuous batching", "kv cache", "paged attention", "speculative decoding", "token/s"
    ],
    "serving_deployment.serving_api": [
        "openai compatible", "chat/completions", "fastapi", "uvicorn", "grpc"
    ],
    "rag_retrieval.retrieval_rerank": [
        "retriever", "bm25", "faiss", "milvus", "qdrant", "weaviate", "chromadb", "rerank"
    ],
    "agents_tooling.planning_orchestration": [
        "agent", "tool calling", "planner", "executor", "workflow", "graph"
    ],
}

def taxonomy_to_markdown(taxonomy: dict = None) -> str:
    taxonomy = taxonomy or AI_INFRA_TAXONOMY
    lines = ["# AI Infra Module Taxonomy", ""]
    def walk(node, depth=0):
        indent = "  " * depth
        if isinstance(node, dict):
            for k, v in node.items():
                lines.append(f"{indent}- {k}")
                walk(v, depth + 1)
    walk(taxonomy, 0)
    lines.append("")
    return "\n".join(lines)

# AI_INFRA_TAXONOMY = {
#     'foundation': {
#         'hardware_and_runtime': [
#             'accelerator_backends(cuda/rocm/tpu/metal/cpu)',
#             'kernel_optimizations(fused_kernels/flash_attention)',
#             'precision_and_numerics(mixed_precision/bfloat16/fp8)',
#             'quantization_runtime(int8/int4/gptq/awq)',
#             'model_formats(safetensors/gguf/onnx/tensorrt)'
#         ],
#         'distributed_and_scheduling': [
#             'distributed_launch_and_collectives(torch.distributed/nccl/mpi)',
#             'parallelism_strategies(data/pipeline/tensor/sequence)',
#             'memory_optimizations(zero/fsdp/activation_offload)',
#             'cluster_scheduling(slurm/kubernetes)',
#             'resource_management(autoscaling/placement)'
#         ],
#         'build_and_packaging': [
#             'dependency_and_env(poetry/uv/conda/docker)',
#             'native_extensions(cpp/cuda)',
#             'ci_cd_and_release'
#         ]
#     },
#     'model_assets': {
#         'loading_and_registry': [
#             'checkpoint_loading(hf_from_pretrained/custom)',
#             'config_management(yaml/json/hydra)',
#             'model_registry(local/remote)',
#             'tokenizers(text)',
#             'processors(vision/audio)'
#         ],
#         'conversion_and_optimization': [
#             'export(onnx/tensorrt/torchscript)',
#             'quantize(gptq/awq/bitsandbytes)',
#             'distill_and_merge(adapters/merging)',
#             'compat_layers(openai_api/hf_compat)'
#         ]
#     },
#     'data': {
#         'ingestion_and_connectors': [
#             'dataset_connectors(hf_datasets/files/dbs)',
#             'document_loaders(pdf/html/docx)',
#             'streaming_ingest',
#             'data_versioning(dvc/lakefs)'
#         ],
#         'processing_and_quality': [
#             'cleaning_and_normalization',
#             'dedup_and_filtering',
#             'chunking_and_parsing',
#             'labeling_and_annotation',
#             'synthetic_data_generation'
#         ],
#         'retrieval_and_index': [
#             'embeddings_generation',
#             'vector_store_adapters(milvus/weaviate/qdrant/chroma)',
#             'hybrid_search(bm25+vector)',
#             'reranking',
#             'index_build_and_refresh'
#         ]
#     },
#     'training': {
#         'pretraining': [
#             'trainer_loop',
#             'distributed_pretraining',
#             'checkpointing_and_resume',
#             'metrics_and_logging'
#         ],
#         'finetuning': [
#             'sft',
#             'peft(lora/qlora/adapters)',
#             'recipe_and_configs',
#             'multi_modal_finetune'
#         ],
#         'post_training': [
#             'reward_modeling',
#             'preference_optimization(dpo/grpo)',
#             'rlhf_or_rlaif(ppo)',
#             'alignment_data_pipelines'
#         ],
#         'efficiency': [
#             'gradient_checkpointing',
#             'activation_or_optimizer_offload',
#             'moe',
#             'compilation(torch_compile/xla)'
#         ]
#     },
#     'inference_and_serving': {
#         'inference_engines': [
#             'optimized_inference(vllm/tensorrt_llm/llama_cpp)',
#             'kv_cache_and_paged_attention',
#             'speculative_decoding',
#             'quantized_inference'
#         ],
#         'serving_frameworks': [
#             'http_grpc_servers(fastapi/grpc)',
#             'model_servers(tgi/triton)',
#             'kubernetes_inference(kserve/seldon)',
#             'batching_streaming_and_rate_limit'
#         ],
#         'deployment_targets': [
#             'cloud_and_cluster',
#             'edge_and_mobile',
#             'browser_and_wasm'
#         ]
#     },
#     'app_and_orchestration': {
#         'llm_app_frameworks': [
#             'chains_and_components(langchain/llamaindex)',
#             'prompt_templates',
#             'memory_and_state'
#         ],
#         'agents_and_tools': [
#             'tool_calling_and_function_calling',
#             'agent_runtimes(planners/executors)',
#             'tool_registry_and_permissions'
#         ],
#         'workflows': [
#             'pipelines_and_dags',
#             'event_driven_orchestration',
#             'distributed_task_execution(ray/celery)'
#         ]
#     },
#     'evaluation_and_safety': {
#         'evaluation': [
#             'benchmarks_and_harness(lm_eval)',
#             'unit_and_regression_tests',
#             'human_eval_and_annotation',
#             'automatic_metrics(bleu/rouge/llm_judges)'
#         ],
#         'safety_and_guardrails': [
#             'input_output_filtering',
#             'policy_enforcement',
#             'red_teaming_and_adversarial_tests',
#             'privacy_and_pii_controls'
#         ]
#     },
#     'ops_and_governance': {
#         'observability': [
#             'tracing_and_spans(opentelemetry)',
#             'logging_and_metrics',
#             'prompt_and_dataset_versioning',
#             'cost_and_latency_tracking'
#         ],
#         'lifecycle_management': [
#             'experiment_tracking',
#             'model_registry_and_artifacts',
#             'deployment_rollout_and_canary',
#             'access_control_and_secrets'
#         ]
#     }
# }
