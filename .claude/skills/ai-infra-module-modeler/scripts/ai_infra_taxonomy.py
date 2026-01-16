"""AI Infra taxonomy and rendering helpers.

This file is intentionally dependency-free so it can be reused by other scripts.
"""

from __future__ import annotations

from typing import Any, Dict, List


# Coarse -> fine taxonomy. Keep keys stable for downstream automation.
AI_INFRA_TAXONOMY: Dict[str, Any] = {
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


def _render_node(key: str, node: Any, depth: int, lines: List[str]) -> None:
    indent = "  " * depth
    lines.append(f"{indent}- {key}")
    if isinstance(node, dict):
        for child_k, child_v in node.items():
            _render_node(child_k, child_v, depth + 1, lines)


def taxonomy_to_markdown(taxonomy: Dict[str, Any] | None = None) -> str:
    """Render the taxonomy dictionary into a markdown bullet tree."""
    taxonomy = taxonomy or AI_INFRA_TAXONOMY
    lines: List[str] = ["# AI Infra Module Taxonomy", ""]
    for k, v in taxonomy.items():
        _render_node(k, v, 0, lines)
    lines.append("")
    return "\n".join(lines)
