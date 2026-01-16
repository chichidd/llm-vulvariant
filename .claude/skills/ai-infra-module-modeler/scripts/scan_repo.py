#!/usr/bin/env python3
"""Evidence-based module classification for AI infra repositories.

This scanner uses repo structure, config files, and lightweight keyword/dependency
heuristics to classify a repo into a hierarchical AI-infra module taxonomy.

Outputs (in --out directory):
- signals.json: raw hits and counts
- module_map.json: module -> score + evidence
- MODULES.md: summary report

Notes:
- This is heuristic. Treat the result as an initial label set to be validated
  against the checklists under references/checklists/.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple

from ai_infra_taxonomy import AI_INFRA_TAXONOMY, taxonomy_to_markdown


# Directories commonly considered non-source or vendor content.
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "__pycache__", ".mypy_cache",
    "node_modules", "dist", "build", "target", "out", "bazel-bin", "bazel-out",
    "bazel-testlogs", "bazel-workspace", ".idea", ".vscode", ".pytest_cache",
}

TEXT_EXTS = {
    ".py", ".pyi", ".md", ".rst", ".txt", ".toml", ".ini", ".cfg", ".json", ".yaml", ".yml",
    ".sh", ".bash", ".ps1", ".go", ".rs", ".java", ".kt", ".scala", ".c", ".cc", ".cpp",
    ".h", ".hpp", ".cu", ".cuh", ".cmake", ".gradle", ".dockerfile",
}

# A small set of "high-signal" files to read even if extension is unknown.
SPECIAL_FILENAMES = {
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "Makefile", "CMakeLists.txt",
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements.in",
    "Pipfile", "Pipfile.lock", "poetry.lock", "package.json", "pnpm-lock.yaml",
    "yarn.lock", "go.mod", "Cargo.toml", "Cargo.lock", "SECURITY.md", "README", "README.md",
}


def flatten_taxonomy(tax: dict) -> List[str]:
    """Return stable coarse module keys from taxonomy."""
    return list(tax.keys())


COARSE_MODULES = flatten_taxonomy(AI_INFRA_TAXONOMY)


@dataclass
class Evidence:
    score: int
    evidence: List[str]
    hits: Dict[str, int]


@dataclass
class Signals:
    repo: str
    files_scanned: int
    total_files: int
    excluded_dirs: List[str]
    module_hits: Dict[str, Dict[str, int]]
    module_evidence: Dict[str, List[str]]


def read_text_safely(path: Path, max_bytes: int = 200_000) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    # best-effort decode
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def should_scan_file(path: Path) -> bool:
    if path.name in SPECIAL_FILENAMES:
        return True
    ext = path.suffix.lower()
    return ext in TEXT_EXTS


def iter_files(repo: Path, exclude_dirs: set[str]) -> Tuple[List[Path], int]:
    files: List[Path] = []
    total = 0
    for root, dirs, filenames in os.walk(repo):
        root_p = Path(root)
        # prune excluded dirs
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fn in filenames:
            total += 1
            p = root_p / fn
            if should_scan_file(p):
                files.append(p)
    return files, total


def normalize(s: str) -> str:
    return s.lower()


def compile_rules() -> Dict[str, Dict[str, List[str]]]:
    """Rules are intentionally simple and transparent.

    Each module has:
    - keywords: code/doc keywords
    - path_hints: directory or filename fragments
    - dep_hints: dependency/library names that strongly indicate the module
    """
    return {
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


def extract_dependency_text(repo: Path) -> str:
    candidates = [
        repo / "pyproject.toml",
        repo / "requirements.txt",
        repo / "setup.py",
        repo / "setup.cfg",
        repo / "package.json",
        repo / "go.mod",
        repo / "Cargo.toml",
    ]
    parts = []
    for p in candidates:
        if p.exists() and p.is_file():
            parts.append(read_text_safely(p, max_bytes=200_000))
    return normalize("\n".join(parts))


def scan(repo: Path, exclude_dirs: set[str]) -> Tuple[Signals, Dict[str, Evidence]]:
    rules = compile_rules()
    files, total_files = iter_files(repo, exclude_dirs)
    dep_text = extract_dependency_text(repo)

    module_hits: Dict[str, Dict[str, int]] = {m: {"keyword": 0, "path": 0, "dep": 0} for m in COARSE_MODULES}
    module_evidence: Dict[str, List[str]] = {m: [] for m in COARSE_MODULES}

    # dependency hints
    for m, r in rules.items():
        for dep in r.get("dep_hints", []):
            if dep and dep in dep_text:
                module_hits[m]["dep"] += 3
                module_evidence[m].append(f"dep:{dep} (from config files)")

    # file/path + keyword scanning
    for p in files:
        rel = str(p.relative_to(repo))
        rel_l = normalize(rel)

        for m, r in rules.items():
            for hint in r.get("path_hints", []):
                if hint and hint in rel_l:
                    module_hits[m]["path"] += 1
                    if len(module_evidence[m]) < 40:
                        module_evidence[m].append(f"path:{rel}")

        text = read_text_safely(p, max_bytes=200_000)
        if not text:
            continue
        t = normalize(text)

        for m, r in rules.items():
            hit_count = 0
            for kw in r.get("keywords", []):
                if not kw:
                    continue
                # cheap contains, then boundary-ish regex for short tokens
                if kw in t:
                    hit_count += 1
            if hit_count:
                module_hits[m]["keyword"] += hit_count
                if len(module_evidence[m]) < 40:
                    module_evidence[m].append(f"kw:{hit_count} in {rel}")

    evidences: Dict[str, Evidence] = {}
    for m in COARSE_MODULES:
        h = module_hits[m]
        # Weighting: deps are strongest (already scaled), then paths, then keywords
        score = int(h["dep"] * 4 + h["path"] * 2 + h["keyword"])
        evidences[m] = Evidence(score=score, evidence=module_evidence[m], hits=h)

    signals = Signals(
        repo=str(repo),
        files_scanned=len(files),
        total_files=total_files,
        excluded_dirs=sorted(list(exclude_dirs)),
        module_hits=module_hits,
        module_evidence=module_evidence,
    )
    return signals, evidences


def choose_modules(evidences: Dict[str, Evidence]) -> List[str]:
    # dynamic threshold: keep modules with score >= max(8, 0.25 * top_score)
    scores = [e.score for e in evidences.values()]
    top = max(scores) if scores else 0
    threshold = max(8, int(0.25 * top))
    picked = [m for m, e in evidences.items() if e.score >= threshold]
    # Always keep at least the top-3 modules
    picked_sorted = sorted(picked, key=lambda m: evidences[m].score, reverse=True)
    if len(picked_sorted) < 3:
        picked_sorted = sorted(evidences.keys(), key=lambda m: evidences[m].score, reverse=True)[:3]
    return picked_sorted


def write_outputs(out_dir: Path, signals: Signals, evidences: Dict[str, Evidence]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "signals.json").write_text(json.dumps(asdict(signals), indent=2), encoding="utf-8")

    picked = choose_modules(evidences)

    module_map = {
        "repo": signals.repo,
        "taxonomy": "AI_INFRA_TAXONOMY",
        "selected_modules": picked,
        "modules": {m: asdict(evidences[m]) for m in picked},
    }
    (out_dir / "module_map.json").write_text(json.dumps(module_map, indent=2), encoding="utf-8")

    # Markdown summary
    lines: List[str] = []
    lines.append(f"# Module summary for `{Path(signals.repo).name}`")
    lines.append("")
    lines.append(f"Scanned files: {signals.files_scanned} (of total files: {signals.total_files})")
    lines.append("")
    lines.append("## Detected modules (coarse)")
    for m in picked:
        e = evidences[m]
        lines.append(f"- **{m}** (score={e.score}, hits={e.hits})")
    lines.append("")
    lines.append("## Evidence (top)")
    for m in picked:
        e = evidences[m]
        lines.append(f"### {m}")
        for ev in e.evidence[:20]:
            lines.append(f"- {ev}")
        lines.append("")

    lines.append("## Taxonomy reference")
    lines.append("(Full taxonomy tree included for convenience.)")
    lines.append("")
    lines.append(taxonomy_to_markdown())

    (out_dir / "MODULES.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="Path to the repository (or subdir) to scan")
    ap.add_argument("--out", required=True, help="Output directory for analysis artifacts")
    ap.add_argument("--exclude", nargs="*", default=[], help="Extra directory names to exclude")
    args = ap.parse_args()

    repo = Path(args.repo).expanduser().resolve()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit(f"repo path not found or not a directory: {repo}")

    out_dir = Path(args.out).expanduser().resolve()
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude)

    signals, evidences = scan(repo, exclude_dirs)
    write_outputs(out_dir, signals, evidences)
    print(f"Wrote: {out_dir / 'module_map.json'}")
    print(f"Wrote: {out_dir / 'MODULES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
