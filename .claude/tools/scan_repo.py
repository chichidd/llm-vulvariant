from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path

DEFAULT_MAX_FILE_BYTES = 512 * 1024  # 512KB
DEFAULT_MAX_FILES = 2000

# Coarse keyword signals. The classifier consumes these counts as weak evidence.
KEYWORD_GROUPS = {
    'training': [
        'deepspeed', 'fsdp', 'zero', 'megatron', 'torch.distributed', 'accelerate',
        'trainer', 'training_step', 'gradient_accumulation', 'lr_scheduler',
        'dpo', 'ppo', 'rlhf', 'rlaif', 'reward_model'
    ],
    'inference_and_serving': [
        'vllm', 'tensorrt', 'triton', 'text-generation-inference',
        'fastapi', 'grpc', 'openai', 'chat.completions', 'stream',
        'kv cache', 'paged', 'speculative', 'serve'
    ],
    'app_and_orchestration': [
        'langchain', 'llama_index', 'rag', 'retriever', 'vectorstore', 'agent',
        'tool', 'function_call', 'workflow', 'pipeline'
    ],
    'data': [
        'datasets', 'parquet', 'jsonl', 'webdataset', 'tokenize', 'dedup',
        'chunk', 'embedding', 'milvus', 'qdrant', 'weaviate', 'chroma'
    ],
    'evaluation_and_safety': [
        'eval', 'benchmark', 'lm-eval', 'rouge', 'bleu', 'judge',
        'guardrail', 'safety', 'redteam', 'pii'
    ],
    'ops_and_governance': [
        'opentelemetry', 'tracing', 'metrics', 'prometheus', 'grafana',
        'mlflow', 'wandb', 'model registry', 'canary', 'auth', 'oauth'
    ],
}

IMPORTANT_FILES = [
    'pyproject.toml', 'setup.py', 'requirements.txt',
    'Dockerfile', 'docker-compose.yml', 'kustomization.yaml',
    'helm', 'chart', 'k8s', 'kubernetes',
    'Makefile', 'CMakeLists.txt',
    'README.md', 'LICENSE',
]


def iter_text_files(repo: Path, max_files: int, max_bytes: int):
    count = 0
    for p in repo.rglob('*'):
        if count >= max_files:
            return
        if not p.is_file():
            continue
        # skip large/binary-ish
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0 or size > max_bytes:
            continue
        # common text extensions; also allow config files without extension
        ext = p.suffix.lower()
        if ext in {'.py', '.js', '.ts', '.go', '.rs', '.cpp', '.c', '.h', '.hpp', '.java',
                   '.md', '.rst', '.txt', '.toml', '.yaml', '.yml', '.json'} or p.name in IMPORTANT_FILES:
            count += 1
            yield p


def scan_repo(repo_path: str, max_files: int = DEFAULT_MAX_FILES, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> dict:
    repo = Path(repo_path).resolve()
    if not repo.exists() or not repo.is_dir():
        raise SystemExit(f"Not a directory: {repo}")

    # high-level structure
    top_dirs = sorted([p.name for p in repo.iterdir() if p.is_dir()])
    top_files = sorted([p.name for p in repo.iterdir() if p.is_file()])

    # languages by extension
    ext_counter: Counter[str] = Counter()
    for p in repo.rglob('*'):
        if p.is_file():
            ext_counter[p.suffix.lower() or '<noext>'] += 1

    # keyword counts
    kw_counts: dict[str, Counter[str]] = {k: Counter() for k in KEYWORD_GROUPS}
    matched_files: dict[str, list[str]] = {k: [] for k in KEYWORD_GROUPS}

    for p in iter_text_files(repo, max_files=max_files, max_bytes=max_bytes):
        try:
            txt = p.read_text(errors='ignore')
        except OSError:
            continue
        low = txt.lower()
        for group, kws in KEYWORD_GROUPS.items():
            hit = False
            for kw in kws:
                c = low.count(kw)
                if c:
                    kw_counts[group][kw] += c
                    hit = True
            if hit:
                matched_files[group].append(str(p.relative_to(repo)))

    # detect infra configs
    infra_signals = {
        'docker': any(name.lower().startswith('dockerfile') for name in top_files) or any('docker' in d.lower() for d in top_dirs),
        'kubernetes': any('k8s' in d.lower() or 'kubernetes' in d.lower() for d in top_dirs) or any(f.endswith(('.yaml', '.yml')) and 'k8s' in f.lower() for f in top_files),
        'helm': any('helm' in d.lower() or 'chart' in d.lower() for d in top_dirs),
        'ci': any(d.lower() in {'.github', '.gitlab', '.circleci'} for d in top_dirs),
    }

    return {
        'repo_path': str(repo),
        'repo_name': repo.name,
        'top_dirs': top_dirs,
        'top_files': top_files,
        'file_extensions': dict(ext_counter.most_common(40)),
        'keyword_counts': {k: dict(v.most_common()) for k, v in kw_counts.items()},
        'matched_files': matched_files,
        'infra_signals': infra_signals,
        'scan_limits': {'max_files': max_files, 'max_bytes': max_bytes},
    }


def main():
    import argparse

    ap = argparse.ArgumentParser(description='Scan a repository to extract weak signals for AI infra module classification.')
    ap.add_argument('repo', help='Path to repo')
    ap.add_argument('--max-files', type=int, default=DEFAULT_MAX_FILES)
    ap.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_FILE_BYTES)
    ap.add_argument('--out', default='-', help='Output JSON path or - for stdout')
    args = ap.parse_args()

    result = scan_repo(args.repo, max_files=args.max_files, max_bytes=args.max_bytes)
    out = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out == '-':
        print(out)
    else:
        Path(args.out).write_text(out, encoding='utf-8')


if __name__ == '__main__':
    main()
