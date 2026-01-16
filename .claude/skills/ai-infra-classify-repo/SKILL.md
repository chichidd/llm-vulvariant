---
name: ai-infra-classify-repo
description: Classify an AI-infrastructure repository into a coarse-to-fine module taxonomy with evidence, producing a machine-readable module map.
metadata:
  short-description: Repo module taxonomy classification (AI infra)
---

# ai-infra-classify-repo

## Purpose
Given a local repository path (typically under `data/repos/<repo>`), produce:
1. A **module map**: which AI-infra modules exist in the repo, at both coarse and fine granularity.
2. **Evidence**: concrete files, directories, configs, and dependency signals supporting each assigned module.
3. A **minimal, stable summary** suitable for research documentation (avoid repo-specific overfitting).

This skill is designed for AI infra repos spanning training, fine-tuning, inference/serving, app frameworks (RAG/agents), evaluation/safety, and operations.

## Inputs
- `REPO_PATH`: local path to the target repository.
- Optional: `OUTPUT_PATH` for the produced JSON (default: `<REPO_PATH>/ai_infra_module_map.json`).

## Outputs
Write a JSON file with this shape:

```json
{
  "repo": "<name>",
  "taxonomy_version": "ai_infra_taxonomy_v1",
  "modules": [
    {
      "label": "training",
      "confidence": 0.0,
      "evidence": ["..."]
    }
  ],
  "file_index": {
    "path/to/file": ["training", "inference_and_serving"]
  },
  "notes": ["assumptions/edge-cases"]
}
```

## Canonical taxonomy
Use the taxonomy in `references/ai_infra_taxonomy.py` as the canonical label space. Prefer *stable* labels that generalize across repos. If a finer label is uncertain, fall back to the nearest parent.

## Procedure
1. **Quick scan (structure + keywords).**
   - Run the lightweight scanner:
     - `python scripts/scan_repo.py --repo "$REPO_PATH" --out /tmp/scan.json`
   - Run the rule-based draft classifier:
     - `python scripts/classify_rules.py --scan /tmp/scan.json --out /tmp/draft.json`
   - Read `/tmp/draft.json` and treat it as a **hypothesis**, not the final answer.

2. **Confirm high-signal artifacts.**
   Use targeted reading (not full-repo ingestion):
   - `README`, `docs/`, `examples/`, `pyproject.toml`, `setup.*`, `requirements*`.
   - Entry points: `cli/`, `main.*`, `serve.*`, `api.*`, `trainer.*`, `scripts/`.
   - Infra configs: `Dockerfile`, `docker-compose*`, `k8s/`, `helm/`, `.github/workflows/`.

3. **Assign modules with evidence.**
   - For each module label you assign, include at least **2 independent evidence points**, e.g.:
     - A directory/function name pattern.
     - A dependency or config (e.g., `deepspeed`, `vllm`, `fastapi`, `kserve`, `langchain`).
   - If evidence is weak, keep confidence low and record a note.

4. **File-to-module mapping (coarse).**
   - Build `file_index` by mapping *representative* files (not necessarily every file):
     - Top-level entry points, key subpackages, major configs.

5. **Write final JSON.**
   - Ensure the output is deterministic, readable, and minimally sufficient.

## Quality gates
- Do not hallucinate modules: every module must cite concrete evidence from the repository.
- Prefer coarse labels over speculative fine labels.
- Avoid project-specific micro-taxonomies; stick to the canonical taxonomy.

## Examples
- "Classify the repo at `data/repos/vllm` and write output to `artifacts/vllm.json`."
- "Classify `data/repos/LLaMA-Factory` focusing on training and fine-tuning modules."
