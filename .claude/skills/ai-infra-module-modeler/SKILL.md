---
name: ai-infra-module-modeler
description: Classify an AI/LLM infrastructure repository into a hierarchical module taxonomy and generate a module map + skeleton, using evidence from repo structure, configs, and key files.
---

# AI Infra Module Modeler

## When to use
Use this skill when you need to:
- **Classify** an AI infra (LLM/multimodal) repo into standardized module categories.
- **Generate** a module map (module → evidence files) suitable for documentation, auditing, or further refactoring.
- **Scaffold** a consistent module skeleton for a new repo, aligned to the taxonomy.

Typical inputs:
- A local path to a repo (e.g., `data/repos/<repo-name>`).
- Optional: a target output directory.

## Outputs
- `module_map.json`: **coarse** module labels with evidence (scores + paths + keyword/dep signals).
- `MODULES.md`: human-readable summary.
- (Optional) `module_skeleton/`: folders + READMEs aligned to detected modules (with fine-grained stubs if enabled).

## Taxonomy
- Read: [references/taxonomy.md](references/taxonomy.md)
- Formal paper-friendly abstraction: [references/formalization.md](references/formalization.md)
- Per-module checklists and inclusion criteria: [references/checklists/](references/checklists/)

## Procedure (recommended)
0. **Check Python environment**, make sure in the conda environment `dsocr`.
1. **Run the scanner** to produce evidence-driven module candidates:
   ```bash
   python .claude/skills/ai-infra-module-modeler/scripts/scan_repo.py \
     --repo data/repos/<repo-name> \
     --out analysis/<repo-name>
   ```
2. **Inspect the summary** in `analysis/<repo-name>/MODULES.md`.
3. **Validate borderline modules** using the checklist files under `references/checklists/`.
4. **(Optional) Scaffold** a module skeleton (non-destructive by default):
   ```bash
   python .claude/skills/ai-infra-module-modeler/scripts/build_module_skeleton.py \
     --module-map analysis/<repo-name>/module_map.json \
     --out analysis/<repo-name>/module_skeleton
   ```

## Batch scanning (optional)
If you keep many repos under a single folder (e.g., `data/repos/`), you can batch-scan:
```bash
python tools/batch_scan_repos.py --repos data/repos --out analysis/repos
```

## Notes / guardrails
- Prefer evidence from `README*`, `pyproject.toml` / `requirements*`, `Dockerfile`, `helm/`, `k8s/`, `examples/`, and top-level packages.
- If the repo is monorepo-style, run the scanner on the specific subdir of interest.
- Keep reasoning reproducible: include paths/snippets in the evidence list rather than intuition-only assignments.

