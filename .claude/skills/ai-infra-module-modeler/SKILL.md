---
name: ai-infra-module-modeler
description: Classify an AI/LLM infrastructure repository into a hierarchical module taxonomy and generate `module_map.json`, `file_index.json`, and `module_profile.json` using LLM semantic analysis. Use when software profiling needs stable module boundaries for AI infra repositories.
---

# AI Infra Module Modeler

## When to use
Use this skill when you need to **Classify** an AI infra (LLM/multimodal) repo into standardized module categories.

Typical inputs:
- A local path to a repo (e.g., `data/repos/<repo-name>`).
- Optional: a target output directory.

## Outputs
- `module_map.json`: **coarse** module labels with evidence (scores + paths + counts).
- `file_index.json`: file → module assignment (coarse.fine labels).
- `module_profile.json`: module list in software-profile schema (name/category/description/paths).
- `MODULES.md`: human-readable summary.

## Taxonomy
- Read: [references/taxonomy.md](references/taxonomy.md) for the definition and notation
- Use per-module validation checklists under [references/checklists/](references/checklists/)

## Procedure (recommended)
0. **Check Python environment**, make sure in the conda environment `dsocr`.
1. **Overview the repository**, make sure you have an global understanding of the structure of the project, by print all the code files under the repository.

**Include files (code only):**
- Code extensions: `.py`, `.pyi`, `.go`, `.rs`, `.java`, `.kt`, `.scala`, `.c`, `.cc`, `.cpp`, `.h`, `.hpp`, `.cu`, `.cuh`, `.sh`, `.bash`, `.ps1`

**Exclude directories:**
- environment folder, like `.git`, `.hg`, `.svn`, `.tox`, `.venv`, `venv`, `__pycache__`, `.mypy_cache`, etc.
- `node_modules`, `dist`, `build`, `target`, `out`, etc.
- `bazel-bin`, `bazel-out`, `bazel-testlogs`, `bazel-workspace`, etc.
- setting folder, `.idea`, `.vscode`, `.pytest_cache`, `.github`, etc.
- testing-related, like `test`
- doc or manual-related, like `doc`
- any other folder that you decide not related to the main code of the repository

2. Obtain LLM-driven module candidates

2.1 If `module_map.json` / `file_index.json` / `module_profile.json` already exist in your target output directory, you can directly jump to step 3.

2.2 If not, **run the scanner** to produce LLM-driven module candidates:
   ```bash
   python .claude/skills/ai-infra-module-modeler/scripts/scan_repo.py \
     --repo <repo-path> \
     --out <path-to-save> \
     --max-files 20000 \
     --max-bytes 200000 \
     --group-depth <to-be-determined> \
     --llm-provider deepseek \
     --max-workers 10 \
     --llm-model "deepseek-chat"
   ```
   - Use `--require-llm` to fail fast if the LLM is unavailable or returns invalid JSON.
   - Adjust grouping with `--group-depth`, `--group-sample-files`, `--group-snippets`, `--snippet-bytes`, `--batch-size`. Choose `--group-depth` based on repository structure to balance runtime and classification accuracy.
   - Wait until the script ends.

3. **Inspect the summary** in `<out>/MODULES.md`.
4. **Validate module assignment quality** by reviewing `module_map.json`, `file_index.json`, and `module_profile.json` against real code files and checklist criteria in `references/checklists/`.
- If you find inconsistency between assignment and code behavior, read the relevant files and correct the output.
- Run at least one verification pass after corrections to ensure consistency.

## Notes / guardrails
- Rely on LLM semantic classification, not keyword rules.
- Prefer evidence from `README*`, `pyproject.toml` / `requirements*`, `Dockerfile`, `helm/`, `k8s/`, `examples/`, and top-level packages.
- If the repo is monorepo-style, run the scanner on the specific subdir of interest.
- Keep reasoning reproducible: include paths/snippets in the evidence list rather than intuition-only assignments.
