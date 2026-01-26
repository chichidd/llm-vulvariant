---
name: ai-infra-module-modeler
description: Classify an AI/LLM infrastructure repository into a hierarchical module taxonomy and generate a module map + skeleton using LLM semantic analysis of repo structure and key files.
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
- Per-module checklists and inclusion criteria: [references/checklists/](references/checklists/)

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

2. Obtain LLM-driven module candiates

2.1 If you find existing output by the scanner `scan_repos.py`, you can directly jump to step 3.

2.2 If not, **run the scanner** to produce LLM-driven module candidates:
   ```bash
   python .claude/skills/ai-infra-module-modeler/scripts/scan_repo.py \
     --repo <repo-path> \
     --out <path-to-save> \
     --max-files 20000 \
     --max-bytes 200000 \
     --group-depth <to-be-determined> \
     --llm-provider lab \
     --max-workers 10 \
     --llm-model "DeepSeek-V3.2"
   ```
   - Use `--require-llm` to fail fast if the LLM is unavailable or returns invalid JSON.
   - Adjust grouping with `--group-depth`, `--group-sample-files`, `--group-snippets`, `--snippet-bytes`, `--batch-size`. Make sure you can cover as many groups as possible. I want the module classification to be as assurate as possible. `--group-depth` should be determined by your overview of the repository to balance the execution time and accuracy. 
   - Wait until the script ends.

3. **Inspect the summary** in `analysis/<repo-name>/MODULES.md`.
4. **IMPORTANT: Validate modules** using the checklist files under `references/checklists/`. Review every output of the module assignment. 
- If you found any insistency betweeen assigned module and the file, read relevant files and correct them. 
- You need to do this check for several arround to make sure they are correct.

## Notes / guardrails
- Rely on LLM semantic classification, not keyword rules.
- Prefer evidence from `README*`, `pyproject.toml` / `requirements*`, `Dockerfile`, `helm/`, `k8s/`, `examples/`, and top-level packages.
- If the repo is monorepo-style, run the scanner on the specific subdir of interest.
- Keep reasoning reproducible: include paths/snippets in the evidence list rather than intuition-only assignments.
