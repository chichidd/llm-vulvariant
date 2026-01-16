---
name: software-profile-generator
description: Generate software profiles (software_profile.json) for repos in this project, including module analysis, basic info, and optional deep analysis. Use when asked to profile a repo or produce module-level summaries for AI infra repositories.
---

# Software Profile Generator

## Workflow
1. Identify the target repo name under `data/repos/<repo-name>` (or confirm it is placed there).
2. Run the software profiler CLI (wrapper script recommended for Claude Code/Codex CLI):
   ```bash
   python .claude/skills/software-profile-generator/scripts/run_profile.py \
     --repo-name <repo-name> \
     --output-dir <output-dir> \
     --enable-deep-analysis
   ```
   - If `software-profile` is installed in PATH, the wrapper uses it automatically.
   - Direct CLI (equivalent):
     ```bash
     software-profile \
       --repo-name <repo-name> \
       --output-dir <output-dir> \
       --enable-deep-analysis
     ```
   - Override repo base path with `--repo-base-path /path/to/repos`.
   - Use `--force-full-analysis` when you want to ignore cached checkpoints.
   - Use `--target-version <commit>` to pin a commit.
   - Use `--llm-provider` / `--llm-name` to override the LLM configuration.
3. Read the generated profile:
   - `repo-profiles/<repo>/<commit>/software_profile.json` (default)
4. Summarize modules with fields: `name`, `category`, `description`, `paths`, `key_functions`, `dependencies`.

## Module analysis only
If the user only needs module analysis:
```bash
python .claude/skills/ai-infra-module-modeler/scripts/scan_repo.py \
  --repo data/repos/<repo-name> \
  --out analysis/<repo-name> \
  --llm-provider deepseek \
  --llm-model ""
```
Use `analysis/<repo-name>/module_profile.json` for the module list.
