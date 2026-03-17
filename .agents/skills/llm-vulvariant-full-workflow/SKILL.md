---
name: llm-vulvariant-full-workflow
description: Execute the complete llm-vulvariant workflow from profile construction to scanning and exploitability/report generation. Use when given a vulnerability list (vuln.json-compatible) plus affected-version repositories and an optional explicit target repository subset materialized as a curated target root, and you need one reproducible run plan that outputs scan results and exploitable submission artifacts (`exploitable_findings_<run-id>[_strict].*`).
---

# LLM-VulVariant Full Workflow

## Overview

Use this when you need one reproducible command plan from profile construction through batch scan and exploitability report generation.

## Set Up Variables

```bash
ROOT="/mnt/raid/home/dongtian/vuln"
APP_DIR="$ROOT/llm-vulvariant"
VULN_JSON="$ROOT/data/vuln.json"
PROFILE_BASE="$ROOT/profiles"

SOURCE_REPOS_ROOT="$ROOT/data/repos"
SOURCE_SOFT_PROFILES_DIR="$PROFILE_BASE/soft"
VULN_PROFILES_DIR="$PROFILE_BASE/vuln"

TARGET_REPOS_ROOT="$ROOT/data/repos"
TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft"
# TARGET_REPOS_ROOT="$ROOT/data/repos-nvidia"
# TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft-nvidia"

SCAN_OUTPUT_DIR="$ROOT/results/full-batch-scan"
EXP_OUTPUT_DIR="$ROOT/results/full-batch-exploitability"
RUNTIME_ROOT="$ROOT/results/claude-runtime"
TARGET_REPO_LIST="$ROOT/data/target_repos.txt"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"
```

## Phase 0: Build Profiles

### 0.1 Source software profiles for vuln commits

```bash
cd "$APP_DIR"
cmd=(
  ./scripts/run_all_vuln_software_profile.sh
  --vuln-json "$VULN_JSON"
  --repo-base-path "$SOURCE_REPOS_ROOT"
  --profile-base-path "$PROFILE_BASE"
  --soft-profile-dirname soft
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}"
```

### 0.2 Vulnerability profiles

```bash
cd "$APP_DIR"
cmd=(
  ./scripts/run_all_vulnerability_profiles.sh
  --vuln-json "$VULN_JSON"
  --repo-base-path "$SOURCE_REPOS_ROOT"
  --soft-profile-dir "$SOURCE_SOFT_PROFILES_DIR"
  --output-dir "$VULN_PROFILES_DIR"
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}"
```

### 0.3 Target software profiles

For all repos under the chosen target root:

```bash
cd "$APP_DIR"
cmd=(
  ./scripts/run_all_software_profiles.sh
  --root "$TARGET_REPOS_ROOT"
  --output-dir "$TARGET_SOFT_PROFILES_DIR"
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}"
```

For an explicit allowlist, first materialize a dedicated target root containing only the repos you want to scan. `batch_scanner` walks every repo under `TARGET_REPOS_ROOT`, so prebuilding a few profiles alone does not restrict the scan set.

```bash
cd "$APP_DIR"
TARGET_REPO_SOURCE_ROOT="$TARGET_REPOS_ROOT"
ALLOWLIST_TAG="$(date +%Y%m%d-%H%M%S)"
TARGET_REPOS_ROOT="$ROOT/data/repos-allowlist-$ALLOWLIST_TAG"
TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft-allowlist-$ALLOWLIST_TAG"
mkdir -p "$TARGET_REPOS_ROOT" "$TARGET_SOFT_PROFILES_DIR"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  ln -sfn "$TARGET_REPO_SOURCE_ROOT/$repo" "$TARGET_REPOS_ROOT/$repo"
  cmd=(
    software-profile
    --repo-name "$repo"
    --repo-base-path "$TARGET_REPOS_ROOT"
    --output-dir "$TARGET_SOFT_PROFILES_DIR"
    --llm-provider "$LLM_PROVIDER"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  "${cmd[@]}"
done < "$TARGET_REPO_LIST"
```

## Phase 1: Batch Scan

Add `--max-targets N` when you need a hard upper bound on threshold-selected targets; the cap is enforced even when `--similarity-threshold` is used.
Use `--max-workers` for total worker budget and `--scan-workers` for concurrent target scans in `batch_scanner` (when unset, `--scan-workers` inherits `--max-workers`).

```bash
SCAN_LOG="$ROOT/output-batch-scan-$(date +%Y%m%d-%H%M%S).log"

cd "$APP_DIR"
cmd=(
  python -m cli.batch_scanner
  --vuln-json "$VULN_JSON"
  --source-repos-root "$SOURCE_REPOS_ROOT"
  --target-repos-root "$TARGET_REPOS_ROOT"
  --profile-base-path "$PROFILE_BASE"
  --source-soft-profiles-dir "$SOURCE_SOFT_PROFILES_DIR"
  --target-soft-profiles-dir "$TARGET_SOFT_PROFILES_DIR"
  --vuln-profiles-dir "$VULN_PROFILES_DIR"
  --scan-output-dir "$SCAN_OUTPUT_DIR"
  --similarity-threshold 0.7
  --fallback-top-n 3
  --max-targets 3
  --max-workers 8
  --scan-workers 4
  --max-iterations-cap 10
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}" > "$SCAN_LOG" 2>&1
```

Only the first vuln entry:

```bash
cd "$APP_DIR"
python -m cli.batch_scanner \
  --vuln-json "$VULN_JSON" \
  --source-repos-root "$SOURCE_REPOS_ROOT" \
  --target-repos-root "$TARGET_REPOS_ROOT" \
  --profile-base-path "$PROFILE_BASE" \
  --source-soft-profiles-dir "$SOURCE_SOFT_PROFILES_DIR" \
  --target-soft-profiles-dir "$TARGET_SOFT_PROFILES_DIR" \
  --vuln-profiles-dir "$VULN_PROFILES_DIR" \
  --scan-output-dir "$SCAN_OUTPUT_DIR" \
  --similarity-threshold 0.7 \
  --fallback-top-n 3 \
  --max-targets 3 \
  --max-workers 8 \
  --scan-workers 4 \
  --max-iterations-cap 10 \
  --llm-provider "$LLM_PROVIDER" \
  --limit 1
```

## Phase 2: Exploitability + Reports

```bash
RUN_ID="full-batch-$(date +%Y%m%d-%H%M%S)"
EXP_LOG="$ROOT/output-exploitability-$RUN_ID.log"

cd "$APP_DIR"
python -m cli.exploitability \
  --scan-results-dir "$SCAN_OUTPUT_DIR" \
  --soft-profile-dir "$TARGET_SOFT_PROFILES_DIR" \
  --repo-base-path "$TARGET_REPOS_ROOT" \
  --max-workers 4 \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir "$EXP_OUTPUT_DIR" \
  --submission-prefix exploitable_findings \
  --claude-runtime-root "$RUNTIME_ROOT" \
  --claude-runtime-mode folder \
  --run-id "$RUN_ID" \
  --timeout 1800 \
  > "$EXP_LOG" 2>&1
```

## Completion Checks

```bash
rg -n "SUMMARY|Submission artifacts|ERROR|EACCES|Connection error" "$SCAN_LOG" "$EXP_LOG"
ls -l "$EXP_OUTPUT_DIR"
```

Expected artifacts:
- `exploitable_findings_<run-id>_strict.json`
- `exploitable_findings_<run-id>_strict.csv`
- `exploitable_findings_<run-id>_strict_submission_index.json`
- `exploitable_findings_<run-id>_strict_exploitable_security_report.md`

## Notes

- Source vulnerability profiles should be built from `data/repos` unless `vuln.json` explicitly points elsewhere.
- For NVIDIA targets, keep source profiles at `profiles/soft`, and scan with `--target-repos-root "$ROOT/data/repos-nvidia"` plus `--target-soft-profiles-dir "$ROOT/profiles/soft-nvidia"`.
- Batch scan commands must pass explicit source/target roots and software-profile dirs.
- `--force-regenerate-profiles` now implies fresh scans even if `--skip-existing-scans` is also enabled, so regenerated profile inputs are not paired with stale findings.
- `--max-targets` still caps threshold-selected repos; `--fallback-top-n` only applies when no repo clears the threshold.
- Add `--scan-workers` to tune batch scan parallelism in `batch_scanner`; default inherits `--max-workers`.
- `cli.exploitability` 并行化目前主要覆盖 `folder` runtime（依赖 `--max-workers`），`run/shared` 保持串行策略。
- To scan only an allowlist, `TARGET_REPOS_ROOT` itself must contain only the allowed repos.
