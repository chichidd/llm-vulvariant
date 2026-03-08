---
name: llm-vulvariant-full-workflow
description: Execute the complete llm-vulvariant workflow from profile construction to scanning and exploitability/report generation. Use when given a vulnerability list (vuln.json-compatible) plus affected-version repositories and an optional explicit target repository list, and you need one reproducible run plan that outputs scan results and exploitable submission artifacts.
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

For an explicit allowlist instead:

```bash
cd "$APP_DIR"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
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

```bash
SCAN_LOG="$ROOT/output-batch-scan-$(date +%Y%m%d-%H%M%S).log"

cd "$APP_DIR"
cmd=(
  python -m cli.batch_scanner
  --vuln-json "$VULN_JSON"
  --repos-root "$TARGET_REPOS_ROOT"
  --profile-base-path "$PROFILE_BASE"
  --soft-profiles-dir "$TARGET_SOFT_PROFILES_DIR"
  --vuln-profiles-dir "$VULN_PROFILES_DIR"
  --scan-output-dir "$SCAN_OUTPUT_DIR"
  --similarity-threshold 0.7
  --fallback-top-n 3
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
  --repos-root "$TARGET_REPOS_ROOT" \
  --profile-base-path "$PROFILE_BASE" \
  --soft-profiles-dir "$TARGET_SOFT_PROFILES_DIR" \
  --vuln-profiles-dir "$VULN_PROFILES_DIR" \
  --scan-output-dir "$SCAN_OUTPUT_DIR" \
  --similarity-threshold 0.7 \
  --fallback-top-n 3 \
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
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir "$EXP_OUTPUT_DIR" \
  --submission-prefix exploitable_findings \
  --claude-runtime-root "$RUNTIME_ROOT" \
  --claude-runtime-mode run \
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
- `exploitable_findings.json`
- `exploitable_findings.csv`
- `submission_index.json`
- `exploitable_security_report.md`

## Notes

- Source vulnerability profiles should be built from `data/repos` unless `vuln.json` explicitly points elsewhere.
- For NVIDIA targets, keep source profiles at `profiles/soft`, but scan with `--repos-root "$ROOT/data/repos-nvidia"` and `--soft-profiles-dir "$ROOT/profiles/soft-nvidia"`.
- Deprecated aliases still work, but skills should use `--soft-profile-dir` and `--soft-profiles-dir`.
