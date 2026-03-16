---
name: llm-vulvariant-scan-pipeline
description: Execute and validate the llm-vulvariant profile-build and batch-scanning pipeline from vulnerability lists and target repository lists. Use when building software/vulnerability profiles (especially after software profile rule changes), running `python -m cli.batch_scanner` with similarity controls (`--similarity-threshold`, `--fallback-top-n`, `--max-targets`), restricting scanning to an explicit target repo subset via a curated target root, and checking output/log consistency.
---

# LLM-VulVariant Scan Pipeline

## Overview

Use this workflow when you need repeatable scanning over known vulnerabilities with explicit profile construction and an optional curated target-root subset.

## Set Up Paths

```bash
ROOT="/mnt/raid/home/dongtian/vuln"
APP_DIR="$ROOT/llm-vulvariant"
VULN_JSON="$ROOT/data/vuln.json"
PROFILE_BASE="$ROOT/profiles"
SOURCE_REPOS_ROOT="$ROOT/data/repos"
SOURCE_SOFT_PROFILES_DIR="$PROFILE_BASE/soft"
VULN_PROFILES_DIR="$PROFILE_BASE/vuln"

# Pick one target set for scanning.
TARGET_REPOS_ROOT="$ROOT/data/repos"
TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft"
# TARGET_REPOS_ROOT="$ROOT/data/repos-nvidia"
# TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft-nvidia"

SCAN_OUTPUT_DIR="$ROOT/results/full-batch-scan"
LOG_FILE="$ROOT/output-batch-scan-$(date +%Y%m%d-%H%M%S).log"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"
```

Optional explicit target list file:

```bash
TARGET_REPO_LIST="$ROOT/data/target_repos.txt"
```

## Build Profiles

### Build software profiles for vuln source versions

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

### Build vulnerability profiles into `profiles/vuln`

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

### Build target software profiles for the scan target set

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

For an explicit repo allowlist, first materialize a dedicated target root containing only the repos you want to scan. `batch_scanner` always walks every repo under `TARGET_REPOS_ROOT`, so prebuilding a few profiles alone does not restrict the scan set.

```bash
cd "$APP_DIR"
TARGET_REPOS_ROOT="$ROOT/data/repos-allowlist"
TARGET_SOFT_PROFILES_DIR="$PROFILE_BASE/soft-allowlist"
mkdir -p "$TARGET_REPOS_ROOT" "$TARGET_SOFT_PROFILES_DIR"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  ln -sfn "$ROOT/data/repos/$repo" "$TARGET_REPOS_ROOT/$repo"
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

## Run Batch Scan

Full `vuln.json` scan:

```bash
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
  --max-iterations-cap 10
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}" > "$LOG_FILE" 2>&1
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
  --max-iterations-cap 10 \
  --llm-provider "$LLM_PROVIDER" \
  --limit 1
```

Useful options:
- `--skip-existing-scans`
- `--force-regenerate-profiles`
- `--max-targets`
- `--include-same-repo`

## Validate Output

```bash
ls -lt "$SCAN_OUTPUT_DIR"/batch-summary-*.json | head -n 1
rg -n "Similarity details|Selected [0-9]+ targets|fallback to top-" "$LOG_FILE"
find "$SCAN_OUTPUT_DIR" -name agentic_vuln_findings.json | wc -l
find "$SCAN_OUTPUT_DIR" -name target_similarity.json | wc -l
find "$SCAN_OUTPUT_DIR" -name scan_memory.json | wc -l
```

## Notes

- `profiles/soft` is the default source profile directory for `data/repos`.
- `profiles/soft-nvidia` is the matching target profile directory for `data/repos-nvidia`.
- `profiles/vuln` should be built from the same source repo root that `vuln.json` references.
- Batch scan commands must pass explicit source/target roots and software-profile dirs.
- To scan only an allowlist, `TARGET_REPOS_ROOT` itself must contain only the allowed repos.
