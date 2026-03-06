---
name: llm-vulvariant-scan-pipeline
description: Execute and validate the llm-vulvariant profile-build and batch-scanning pipeline from vulnerability lists and target repository lists. Use when building software/vulnerability profiles (especially after software profile rule changes), running `python -m cli.batch_scanner` with similarity controls (`--similarity-threshold`, `--fallback-top-n`, `--max-targets`), restricting scanning to an explicit target repo subset, and checking output/log consistency.
---

# LLM-VulVariant Scan Pipeline

## Overview

Use this workflow when you need repeatable scanning over known vulnerabilities with explicit profile construction and optional target repository allowlists.

## Set Up Paths

```bash
ROOT="/mnt/raid/home/dongtian/vuln"
APP_DIR="$ROOT/llm-vulvariant"
VULN_JSON="$ROOT/data/vuln.json"           # Replace with custom vuln list if needed
REPOS_ROOT="$ROOT/data/repos"
REPO_PROFILES_DIR="$APP_DIR/repo-profiles"
VULN_PROFILES_DIR="$APP_DIR/vuln-profiles"
SCAN_OUTPUT_DIR="$ROOT/results/full-batch-scan"
LOG_FILE="$ROOT/output-batch-scan-$(date +%Y%m%d-%H%M%S).log"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"                   # Optional
```

Optional explicit target list file (one repo name per line):

```bash
TARGET_REPO_LIST="$ROOT/data/target_repos.txt"
```

## Build Profiles (Required for Deterministic Runs)

### Build software profiles for vulnerable source versions

Use the repository script for the default `~/vuln/data/vuln.json` layout:

```bash
cd "$APP_DIR"
LLM_PROVIDER="$LLM_PROVIDER" LLM_NAME="$LLM_NAME" ./scripts/run_all_vuln_software_profile.sh
```

If you must use a custom `VULN_JSON`, run the explicit loop:

```bash
cd "$APP_DIR"
jq -r '.[] | "\(.repo_name)|\(.commit)"' "$VULN_JSON" | sort -u | \
while IFS='|' read -r repo commit; do
  cmd=(
    software-profile
    --repo-name "$repo"
    --repo-base-path "$REPOS_ROOT"
    --target-version "$commit"
    --llm-provider "$LLM_PROVIDER"
    --output-dir "$REPO_PROFILES_DIR"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  "${cmd[@]}"
done
```

### Build vulnerability profiles from vuln list

```bash
cd "$APP_DIR"
cmd=(
  python -m cli.vulnerability
  --vuln-json "$VULN_JSON"
  --repo-profile-dir "$REPO_PROFILES_DIR"
  --output-dir "$VULN_PROFILES_DIR"
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}"
```

### Build software profiles for explicit target repos (latest checked-out commit)

```bash
cd "$APP_DIR"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  cmd=(
    software-profile
    --repo-name "$repo"
    --repo-base-path "$REPOS_ROOT"
    --llm-provider "$LLM_PROVIDER"
    --output-dir "$REPO_PROFILES_DIR"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  "${cmd[@]}"
done < "$TARGET_REPO_LIST"
```

For all repos under `REPOS_ROOT`, you can use:

```bash
cd "$APP_DIR"
./scripts/run_all_software_profiles.sh \
  --root "$REPOS_ROOT" \
  --llm-provider "$LLM_PROVIDER" \
  --output-dir "$REPO_PROFILES_DIR"
```

Add `--llm-name <model>` to that command when you need a fixed model override.

## Optional: Build Target-Subset Repos Root

Use this when you are given an explicit target repository list and must scan only those repos.

```bash
RUN_TAG="$(date +%Y%m%d-%H%M%S)"
SELECTED_REPOS_ROOT="$ROOT/data/repos-selected-$RUN_TAG"
mkdir -p "$SELECTED_REPOS_ROOT"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  ln -s "$REPOS_ROOT/$repo" "$SELECTED_REPOS_ROOT/$repo"
done < "$TARGET_REPO_LIST"
```

## Run Full Batch Scan

```bash
cd "$APP_DIR"
cmd=(
  python -m cli.batch_scanner
  --vuln-json "$VULN_JSON"
  --repos-root "$REPOS_ROOT"
  --repo-profiles-dir "$REPO_PROFILES_DIR"
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

To scan only allowlisted targets, replace `--repos-root "$REPOS_ROOT"` with:

```bash
--repos-root "$SELECTED_REPOS_ROOT"
```

Key options:
- `--similarity-threshold`: similarity gate.
- `--fallback-top-n`: used when all similarities are below threshold.
- `--max-targets`: cap selected targets after threshold filtering.
- `--max-iterations-cap`: scan cap with critical-stop enabled by default.
- `--skip-existing-scans`: resume-friendly re-run.
- `--force-regenerate-profiles`: refresh profiles.
- `--include-same-repo`: include source repository as candidate.
- `--limit`: process only first N vuln entries.
- `--language`: force scan language (otherwise auto-detect per target repo).

## Run Detached

```bash
cd "$APP_DIR"
setsid bash -lc 'python -m cli.batch_scanner \
  --vuln-json "'"$VULN_JSON"'" \
  --repos-root "'"$REPOS_ROOT"'" \
  --repo-profiles-dir "'"$REPO_PROFILES_DIR"'" \
  --vuln-profiles-dir "'"$VULN_PROFILES_DIR"'" \
  --scan-output-dir "'"$SCAN_OUTPUT_DIR"'" \
  --similarity-threshold 0.7 \
  --fallback-top-n 3 \
  --max-iterations-cap 10 \
  --llm-provider "'"$LLM_PROVIDER"'" \
  > "'"$LOG_FILE"'" 2>&1' >/dev/null 2>&1 < /dev/null & echo $!
```

## Validate Output Consistency

Check batch summary:

```bash
ls -lt "$SCAN_OUTPUT_DIR"/batch-summary-*.json | head -n 1
```

Check fallback/selection behavior in logs:

```bash
rg -n "Similarity details|Selected [0-9]+ targets|fallback to top-" "$LOG_FILE"
```

Check expected scan artifacts:

```bash
find "$SCAN_OUTPUT_DIR" -mindepth 2 -maxdepth 2 -type d | sed -n '1,20p'
find "$SCAN_OUTPUT_DIR" -name agentic_vuln_findings.json | wc -l
find "$SCAN_OUTPUT_DIR" -name target_similarity.json | wc -l
find "$SCAN_OUTPUT_DIR" -name scan_memory.json | wc -l
```

## Notes

- `cli.batch_scanner` performs on-demand profile generation when profiles are missing.
- Running explicit profile-build steps first improves reproducibility and avoids profile-generation stalls during scanning.
- `software-profile` resolves default paths from `config/paths.yaml`; pass `--repo-base-path` explicitly when scanning from non-default repo roots.
- `software-profile` reuses an existing `software_profile.json` and saved checkpoints for the same repo/commit when available.
- Pass `--force-regenerate` to `software-profile` when you need a clean rebuild for the same repo/commit.
- Use `--force-regenerate-profiles` on `cli.batch_scanner` when the batch run should refresh software/vulnerability profiles before scanning.
