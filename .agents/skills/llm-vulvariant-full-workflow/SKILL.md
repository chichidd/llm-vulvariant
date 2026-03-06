---
name: llm-vulvariant-full-workflow
description: Execute the complete llm-vulvariant workflow from profile construction to scanning and exploitability/report generation. Use when given a vulnerability list (vuln.json-compatible) plus affected-version repositories and an optional explicit target repository list, and you need one reproducible run plan that outputs scan results and exploitable submission artifacts.
---

# LLM-VulVariant Full Workflow

## Overview

Follow this when you need a single start-to-finish run from inputs to final exploitable reports.

## Input Assumptions

- Vulnerability list: JSON compatible with `data/vuln.json` schema.
- Source repos: available under `data/repos` and checked out to relevant commits when required.
- Optional target list: plain text, one repo name per line.

```bash
ROOT="/mnt/raid/home/dongtian/vuln"
APP_DIR="$ROOT/llm-vulvariant"
VULN_JSON="$ROOT/data/vuln.json"                 # Replace with your provided vuln list
TARGET_REPO_LIST="$ROOT/data/target_repos.txt"   # Optional
REPOS_ROOT="$ROOT/data/repos"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"                         # Optional
```

## Phase 0: Build Profiles

### 0.1 Build software profiles for vulnerable source versions

```bash
cd "$APP_DIR"
LLM_PROVIDER="$LLM_PROVIDER" LLM_NAME="$LLM_NAME" ./scripts/run_all_vuln_software_profile.sh
```

If you need a custom vuln file path, use the explicit loop:

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
    --output-dir "$APP_DIR/repo-profiles"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  "${cmd[@]}"
done
```

### 0.2 Build vulnerability profiles

```bash
cd "$APP_DIR"
cmd=(
  python -m cli.vulnerability
  --vuln-json "$VULN_JSON"
  --repo-profile-dir "$APP_DIR/repo-profiles"
  --output-dir "$APP_DIR/vuln-profiles"
  --llm-provider "$LLM_PROVIDER"
)
if [[ -n "$LLM_NAME" ]]; then
  cmd+=(--llm-name "$LLM_NAME")
fi
"${cmd[@]}"
```

### 0.3 Build software profiles for explicit target repos (optional)

```bash
cd "$APP_DIR"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  cmd=(
    software-profile
    --repo-name "$repo"
    --repo-base-path "$REPOS_ROOT"
    --llm-provider "$LLM_PROVIDER"
    --output-dir "$APP_DIR/repo-profiles"
  )
  if [[ -n "$LLM_NAME" ]]; then
    cmd+=(--llm-name "$LLM_NAME")
  fi
  "${cmd[@]}"
done < "$TARGET_REPO_LIST"
```

For all repos under `data/repos`, use:

```bash
cd "$APP_DIR"
./scripts/run_all_software_profiles.sh \
  --root "$REPOS_ROOT" \
  --llm-provider "$LLM_PROVIDER" \
  --output-dir "$APP_DIR/repo-profiles"
```

## Phase 1: Build Target Subset (Optional)

Use only when you must scan a specific target list:

```bash
RUN_TAG="$(date +%Y%m%d-%H%M%S)"
SELECTED_REPOS_ROOT="$ROOT/data/repos-selected-$RUN_TAG"
mkdir -p "$SELECTED_REPOS_ROOT"
while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -n "$repo" ]] || continue
  ln -s "$ROOT/data/repos/$repo" "$SELECTED_REPOS_ROOT/$repo"
done < "$TARGET_REPO_LIST"
```

## Phase 2: Batch Scan

```bash
SCAN_LOG="$ROOT/output-batch-scan-$(date +%Y%m%d-%H%M%S).log"

cd "$APP_DIR"
cmd=(
  python -m cli.batch_scanner
  --vuln-json "$VULN_JSON"
  --repos-root "$ROOT/data/repos"
  --repo-profiles-dir "$APP_DIR/repo-profiles"
  --vuln-profiles-dir "$APP_DIR/vuln-profiles"
  --scan-output-dir "$ROOT/results/full-batch-scan"
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

If scanning allowlisted targets only, set:

```bash
--repos-root "$SELECTED_REPOS_ROOT"
```

Useful resume/selection options:
- `--skip-existing-scans`
- `--max-targets`
- `--include-same-repo`
- `--limit`
- `--language`

## Phase 3: Exploitability + Reports

```bash
RUN_ID="full-batch-$(date +%Y%m%d-%H%M%S)"
EXP_LOG="$ROOT/output-exploitability-$RUN_ID.log"

cd "$APP_DIR"
python -m cli.exploitability \
  --scan-results-dir "$ROOT/results/full-batch-scan" \
  --repo-profile-dir "$APP_DIR/repo-profiles" \
  --repo-base-path "$ROOT/data/repos" \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir "$ROOT/results/full-batch-exploitability" \
  --submission-prefix exploitable_findings \
  --claude-runtime-root "$ROOT/results/claude-runtime" \
  --claude-runtime-mode run \
  --run-id "$RUN_ID" \
  --timeout 1800 \
  > "$EXP_LOG" 2>&1
```

`--submission-output-dir` implies report packaging; keep `--generate-report` explicit for readability.

## Detached Mode

Use `setsid` for long runs:

```bash
setsid bash -lc 'cd /mnt/raid/home/dongtian/vuln/llm-vulvariant && <COMMAND> > <LOG> 2>&1' >/dev/null 2>&1 < /dev/null & echo $!
```

## Completion Checks

```bash
rg -n "SUMMARY|Submission artifacts|ERROR|EACCES|Connection error" "$SCAN_LOG" "$EXP_LOG"
ls -l "$ROOT/results/full-batch-exploitability"
python - <<'PY'
import json
from pathlib import Path
p = Path("/mnt/raid/home/dongtian/vuln/results/full-batch-exploitability/exploitable_findings.json")
if p.exists():
    d = json.loads(p.read_text())
    print("total_findings:", d.get("total_findings"))
else:
    print("missing:", p)
PY
```

Expected files:
- `exploitable_findings.json`
- `exploitable_findings.csv`
- `submission_index.json`
- `exploitable_security_report.md`

## Notes

- `software-profile` reuses an existing `software_profile.json` and saved checkpoints for the same repo/commit when available.
- Pass `--force-regenerate` to `software-profile` when you need a clean rebuild for the same repo/commit.
- Use `--force-regenerate-profiles` on `cli.batch_scanner` when the batch run should refresh software/vulnerability profiles before scanning.
