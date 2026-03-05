#!/usr/bin/env bash

set -euo pipefail

ROOT="${ROOT:-/mnt/raid/home/dongtian/vuln}"
APP_DIR="$ROOT/llm-vulvariant"
PROFILES_ROOT="${PROFILES_ROOT:-$ROOT/profiles}"
VULN_JSON="${VULN_JSON:-$ROOT/data/vuln.json}"
REPOS_NVIDIA="${REPOS_NVIDIA:-$ROOT/data/repos-nvidia}"
SOURCE_REPOS_ROOT="${SOURCE_REPOS_ROOT:-$ROOT/data/repos}"
REPO_PROFILES_NVIDIA="${REPO_PROFILES_NVIDIA:-$PROFILES_ROOT/soft-nvidia}"
SOURCE_REPO_PROFILES="${SOURCE_REPO_PROFILES:-$PROFILES_ROOT/soft}"
VULN_PROFILES_DIR="${VULN_PROFILES_DIR:-$PROFILES_ROOT/vuln}"
SCAN_OUTPUT_DIR="${SCAN_OUTPUT_DIR:-$ROOT/results/nvidia-batch-scan}"
EXP_OUTPUT_DIR="${EXP_OUTPUT_DIR:-$ROOT/results/nvidia-batch-exploitability}"
RUNTIME_ROOT="${RUNTIME_ROOT:-$ROOT/results/claude-runtime}"
MAX_ITERATIONS_CAP="${MAX_ITERATIONS_CAP:-20}"
SIMILARITY_THRESHOLD="${SIMILARITY_THRESHOLD:-0.7}"
FALLBACK_TOP_N="${FALLBACK_TOP_N:-3}"
CRITICAL_STOP_MODE="${CRITICAL_STOP_MODE:-min}"
SOFTWARE_PROFILE_TIMEOUT="${SOFTWARE_PROFILE_TIMEOUT:-1800}"
RUN_ID="${RUN_ID:-nvidia-full-$(date +%Y%m%d-%H%M%S)}"

LOG_DIR="$ROOT"
PROFILE_LOG="$LOG_DIR/output-nvidia-profile-$RUN_ID.log"
SCAN_LOG="$LOG_DIR/output-nvidia-scan-$RUN_ID.log"
EXP_LOG="$LOG_DIR/output-nvidia-exploitability-$RUN_ID.log"
STATUS_LOG="$LOG_DIR/output-nvidia-status-$RUN_ID.log"

mkdir -p "$REPO_PROFILES_NVIDIA" "$SCAN_OUTPUT_DIR" "$EXP_OUTPUT_DIR" "$RUNTIME_ROOT"

cleanup_codeql_temp_artifacts() {
  local repo_dir="$1"
  [[ -d "$repo_dir" ]] || return 0

  local cleaned=0
  if [[ -L "$repo_dir/_codeql_detected_source_root" || -e "$repo_dir/_codeql_detected_source_root" ]]; then
    rm -f "$repo_dir/_codeql_detected_source_root"
    cleaned=1
  fi
  if [[ -d "$repo_dir/_codeql_build_dir" ]]; then
    rm -rf "$repo_dir/_codeql_build_dir"
    cleaned=1
  fi
  if [[ "$cleaned" -eq 1 ]]; then
    echo "[$(date -Iseconds)] cleaned CodeQL temp artifacts: $repo_dir" | tee -a "$STATUS_LOG"
  fi
}

echo "[$(date -Iseconds)] RUN_ID=$RUN_ID" | tee -a "$STATUS_LOG"
echo "[$(date -Iseconds)] PROFILE_LOG=$PROFILE_LOG" | tee -a "$STATUS_LOG"
echo "[$(date -Iseconds)] SCAN_LOG=$SCAN_LOG" | tee -a "$STATUS_LOG"
echo "[$(date -Iseconds)] EXP_LOG=$EXP_LOG" | tee -a "$STATUS_LOG"

echo "[$(date -Iseconds)] Stage 1/5: verify existing vuln profiles" | tee -a "$STATUS_LOG"
python - <<'PY' "$VULN_JSON" "$VULN_PROFILES_DIR" | tee -a "$STATUS_LOG"
import json
import sys
from pathlib import Path

vuln_json = Path(sys.argv[1])
vuln_profiles = Path(sys.argv[2])
entries = json.loads(vuln_json.read_text(encoding="utf-8"))

missing = []
for i, e in enumerate(entries):
    repo = str(e.get("repo_name", "")).strip()
    cve = str(e.get("cve_id", "")).strip() or f"vuln-{i}"
    p = vuln_profiles / repo / cve / "vulnerability_profile.json"
    if not p.exists():
        missing.append((i, repo, cve, str(p)))

print(f"vuln_entries={len(entries)}")
print(f"vuln_profiles_missing={len(missing)}")
for i, repo, cve, p in missing:
    print(f"  missing [{i}] {repo} {cve} -> {p}")
PY

echo "[$(date -Iseconds)] Stage 2/5: link source software profiles for vuln entries into soft-nvidia" | tee -a "$STATUS_LOG"
python - <<'PY' "$VULN_JSON" "$SOURCE_REPO_PROFILES" "$REPO_PROFILES_NVIDIA" | tee -a "$STATUS_LOG"
import json
import shutil
import sys
from pathlib import Path

vuln_json = Path(sys.argv[1])
src_root = Path(sys.argv[2])
dst_root = Path(sys.argv[3])
entries = json.loads(vuln_json.read_text(encoding="utf-8"))
need = sorted(set((e["repo_name"], e["commit"]) for e in entries))

linked = 0
copied = 0
skipped = 0
missing_src = 0

for repo, commit in need:
    src_dir = src_root / repo / commit
    dst_dir = dst_root / repo / commit
    dst_dir.parent.mkdir(parents=True, exist_ok=True)
    if dst_dir.exists() or dst_dir.is_symlink():
        skipped += 1
        continue
    if not src_dir.exists():
        missing_src += 1
        continue
    try:
        dst_dir.symlink_to(src_dir)
        linked += 1
    except Exception:
        shutil.copytree(src_dir, dst_dir)
        copied += 1

print(f"source_profiles_needed={len(need)}")
print(f"source_profiles_linked={linked}")
print(f"source_profiles_copied={copied}")
print(f"source_profiles_skipped={skipped}")
print(f"source_profiles_missing_in_source_dir={missing_src}")
PY

echo "[$(date -Iseconds)] Stage 3/5: build missing software profiles for repos-nvidia (timeout=${SOFTWARE_PROFILE_TIMEOUT}s each)" | tee -a "$STATUS_LOG"
cd "$APP_DIR"
total=0
ok=0
skip=0
fail=0
for d in "$REPOS_NVIDIA"/*; do
  [[ -d "$d" ]] || continue
  total=$((total+1))
done
idx=0
for d in "$REPOS_NVIDIA"/*; do
  [[ -d "$d" ]] || continue
  idx=$((idx+1))
  repo="$(basename "$d")"
  commit="$(git -C "$d" rev-parse HEAD)"
  cleanup_codeql_temp_artifacts "$d"
  profile="$REPO_PROFILES_NVIDIA/$repo/$commit/software_profile.json"

  if [[ -f "$profile" ]]; then
    skip=$((skip+1))
    echo "[$(date -Iseconds)] [profile $idx/$total] skip $repo@$commit" | tee -a "$STATUS_LOG"
    continue
  fi

  echo "[$(date -Iseconds)] [profile $idx/$total] build $repo@$commit" | tee -a "$STATUS_LOG"
  if timeout "$SOFTWARE_PROFILE_TIMEOUT" python -m cli.software \
      --repo-name "$repo" \
      --repo-base-path "$REPOS_NVIDIA" \
      --target-version "$commit" \
      --output-dir "$REPO_PROFILES_NVIDIA" \
      --llm-provider deepseek \
      >> "$PROFILE_LOG" 2>&1; then
    ok=$((ok+1))
    echo "[$(date -Iseconds)] [profile $idx/$total] ok $repo@$commit" | tee -a "$STATUS_LOG"
  else
    fail=$((fail+1))
    echo "[$(date -Iseconds)] [profile $idx/$total] fail_or_timeout $repo@$commit" | tee -a "$STATUS_LOG"
  fi
done
echo "[$(date -Iseconds)] Stage 3 summary: total=$total ok=$ok skip=$skip fail=$fail" | tee -a "$STATUS_LOG"

echo "[$(date -Iseconds)] Stage 4/5: run batch scanner" | tee -a "$STATUS_LOG"
python -m cli.batch_scanner \
  --vuln-json "$VULN_JSON" \
  --repos-root "$REPOS_NVIDIA" \
  --soft-profiles-dir "$REPO_PROFILES_NVIDIA" \
  --vuln-profiles-dir "$VULN_PROFILES_DIR" \
  --scan-output-dir "$SCAN_OUTPUT_DIR" \
  --similarity-threshold "$SIMILARITY_THRESHOLD" \
  --fallback-top-n "$FALLBACK_TOP_N" \
  --max-iterations-cap "$MAX_ITERATIONS_CAP" \
  --critical-stop-mode "$CRITICAL_STOP_MODE" \
  --llm-provider deepseek \
  >> "$SCAN_LOG" 2>&1
echo "[$(date -Iseconds)] Stage 4 completed" | tee -a "$STATUS_LOG"

echo "[$(date -Iseconds)] Stage 5/5: run exploitability and generate reports" | tee -a "$STATUS_LOG"
python -m cli.exploitability \
  --scan-results-dir "$SCAN_OUTPUT_DIR" \
  --soft-profile-dir "$REPO_PROFILES_NVIDIA" \
  --repo-base-path "$REPOS_NVIDIA" \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir "$EXP_OUTPUT_DIR" \
  --submission-prefix exploitable_findings \
  --claude-runtime-root "$RUNTIME_ROOT" \
  --claude-runtime-mode run \
  --run-id "$RUN_ID" \
  --timeout 1800 \
  >> "$EXP_LOG" 2>&1
echo "[$(date -Iseconds)] Stage 5 completed" | tee -a "$STATUS_LOG"

echo "[$(date -Iseconds)] Pipeline done: RUN_ID=$RUN_ID" | tee -a "$STATUS_LOG"
