#!/usr/bin/env bash
# Test script for CodeQL call graph queries.
# Compiles all call_graph.ql queries, then runs them against available databases.
set -euo pipefail

QUERIES_DIR="$(cd "$(dirname "$0")/../.codeql-queries" && pwd)"
DB_DIR="${HOME}/vuln/codeql_dbs"
TMP_DIR="/tmp/codeql_cg_test"
mkdir -p "$TMP_DIR"

# ---- Step 1: Compile all queries ----
echo "=== Step 1: Compile all call_graph.ql queries ==="
COMPILE_OK=0
COMPILE_FAIL=0
for lang_dir in "$QUERIES_DIR"/*/; do
    lang=$(basename "$lang_dir")
    ql_file="$lang_dir/call_graph.ql"
    if [[ ! -f "$ql_file" ]]; then
        echo "  SKIP  $lang (no call_graph.ql)"
        continue
    fi
    echo -n "  Compiling $lang ... "
    if codeql query compile "$ql_file" >/dev/null 2>"$TMP_DIR/compile_${lang}.err"; then
        echo "OK"
        COMPILE_OK=$((COMPILE_OK + 1))
    else
        echo "FAILED"
        cat "$TMP_DIR/compile_${lang}.err"
        COMPILE_FAIL=$((COMPILE_FAIL + 1))
    fi
done
echo "Compile results: $COMPILE_OK OK, $COMPILE_FAIL FAILED"
echo ""

if [[ $COMPILE_FAIL -gt 0 ]]; then
    echo "Fix compilation errors before running queries."
    exit 1
fi

# ---- Step 2: Run queries against available databases ----
echo "=== Step 2: Run queries against test databases ==="

# Map: language -> test database
declare -A TEST_DBS=(
    [python]="LLaMA-Factory-ca75f1ed-python"
    [cpp]="TensorRT-LLM-e8ad899f-cpp"
    [go]="KAI-Scheduler-e377b418-go"
    [javascript]="personaplex-052206ac-javascript"
)

RUN_OK=0
RUN_FAIL=0
for lang in "${!TEST_DBS[@]}"; do
    db_name="${TEST_DBS[$lang]}"
    db_path="$DB_DIR/$db_name"
    ql_file="$QUERIES_DIR/$lang/call_graph.ql"

    if [[ ! -d "$db_path" ]]; then
        echo "  SKIP  $lang (database $db_name not found)"
        continue
    fi
    if [[ ! -f "$ql_file" ]]; then
        echo "  SKIP  $lang (no call_graph.ql)"
        continue
    fi

    bqrs_file="$TMP_DIR/${lang}_cg.bqrs"
    csv_file="$TMP_DIR/${lang}_cg.csv"

    echo -n "  Running $lang on $db_name ... "
    if codeql query run "$ql_file" \
        --database="$db_path" \
        --output="$bqrs_file" \
        >/dev/null 2>"$TMP_DIR/run_${lang}.err"; then

        # Decode BQRS to CSV
        codeql bqrs decode --format=csv "$bqrs_file" --output="$csv_file" 2>/dev/null
        row_count=$(wc -l < "$csv_file")
        row_count=$((row_count - 1)) # subtract header
        echo "OK ($row_count edges)"

        # Show sample rows
        echo "    Sample results:"
        head -6 "$csv_file" | tail -5 | while IFS= read -r line; do
            echo "      $line"
        done
        RUN_OK=$((RUN_OK + 1))
    else
        echo "FAILED"
        tail -5 "$TMP_DIR/run_${lang}.err"
        RUN_FAIL=$((RUN_FAIL + 1))
    fi
    echo ""
done

echo "=== Summary ==="
echo "Compile: $COMPILE_OK OK, $COMPILE_FAIL FAILED"
echo "Run:     $RUN_OK OK, $RUN_FAIL FAILED"

if [[ $COMPILE_FAIL -eq 0 && $RUN_FAIL -eq 0 ]]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
