#!/bin/bash

# Script to generate software profiles for all vulnerabilities in vuln.json
# Usage: ./run_all_vuln_software_profile.sh
# Run sth like: software-profile --repo-name Megatron-LM --target-version a845aa7e12b3a117e24c2352b9e3e60bad2e3a17 --llm-provider deepseek --output-dir ./repo-profiles --force-full-analysis
# under llm-vulvariant: ./scripts/run_all_vuln_software_profile.sh
set -e  # Exit on error

VULN_JSON="$HOME/vuln/data/vuln.json"
OUTPUT_DIR="./repo-profiles"
LLM_PROVIDER="${LLM_PROVIDER:-deepseek}"
LLM_NAME="${LLM_NAME:-}"

echo "=========================================="
echo "Software Profile Batch Generator"
echo "=========================================="
echo "Reading vulnerability data from: $VULN_JSON"
echo "Output directory: $OUTPUT_DIR"
echo "LLM provider: $LLM_PROVIDER"
echo ""

# Check if vuln.json exists
if [ ! -f "$VULN_JSON" ]; then
    echo "Error: $VULN_JSON not found!"
    exit 1
fi

# Extract unique repo_name and commit combinations using jq
# Format: "repo_name|commit"
entries=$(jq -r '.[] | "\(.repo_name)|\(.commit)"' "$VULN_JSON" | sort -u)

# Count total entries
total=$(echo "$entries" | wc -l)
echo "Found $total unique repository-commit combinations"
echo ""

# Process each entry
current=0
failed=0
succeeded=0

while IFS='|' read -r repo_name commit; do
    current=$((current + 1))
    echo "=========================================="
    echo "[$current/$total] Processing: $repo_name @ ${commit:0:8}"
    echo "=========================================="
    
    # Run software-profile command
    cmd=(
        software-profile
        --repo-name "$repo_name"
        --target-version "$commit"
        --llm-provider "$LLM_PROVIDER"
        --output-dir "$OUTPUT_DIR"
        --force-full-analysis
    )
    if [ -n "$LLM_NAME" ]; then
        cmd+=(--llm-name "$LLM_NAME")
    fi

    if "${cmd[@]}"; then
        succeeded=$((succeeded + 1))
        echo "✅ Success: $repo_name @ ${commit:0:8}"
    else
        failed=$((failed + 1))
        echo "❌ Failed: $repo_name @ ${commit:0:8}"
        echo "   Continuing with next entry..."
    fi
    
    echo ""
done <<< "$entries"

# Summary
echo "=========================================="
echo "Batch Processing Complete"
echo "=========================================="
echo "Total processed: $total"
echo "Succeeded: $succeeded"
echo "Failed: $failed"
echo ""
echo "Results saved to: $OUTPUT_DIR"
