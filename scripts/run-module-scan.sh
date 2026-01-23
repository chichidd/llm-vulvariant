#!/bin/bash

# Script to scan all repositories under ../data/repos/
# Usage: bash run-module-scan.sh

REPOS_DIR="../data/repos"
OUTPUT_DIR="../analysis-cc-s"
SCAN_SCRIPT=".claude/skills/ai-infra-module-modeler/scripts/scan_repo.py"

# Check if repos directory exists
if [ ! -d "$REPOS_DIR" ]; then
    echo "Error: Repository directory $REPOS_DIR not found"
    exit 1
fi

# Iterate through all directories in repos folder
for repo_path in "$REPOS_DIR"/*; do
    # Check if it's a directory
    if [ -d "$repo_path" ]; then
        repo_name=$(basename "$repo_path")
        output_path="$OUTPUT_DIR/$repo_name"
        
        echo "========================================"
        echo "Scanning repository: $repo_name"
        echo "Output directory: $output_path"
        echo "========================================"
        
        python "$SCAN_SCRIPT" \
            --repo "$repo_path" \
            --out "$output_path" \
            --max-files 200000 \
            --max-bytes 200000 \
            --group-depth 5 \
            --llm-provider lab \
            --max-workers 10 \
            --llm-model "DeepSeek-V3.2"
        
        if [ $? -eq 0 ]; then
            echo "✓ Successfully scanned $repo_name"
        else
            echo "✗ Failed to scan $repo_name"
        fi
        echo ""
    fi
done

echo "========================================"
echo "All repositories scanned!"
echo "Results saved to: $OUTPUT_DIR"
echo "========================================"