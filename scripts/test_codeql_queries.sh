#!/bin/bash

# CodeQL 查询测试脚本
# 在指定的数据库上运行所有简化查询

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认参数
DATABASE="${1:-${HOME}/vuln/testllmvulv-nemo-codeqldb}"
OUTPUT_DIR="${2:-${HOME}/vuln/codeql_results}"
CODEQL_CLI="${HOME}/.codeql/codeql-cli/codeql/codeql"
QUERIES_DIR="${HOME}/vuln/llm-vulvariant/analyzers/codeql/queries/python"

echo -e "${GREEN}=== CodeQL 查询测试 ===${NC}"
echo "数据库: ${DATABASE}"
echo "输出目录: ${OUTPUT_DIR}"
echo ""

# 检查数据库是否存在
if [ ! -d "${DATABASE}" ]; then
    echo -e "${RED}错误: 数据库不存在: ${DATABASE}${NC}"
    exit 1
fi

# 创建输出目录
mkdir -p "${OUTPUT_DIR}"

# 查询文件列表
QUERIES=(
    "deserialization.ql"
    "command_injection_simple.ql"
    "sql_injection_simple.ql"
    "path_traversal_simple.ql"
    "ssrf_simple.ql"
)

# 运行每个查询
for query in "${QUERIES[@]}"; do
    query_name=$(basename "$query" .ql)
    output_file="${OUTPUT_DIR}/${query_name}.csv"
    
    echo -e "${YELLOW}运行查询: ${query}${NC}"
    
    if ${CODEQL_CLI} database analyze \
        "${DATABASE}" \
        "${QUERIES_DIR}/${query}" \
        --format=csv \
        --output="${output_file}" \
        2>&1 | grep -E "(error|Error|ERROR)" && false; then
        echo -e "${RED}✗ 失败: ${query}${NC}"
        continue
    fi
    
    # 统计结果数量（减去表头）
    result_count=$(($(wc -l < "${output_file}") - 1))
    
    if [ $result_count -gt 0 ]; then
        echo -e "${GREEN}✓ 完成: 找到 ${result_count} 个结果${NC}"
        echo "  输出: ${output_file}"
    else
        echo -e "${GREEN}✓ 完成: 未找到问题${NC}"
    fi
    echo ""
done

# 生成汇总报告
echo -e "${GREEN}=== 结果汇总 ===${NC}"
for query in "${QUERIES[@]}"; do
    query_name=$(basename "$query" .ql)
    output_file="${OUTPUT_DIR}/${query_name}.csv"
    
    if [ -f "${output_file}" ]; then
        result_count=$(($(wc -l < "${output_file}") - 1))
        printf "%-35s : %d 个问题\n" "${query_name}" "${result_count}"
    fi
done

echo ""
echo -e "${GREEN}所有查询已完成！${NC}"
echo "结果保存在: ${OUTPUT_DIR}"
