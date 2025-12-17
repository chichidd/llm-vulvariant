#!/bin/bash
# CodeQL 环境安装脚本

set -e

CODEQL_VERSION="2.23.7"
CODEQL_DIR="$HOME/.codeql"
CODEQL_CLI_DIR="$CODEQL_DIR/codeql-cli"
CODEQL_QUERIES_DIR="$CODEQL_DIR/codeql-queries"

echo "=== CodeQL 环境安装脚本 ==="

# 检查是否已安装
if command -v codeql &> /dev/null; then
    echo "✓ CodeQL 已安装: $(codeql version --format=terse)"
    exit 0
fi

# 检查依赖
echo "检查依赖..."
for cmd in wget unzip git; do
    if ! command -v $cmd &> /dev/null; then
        echo "错误: 需要 $cmd，请先安装"
        exit 1
    fi
done

# 创建目录
mkdir -p "$CODEQL_DIR"

# 下载 CodeQL CLI
echo "下载 CodeQL CLI v${CODEQL_VERSION}..."
cd "$CODEQL_DIR"
PLATFORM="linux64"
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="osx64"
fi

wget -q --show-progress \
    "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-${PLATFORM}.zip" \
    -O codeql-cli.zip

echo "解压 CodeQL CLI..."
unzip -q codeql-cli.zip -d "$CODEQL_CLI_DIR"
rm codeql-cli.zip

# 添加到 PATH
CODEQL_BIN="$CODEQL_CLI_DIR/codeql"
echo "export PATH=\"$CODEQL_BIN:\$PATH\"" >> ~/.bashrc

# 下载标准查询库
echo "下载 CodeQL 标准查询库..."
git clone --depth 1 https://github.com/github/codeql.git "$CODEQL_QUERIES_DIR"

# 验证安装
export PATH="$CODEQL_BIN:$PATH"
echo ""
echo "=== 安装完成 ==="
echo "CodeQL CLI 版本: $(codeql version --format=terse)"
echo "CodeQL 路径: $CODEQL_BIN/codeql"
echo "查询库路径: $CODEQL_QUERIES_DIR"
echo ""
echo "请运行以下命令使环境变量生效："
echo "  source ~/.bashrc"
