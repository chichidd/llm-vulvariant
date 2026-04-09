# llm-vulvariant

LLM 驱动的漏洞变种发现与可利用性验证框架。

给定一个已知漏洞条目（源仓库、提交、call chain、payload），项目会先生成软件画像与漏洞画像，再对目标仓库执行 agentic 扫描，最后输出可利用性判定、研究报告和提交材料。

## 流水线概览

| 阶段 | 输入 | 输出 | 主要命令 |
|------|------|------|----------|
| 1. 软件画像 | 仓库源码 + 提交版本 | `software_profile.json` | `software-profile` |
| 2. 漏洞画像 | `vuln.json` + 软件画像 | `vulnerability_profile.json` | `vuln-profile` |
| 3. 变种扫描 | 漏洞画像 + 目标仓库 | `agentic_vuln_findings.json` | `scanner` / `batch-scanner` |
| 4. 可利用性验证 | 扫描结果 | `exploitability.json`、报告、聚合提交材料 | `python -m cli.exploitability` |

## 开始前先看

先读 [docs/runtime-requirements.md](docs/runtime-requirements.md)。当前版本有几条容易漏掉的前提：

- 默认 `software-profile` 模块分析和 `python -m cli.exploitability` 都依赖本仓库自带的 `.claude/skills/*`，以及可非交互运行的 `claude -p`。
- `python -m cli.exploitability` 会为 `EXPLOITABLE` finding 自动执行 Docker PoC；并发时 `--jobs > 1` 必须配 `--claude-runtime-mode folder`。
- 自动目标选择不只需要 `transformers` / `sentence-transformers` / `torch`，还需要 `paths.embedding_model_path/<model_name>` 的本地模型目录真实存在。
- `scanner`、`batch-scanner`、`exploitability` 都可能临时切换仓库 commit；目标仓库应保持为可 checkout 的 git 工作树，`exploitability` 明确要求 clean worktree。

## 快速开始

### 1. 安装

```bash
cd /mnt/raid/home/dongtian/vuln/llm-vulvariant
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

如果要使用自动目标选择中的 embedding 相似度能力，还需要：

```bash
pip install transformers sentence-transformers torch
```

### 2. 预检关键前提

环境、工具链和 Claude 相关要求见：

- [docs/runtime-requirements.md](docs/runtime-requirements.md)
- [docs/getting-started.md](docs/getting-started.md)

### 3. 最小单漏洞流程

```bash
# 1) 为源仓库生成软件画像
software-profile \
  --repo-name NeMo \
  --repo-base-path ~/vuln/data/repos \
  --target-version <source_commit> \
  --llm-provider deepseek

# 2) 生成漏洞画像
vuln-profile \
  --vuln-index 0 \
  --vuln-json ~/vuln/data/vuln.json \
  --llm-provider deepseek

# 3) 扫描一个指定目标仓库
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --target-repo Megatron-LM \
  --target-commit <target_commit> \
  --repo-base-path ~/vuln/data/repos \
  --llm-provider deepseek \
  --max-iterations 3 \
  --output ~/vuln/results/scan-results

# 4) 可利用性验证与报告
python -m cli.exploitability \
  --scan-results-dir ~/vuln/results/scan-results \
  --repo-base-path ~/vuln/data/repos \
  --generate-report \
  --submission-output-dir ~/vuln/results/exploitability
```

完整 recipe、批量流程和脚本入口见 [docs/pipeline-recipes.md](docs/pipeline-recipes.md)。

## 文档索引

- [docs/runtime-requirements.md](docs/runtime-requirements.md): `claude` / `.claude/skills` / `.claude-runtime`、Docker、CodeQL、`jq`、git 工作树、本地 embedding 模型等隐形前提
- [docs/getting-started.md](docs/getting-started.md): 安装、API Key、自检命令、脚本入口变量
- [docs/data-and-repositories.md](docs/data-and-repositories.md): `vuln.json`、仓库布局、git 工作树要求、批量准备脚本
- [docs/pipeline-recipes.md](docs/pipeline-recipes.md): 单次扫描、自动选目标、批量扫描、批量 exploitability、内置脚本
- [docs/parameter-reference.md](docs/parameter-reference.md): 常用参数分组说明和对应运行前提

## 目录与输出

默认路径来自 `config/paths.yaml`，常见目录如下：

```text
~/vuln/
├── data/
│   ├── vuln.json
│   └── repos/
├── profiles/
│   ├── soft/
│   └── vuln/
├── results/
├── models/
└── llm-vulvariant/
```

常见输出物：

- `profiles/soft/<repo>/<commit>/software_profile.json`
- `profiles/vuln/<repo>/<cve>/vulnerability_profile.json`
- `results/<scan-dir>/<cve>/<target>-<commit>/agentic_vuln_findings.json`
- `results/<scan-dir>/<cve>/<target>-<commit>/exploitability.json`
- `results/<submission-dir>/<prefix>_<run-id>.json`

## 内部文档边界

`llm-vulvariant/docs/` 只放项目使用文档，不再承载 superpower 协作资料。相关内部文档入口在根级 [../docs/superpowers/README.md](../docs/superpowers/README.md)。

## 安全声明

本项目用于漏洞研究、变种挖掘与防御修复验证。请只在已授权的环境、仓库和数据上运行扫描、验证与 PoC 流程。
