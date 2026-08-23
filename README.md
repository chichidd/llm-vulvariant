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

- 默认 `software-profile` 模块分析依赖本仓库自带的 `.claude/skills/ai-infra-module-modeler`，并要求 `claude -p` 可非交互运行。
- `python -m cli.exploitability` 依赖可非交互运行的 `claude -p` 和可写 `results/runtime/claude`。
- `python -m cli.exploitability` 会为 `EXPLOITABLE` finding 自动执行 Docker PoC；并发时 `--jobs > 1` 必须配 `--claude-runtime-mode folder`。
- 自动目标选择不只需要 `transformers` / `sentence-transformers` / `torch`，还需要 `paths.embedding_model_path/<model_name>` 的本地模型目录真实存在。
- `scanner`、`batch-scanner`、`exploitability` 都可能临时切换仓库 commit；目标仓库应保持为可 checkout 的 git 工作树，`exploitability` 明确要求 clean worktree。
- 本目录仅供 CCS revision 内部使用，不是 artifact 或 release；正式可利用性流程只接受完整 batch 的 manifest v2。

正式扫描固定使用 `lab` / `GLM-5.2` / `https://llm.shtech.org/v1`：

```bash
export LAB_LLM_API_BASE=https://llm.shtech.org/v1
```

## 快速开始

所有命令先显式绑定到这份 revision，而不是依赖当前用户的 home 或父工作区：

```bash
export CCS_REVISION_ROOT=/absolute/path/to/ccs-revision
cd "$CCS_REVISION_ROOT/code/llm-vulvariant"
```

### 1. 安装

```bash
# Run from the repository root.
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

### 3. 单目标 direct scan（仅调试）

direct scan 只用于排查输入或扫描问题；其输出不能直接进入正式 exploitability。正式流程必须由完整 `batch-scanner` 生成 manifest v2，详见 [docs/pipeline-recipes.md](docs/pipeline-recipes.md)。

```bash
# 1) 为源仓库生成软件画像
software-profile \
  --repo-name <REPO_NAME> \
  --repo-base-path $CCS_REVISION_ROOT/repos/general \
  --target-version <source_commit> \
  --llm-provider lab \
  --llm-name GLM-5.2

# 2) 生成漏洞画像
vuln-profile \
  --vuln-index 0 \
  --vuln-json $CCS_REVISION_ROOT/benchmark/input/vuln.json \
  --llm-provider lab \
  --llm-name GLM-5.2

# 3) 扫描一个指定目标仓库
scanner \
  --vuln-repo <VULN_REPO> \
  --cve <CVE_ID> \
  --target-repo <TARGET_REPO> \
  --target-commit <target_commit> \
  --repo-base-path $CCS_REVISION_ROOT/repos/general \
  --llm-provider lab \
  --llm-name GLM-5.2 \
  --max-iterations 3 \
  --output $CCS_REVISION_ROOT/results/scan-results

```

### 4. 正式 exploitability（完整 batch manifest v2）

只能使用完整 batch 的 `scan-output-commit-bindings-<RUN_ID>.json`；命令必须同时传入 manifest 与其小写 SHA-256。即使使用 `--folder`，该目录也必须是该完整 manifest 中的 binding，不能绕过该约束。

```bash
python -m cli.exploitability \
  --scan-results-dir $CCS_REVISION_ROOT/results/nvidia-batch-scan \
  --scan-output-commit-manifest $CCS_REVISION_ROOT/results/nvidia-batch-scan/scan-output-commit-bindings-<RUN_ID>.json \
  --scan-output-commit-manifest-sha256 <MANIFEST_SHA256> \
  --repo-base-path $CCS_REVISION_ROOT/repos/nvidia \
  --generate-report \
  --submission-output-dir $CCS_REVISION_ROOT/results/exploitability
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
$CCS_REVISION_ROOT/
├── benchmark/input/vuln.json
├── code/llm-vulvariant/
├── evidence/profiles/
│   ├── soft/
│   └── vuln/
├── repos/
│   ├── general/
│   └── nvidia/
├── models/
└── results/
```

常见输出物：

- `evidence/profiles/soft/<repo>/<commit>/software_profile.json`
- `evidence/profiles/vuln/<repo>/<cve>/vulnerability_profile.json`
- `results/<scan-dir>/<cve>/<target>-<commit>/agentic_vuln_findings.json`
- `results/<scan-dir>/<cve>/<target>-<commit>/exploitability.json`
- `results/<submission-dir>/<prefix>_<run-id>.json`

## 安全声明

本项目用于漏洞研究、变种挖掘与防御修复验证。请只在已授权的环境、仓库和数据上运行扫描、验证与 PoC 流程。
