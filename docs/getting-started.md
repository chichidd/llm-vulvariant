# 快速开始

本文面向第一次接手 `llm-vulvariant` 的内部同学，目标是先把环境装好、关键依赖查清，再进入数据准备和具体流水线。

第一步建议先读 [runtime-requirements.md](runtime-requirements.md)。那里集中写了当前代码路径真正依赖的 `claude`、`.claude/skills`、`.claude-runtime`、Docker、CodeQL、`jq`、git working tree 和本地 embedding 模型要求。

## 1. 最小前提

### 核心前提

| 类别 | 是否必须 | 说明 |
|------|----------|------|
| Python 3.10+ | 必须 | CLI 本体要求 `>=3.10` |
| Git | 必须 | profile 生成、扫描和 exploitability 都会读取或切换提交 |
| Bash | 跑脚本时必须 | `scripts/*.sh` 都依赖 `bash` |
| `python` 或 `python3` | 基本必须 | 多数脚本会自动探测，但 `run_all_vulnerability_profiles.sh` 当前直接调用 `python -` |
| API Key | 必须 | 至少为所选 LLM provider 配置一个可用 key |
| console scripts | 常用脚本必须 | `pip install -e .` 后会得到 `software-profile` / `vuln-profile` / `scanner` / `batch-scanner` |

### 按功能启用的附加前提

| 功能 | 额外要求 |
|------|----------|
| 默认 `software-profile` 模块分析 | `claude` CLI、repo-local `.claude/skills/ai-infra-module-modeler` |
| `python -m cli.exploitability` | `claude` CLI、可写 `.claude-runtime` |
| 自动目标选择 | `transformers` / `sentence-transformers` / `torch` + 本地 embedding 模型目录 |
| CodeQL 查询 | `codeql` CLI + 可用 database / query pack |
| Docker PoC | Docker。对 `EXPLOITABLE` finding，这一步会被 exploitability 自动触发 |
| `run_all_vuln_software_profile.sh` | `jq` |

## 2. 安装仓库

```bash
cd /mnt/raid/home/dongtian/vuln/llm-vulvariant
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

如果要使用自动目标选择中的 embedding 相似度能力，再补装：

```bash
pip install transformers sentence-transformers torch
```

## 3. 配置 provider 与环境变量

当前 provider 默认定义在 `config/llm_config.yaml`：

| Provider | API Key 环境变量 | 备注 |
|----------|------------------|------|
| `deepseek` | `DEEPSEEK_API_KEY` | 默认模型为 `deepseek-chat` |
| `openai` | `NY_API_KEY` | 当前配置中的 base URL 不是标准 OpenAI 官方地址，按仓库现有配置使用 |
| `lab` | `LAB_LLM_API_KEY` | 当前配置带有重试耗尽后回退到 `deepseek` 的策略 |

示例：

```bash
export DEEPSEEK_API_KEY=...
export NY_API_KEY=...
export LAB_LLM_API_KEY=...
```

命令里可以通过 `--llm-provider` 选择 provider，通过 `--llm-name` 覆盖默认模型名。

## 4. 建议先做预检

### 核心 CLI 预检

```bash
software-profile --help
vuln-profile --help
scanner --help
batch-scanner --help
python -m cli.exploitability --help
```

### Claude / Docker / CodeQL / jq 按需预检

```bash
command -v claude
command -v docker
command -v codeql
command -v jq
claude -p '{"ok":true}'
```

### repo-local skills 与模型目录预检

```bash
test -d .claude/skills/ai-infra-module-modeler
ls ~/vuln/models/<model-name>
```

## 5. 脚本入口变量与特殊情况

常用覆盖变量：

- `PYTHON_BIN`: 让脚本使用指定解释器，适用于 `python` / `python3` 都不合适的环境
- `VULN_PROFILE_CMD`: 覆盖 `run_all_vulnerability_profiles.sh` 调用的 `vuln-profile` 命令名
- `ROOT`, `ROOT_DIR`, `PROFILE_BASE_PATH`, `OUTPUT_DIR`: 控制批量脚本的输入/输出目录

隐藏情况：

- `run_all_vulnerability_profiles.sh` 当前内部直接执行 `python -` 解析 `vuln.json`，因此如果系统没有 `python` 这个名字，脚本本身仍会失败。
- `run_microsoft_scan_full.sh` 不会自动激活特定 Conda 环境；如果默认 `python` / `python3` 不合适，请显式设置 `PYTHON_BIN`。
- 默认 `software-profile` 走的是 skill analyzer；如果你改了 `config/software_profile_rule.yaml` 的 `analyzer_type` 或 `validation_mode`，Claude 相关要求会变化。

## 6. 推荐阅读顺序

1. 先看 [runtime-requirements.md](runtime-requirements.md)，把工具链和隐形前提对齐。
2. 再看 [data-and-repositories.md](data-and-repositories.md)，准备 `vuln.json`、source repo、target repo 和 profile 目录。
3. 然后看 [pipeline-recipes.md](pipeline-recipes.md)，选择单漏洞流程、自动目标选择还是批量流程。
4. 参数不清楚时，再查 [parameter-reference.md](parameter-reference.md)。

## 7. 常见安装与环境问题

### `software-profile: command not found`

- 确认虚拟环境已激活
- 确认执行过 `pip install -e .`
- 也可以临时改用 `PYTHONPATH=src .venv/bin/python -m cli.software --help` 排查

### `claude: command not found`

- 安装 Claude CLI / Claude Code 对应的 `claude` 命令
- 确认它能在仓库根目录执行 `claude -p`

### `Skill not found`

- 默认模块分析仍依赖 `.claude/skills/ai-infra-module-modeler`
- 确认 `config/paths.yaml` 的 `project_root` / `repo_root` 没指到别处

### `Embedding model path not found`

- 这不是 Python 包问题，而是本地模型目录缺失
- 检查 `config/paths.yaml` 的 `embedding_model_path`
- 检查 `--similarity-model-name` 对应目录是否真的存在

### `Repository has local changes`

- `exploitability` 和部分扫描路径要求 clean worktree
- 把扫描目标仓库和日常开发中的脏工作树分开

### `command not found: jq`

- 这是 `run_all_vuln_software_profile.sh` 的脚本级依赖
- 不影响所有 CLI，但影响该批量脚本
