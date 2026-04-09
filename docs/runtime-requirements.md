# 运行前提与隐形依赖

这页专门记录代码里已经存在、但用户最容易漏掉的运行条件。建议在第一次跑命令前先过一遍。

## 1. 核心前提

| 项目 | 是否必须 | 说明 |
|------|----------|------|
| Git working tree | 必须 | source/target repo 需要能解析当前 commit，并允许临时 checkout |
| Bash | 脚本必须 | `scripts/*.sh` 都依赖 `bash` |
| Python 3.10+ | 必须 | CLI 本体要求 `>=3.10` |
| `python` 或 `python3` | 基本必须 | 多数脚本会自动探测；但 `run_all_vulnerability_profiles.sh` 当前直接调用 `python -` |
| console scripts (`software-profile` / `vuln-profile` / `scanner` / `batch-scanner`) | 常用脚本必须 | 通常来自 `pip install -e .` |
| LLM API Key | 必须 | 至少为所选 provider 提供一个 key |

## 2. Claude Code / Claude CLI 要求

以下两条路径都依赖 Claude：

- `software-profile` 的默认模块分析路径。当前 `config/software_profile_rule.yaml` 默认 `module_analyzer_config.analyzer_type: skill`，会调用 repo-local `ai-infra-module-modeler`。
- `python -m cli.exploitability`。它会调用 repo-local `check-exploitability`，并在 `EXPLOITABLE` finding 上自动进入 Docker PoC 验证。

你需要满足这些条件：

- `claude` 可执行文件在 `PATH`。
- 已完成登录，且 `claude -p` 能在仓库根目录非交互运行。
- `exploitability` 路径要求 `claude -p --output-format json` 可用；module analyzer 对旧版 CLI 可以回退纯文本模式，但 exploitability 不应依赖这个回退。
- 本仓库内置的 `.claude/skills/check-exploitability` 和 `.claude/skills/ai-infra-module-modeler` 必须保留。
- Claude runtime 目录必须可写。默认是仓库根目录下的 `.claude-runtime/`，也可以显式传 `--claude-runtime-root`。
- 并发跑 `python -m cli.exploitability --jobs > 1` 时，必须使用 `--claude-runtime-mode folder`。

补充说明：

- 代码会自动设置 `CLAUDE_CONFIG_DIR` 指向当前运行目录；平时无需手动导出，除非你在调试 Claude 行为。
- 自动化调用会传 `--dangerously-skip-permissions`。如果你的 Claude 安装或账号环境不支持这一行为，skill-based 流程会失败。
- 仓库里带了 `.claude/settings.local.json` 作为本地权限配置。如果你也用 Claude Code 手动进入仓库操作，尽量不要删掉它。

## 3. Repo-local skills 与手工执行说明

当前仓库内置 skills：

- `.claude/skills/check-exploitability`
- `.claude/skills/ai-infra-module-modeler`

隐藏约束：

- `ai-infra-module-modeler` 的手工 skill 文档建议使用 `conda` 环境 `dsocr`。核心 CLI 不会自动为你创建这个环境。
- `run_microsoft_scan_full.sh` 如果检测到 `conda` 和 `dsocr`，会优先 `conda activate dsocr`；否则再回退到 `python` / `python3`。

## 4. 自动目标选择的完整前提

自动目标选择不只是安装 Python 包。

你需要同时满足：

- 安装 `transformers`、`sentence-transformers`、`torch`
- `config/scanner_config.yaml` 或 CLI 参数里指定的模型名存在
- `paths.embedding_model_path/<model_name>` 这个本地目录真实存在

代码会先检查本地模型路径；如果目录不存在，会直接抛出 `FileNotFoundError`，不会自动帮你下载。

## 5. CodeQL 相关前提

只有在需要 CodeQL 工具链时才需要这些条件：

- `codeql` CLI 在 `PATH`，或者在 `config/codeql_config.yaml` 里显式配置 `cli_path`
- `paths.codeql_db_path` 指向可读写的数据库目录
- `.codeql-queries/` 可写

隐藏约束：

- 首次运行某些查询路径时，代码可能会执行 `codeql pack install` 来准备 query pack 依赖。
- 这意味着对应环境需要具备可用的 CodeQL pack 解析条件；如果没有预装 cache，首次运行可能更慢，也可能受网络/pack 配置影响。

## 6. Docker 与 exploitability 的真实要求

`python -m cli.exploitability` 不是“只有你显式做 PoC 时才需要 Docker”。当前实现里：

- `check-exploitability` skill 对 `EXPLOITABLE` finding 会自动执行 Phase 5 Docker PoC。
- 因此一旦进入这一分支，Docker 就从“可选工具”升级成“运行时依赖”。

同时还要满足：

- 目标 repo 对应 commit 可 checkout
- repo 工作树是 clean 的
- Docker 能 build 目标项目依赖的镜像

## 7. Git 工作树与仓库状态要求

这部分是最容易漏掉的真实前提。

- `scanner`、`batch-scanner`、`python -m cli.exploitability` 都可能临时 checkout 到目标 commit，然后再恢复。
- source/target repo 应该是正常的 git working tree，而不是随便拷出来的代码目录。
- `python -m cli.exploitability` 明确要求 clean worktree；repo 有本地未提交改动时会直接拒绝继续。
- `scanner` 在需要切换 commit 时也要求 clean worktree，否则会报错并跳过该 target。
- `batch-scanner --skip-existing-scans` 的 live fingerprint 校验同样要求 clean tree；dirty tree 会导致跳过验证或回退到缓存兼容逻辑。

建议：

- 把用于扫描/验证的 target repo 与你日常开发中的脏工作树分开
- 长跑批处理时，不要手动在这些 repo 里切分支或改文件

## 8. 脚本级隐形依赖

### `scripts/run_all_vuln_software_profile.sh`

- 需要 `jq`
- 需要 `software-profile` 在 `PATH`
- 需要 `python` 或 `python3`，也可以显式设置 `PYTHON_BIN`

### `scripts/run_all_vulnerability_profiles.sh`

- 需要 `vuln-profile` 在 `PATH`，或者覆盖 `VULN_PROFILE_CMD`
- 当前脚本内部使用 `python -` 做 JSON 解析 helper，所以这里不是“有 `python3` 就够”

### `scripts/run_all_software_profiles.sh`

- 需要 `software-profile` 在 `PATH`
- 需要 `python` 或 `python3`，也可以显式设置 `PYTHON_BIN`
- 按一级子目录扫描 repo root

### `scripts/update_repos.sh` / `scripts/checkout_main.sh`

- 只处理一级子目录 git repo
- `realpath` 是可选的；脚本在缺失时会回退

### `scripts/run_nvidia_full_pipeline.sh`

- 需要 `python` 或 `python3`，也可以显式设置 `PYTHON_BIN`
- `EXPLOITABILITY_JOBS > 1` 时会自动强制 `folder` runtime mode

### `scripts/run_microsoft_scan_full.sh`

- 优先尝试 `conda activate dsocr`
- 找不到时再回退到 `python` / `python3`
- 默认走 `LLM_PROVIDER=lab`

## 9. 建议预检命令

### 核心检查

```bash
command -v git bash
command -v python || command -v python3
command -v software-profile
command -v vuln-profile
command -v scanner
command -v batch-scanner
```

### Claude / Docker / CodeQL / jq 按需检查

```bash
command -v claude
command -v docker
command -v codeql
command -v jq
claude -p --output-format json '{"ok":true}'
```

### repo-local skills 与本地模型检查

```bash
test -d .claude/skills/check-exploitability
test -d .claude/skills/ai-infra-module-modeler
ls .claude/skills
ls ~/vuln/models/<model-name>
```

## 10. 常见报错与定位方向

| 现象 | 常见原因 |
|------|----------|
| `claude: command not found` | Claude CLI 未安装或不在 `PATH` |
| `Skill not found` | `.claude/skills/*` 被移动、删掉，或 `project_root` / `repo_root` 配置错了 |
| `Expected JSON object from Claude CLI` | 当前 Claude CLI 不支持 `--output-format json`；exploitability 会受影响 |
| `Embedding model path not found` | 本地模型目录不存在，只有 Python 包没有模型文件 |
| `command not found: jq` | 跑了 `run_all_vuln_software_profile.sh` 但系统没装 `jq` |
| `Repository has local changes` | 目标 repo 脏工作树，无法安全 checkout / 验证 |
| `--jobs > 1 requires --claude-runtime-mode folder` | 并发 exploitability 配置错误 |
| CodeQL query pack 失败 | `codeql` 未安装、数据库路径不对，或首次 pack 安装条件不满足 |
