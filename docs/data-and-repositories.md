# 数据与仓库准备

这一页回答四个问题：

1. `vuln.json` 应该长什么样
2. source repo、target repo、profile、results 应该放在哪里
3. 哪些路径必须是 git working tree
4. 什么时候用批量脚本准备数据

## 1. 默认目录布局

默认路径来自 `config/paths.yaml`。按当前配置，项目默认假设你在 `~/vuln` 下组织数据：

```text
~/vuln/
├── data/
│   ├── vuln.json
│   └── repos/
├── profiles/
│   ├── soft/
│   └── vuln/
├── codeql_dbs/
├── models/
└── llm-vulvariant/
```

关键路径含义：

| 路径 | 用途 |
|------|------|
| `data/vuln.json` | 漏洞条目输入 |
| `data/repos/` | 默认 source repo 根目录，也可以同时作为 target repo 根目录 |
| `profiles/soft/` | 软件画像输出目录 |
| `profiles/vuln/` | 漏洞画像输出目录 |
| `results/` | 扫描结果、exploitability 结果、聚合提交材料 |
| `models/` | 自动目标选择使用的本地 embedding 模型目录 |

如果你不用默认路径，可以在命令行覆盖：

- `--repo-base-path`
- `--profile-base-path`
- `--output-dir`
- `--source-repos-root`
- `--target-repos-root`
- `--source-soft-profiles-dir`
- `--target-soft-profiles-dir`
- `--vuln-profiles-dir`

## 2. `vuln.json` 最小格式

示例：

```json
[
  {
    "repo_name": "NeMo",
    "commit": "a1b2c3d4e5f6",
    "cve_id": "CVE-2025-23361",
    "call_chain": [
      "nemo/api/server.py#handle_request",
      "nemo/runtime/loader.py#load_model",
      "pickle.loads"
    ],
    "payload": "..."
  }
]
```

字段约定：

| 字段 | 是否必须 | 说明 |
|------|----------|------|
| `repo_name` | 必须 | 必须与仓库目录名一致 |
| `commit` | 必须 | 源漏洞对应提交 |
| `call_chain` | 必须 | 用于构建漏洞画像；带 `#` 的项通常是 `file#function` |
| `payload` | 必须 | 漏洞利用负载或触发输入 |
| `cve_id` | 建议提供 | 缺失时系统会回退到 `vuln-{index}` |

## 3. source repo 与 target repo 如何摆放

### source repo

source repo 必须能够按 `repo_name` 找到：

```text
<repo-base-path>/<repo_name>
```

例如 `repo_name=NeMo` 时，默认路径是：

```text
~/vuln/data/repos/NeMo
```

### target repo

target repo 有两种常见方式：

- 与 source repo 放在同一个根目录，直接复用 `data/repos`
- 单独放到另一个根目录，例如 `data/repos-nvidia`、`data/repos-microsoft`

对应地：

- `scanner` 用 `--repo-base-path`
- `batch-scanner` 分别用 `--source-repos-root` 和 `--target-repos-root`

## 4. Git working tree 要求

这部分不是“建议”，而是多个命令的真实运行前提。

- `software-profile`、`scanner`、`batch-scanner`、`python -m cli.exploitability` 都依赖 repo 是正常 git working tree，而不是随便拷出来的代码目录。
- `scanner`、`batch-scanner`、`exploitability` 可能临时 checkout 到目标 commit 再恢复。
- `python -m cli.exploitability` 明确要求 clean worktree；目标 repo 有本地未提交改动时会直接拒绝继续。
- `scanner` 在需要切 commit 时也要求 clean worktree；否则该 target 会失败。
- `batch-scanner --skip-existing-scans` 的 live fingerprint 校验要求 clean tree；dirty tree 会导致回退或放弃这条验证路径。

建议：

- 把用于扫描/验证的 target repo 与你日常开发中的脏工作树分开
- 长跑批处理时，不要手动在这些 repo 里切分支或编辑文件

## 5. Profile 与结果目录

默认输出结构：

```text
profiles/
├── soft/<repo>/<commit>/software_profile.json
└── vuln/<repo>/<cve>/vulnerability_profile.json

results/
└── <scan-output-dir>/<cve>/<target-repo>-<commit12>/
    ├── agentic_vuln_findings.json
    ├── conversation_history.json
    ├── scan_memory.json
    ├── exploitability.json
    └── reports/
```

结果目录名里的 commit 片段默认是 12 位前缀，后续 `exploitability` 会用它反查对应 repo 与 software profile。

如果你想把 profile 按项目分桶，比如 `soft-nvidia`、`soft-microsoft`，可以：

- 用 `--software-profile-dirname`
- 或者直接用 `--output-dir`

## 6. 批量准备脚本

仓库里已有几个适合准备数据的脚本。

### `scripts/update_repos.sh`

用途：对一个根目录下的一级 git 仓库执行 `git pull --ff-only`。

隐藏要求：

- 只处理一级子目录 repo
- 需要 `bash`
- `realpath` 可选，没有时会回退

示例：

```bash
ROOT=~/vuln/data/repos-nvidia bash scripts/update_repos.sh
```

### `scripts/run_all_vuln_software_profile.sh`

用途：为 `vuln.json` 中出现过的 `repo_name + commit` 批量生成软件画像。

隐藏要求：

- 需要 `jq`
- 需要 `software-profile` 在 `PATH`
- 需要 `python` 或 `python3`，也可显式设置 `PYTHON_BIN`

示例：

```bash
bash scripts/run_all_vuln_software_profile.sh \
  --vuln-json ~/vuln/data/vuln.json \
  --repo-base-path ~/vuln/data/repos \
  --profile-base-path ~/vuln/profiles \
  --soft-profile-dirname soft \
  --llm-provider deepseek
```

### `scripts/run_all_vulnerability_profiles.sh`

用途：为 `vuln.json` 中的条目批量生成漏洞画像。

隐藏要求：

- 需要 `vuln-profile` 在 `PATH`，或者覆盖 `VULN_PROFILE_CMD`
- 当前脚本内部直接执行 `python -` 做 helper 解析，因此这里不是“有 `python3` 就一定够”

示例：

```bash
bash scripts/run_all_vulnerability_profiles.sh \
  --vuln-json ~/vuln/data/vuln.json \
  --profile-base-path ~/vuln/profiles \
  --soft-profile-dirname soft \
  --vuln-profile-dirname vuln \
  --llm-provider deepseek
```

### `scripts/run_all_software_profiles.sh`

用途：对一个根目录下的所有一级仓库，按当前 `HEAD` 批量生成软件画像。

隐藏要求：

- 只扫描一级子目录 repo
- 需要 `software-profile` 在 `PATH`
- 需要 `python` 或 `python3`，也可显式设置 `PYTHON_BIN`

示例：

```bash
bash scripts/run_all_software_profiles.sh \
  --root ~/vuln/data/repos-nvidia \
  --output-dir ~/vuln/profiles/soft-nvidia \
  --llm-provider deepseek
```

## 7. 准备数据时最容易踩的坑

- `repo_name` 和实际目录名不一致，导致 profile 或扫描找不到仓库
- source repo 与 target repo 分散在不同根目录里，却忘了显式传 `--source-repos-root` / `--target-repos-root`
- 已经自定义了 `--output-dir`，却又误以为结果会写回默认 `profiles/soft` 或 `profiles/vuln`
- 自动目标选择只装了 Python 包，但没有把本地 embedding 模型放到 `paths.embedding_model_path` 下
- target repo 有本地改动，结果在扫描或 exploitability 阶段因为 clean worktree 检查失败
