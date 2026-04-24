# 参数参考

这一页不机械复述 `--help`，而是把最常用参数按用途分组，并把容易漏掉的运行前提一起写出来。

## 1. 默认值从哪里来

### `config/paths.yaml`

提供默认路径：

- `project_root`
- `profile_base_path`
- `vuln_data_path`
- `repo_base_path`
- `codeql_db_path`
- `embedding_model_path`

### `config/llm_config.yaml`

提供 provider 默认模型与 API Key 环境变量：

- `deepseek` -> `DEEPSEEK_API_KEY`
- `openai` -> `NY_API_KEY`
- `lab` -> `LAB_LLM_API_KEY`

其中 `lab` 当前配置里带有回退到 `deepseek` 的策略。

### `config/scanner_config.yaml`

提供模块相似度的默认值，例如：

- `module_similarity.threshold`
- `module_similarity.model_name`
- `module_similarity.device`

## 2. 命令和运行前提的对应关系

| 命令 / 脚本 | 额外前提 |
|-------------|----------|
| `software-profile` | 默认 `analyzer_type=skill`，依赖 `claude` + `.claude/skills/ai-infra-module-modeler` |
| `vuln-profile` | 主要依赖所选 LLM provider；批量脚本版还依赖 `vuln-profile` 命令在 `PATH` |
| `scanner` | target repo 需要是可 checkout 的 git working tree；自动目标选择还依赖本地 embedding 模型目录 |
| `batch-scanner` | source/target repo 需要是 git working tree；`--skip-existing-scans` 最好配 clean tree |
| `python -m cli.exploitability` | 依赖 `claude` CLI、可写 `.claude-runtime`、clean target repo；`EXPLOITABLE` finding 会自动触发 Docker PoC |
| `run_all_vuln_software_profile.sh` | 依赖 `jq`、`software-profile`、`python` / `python3` 或 `PYTHON_BIN` |
| `run_all_vulnerability_profiles.sh` | 依赖 `vuln-profile` 或 `VULN_PROFILE_CMD`，并且当前脚本内部直接调用 `python -` |
| `run_microsoft_scan_full.sh` | 使用 `PYTHON_BIN` 或回退到 `python` / `python3`，默认 `LLM_PROVIDER=lab` |

更完整的说明见 [runtime-requirements.md](runtime-requirements.md)。

## 3. 通用规则

- `--output-dir` 通常优先级最高，显式指定后会覆盖 `--profile-base-path + dirname` 的组合。
- `--llm-provider` 负责选择 provider，`--llm-name` 只在你要覆盖默认模型时再传。
- `-v` / `--verbose` 适合先在小样本上打开，批量场景下日志会很多。
- 本页不记录 superpower / 协作文档参数；那部分统一留在根级 `vuln/docs/superpowers/`。

## 4. `software-profile`

用途：为某个仓库的某个提交生成 `software_profile.json`。

### 核心输入

| 参数 | 说明 |
|------|------|
| `--repo-name` | 仓库名，必须与 `repo-base-path` 下目录名一致 |
| `--repo-base-path` | 仓库根目录；不传时走 `config/paths.yaml` |
| `--target-version` | 指定提交；不传时使用当前版本 |

### 路径相关

| 参数 | 说明 |
|------|------|
| `--profile-base-path` | profile 根目录 |
| `--software-profile-dirname` | software profile 子目录名，默认 `soft` |
| `--output-dir` | 直接指定输出目录，覆盖前两项组合 |

### LLM 相关

| 参数 | 说明 |
|------|------|
| `--llm-provider` | `deepseek`、`openai`、`lab` |
| `--llm-name` | 覆盖 provider 默认模型 |

### 运行控制

| 参数 | 说明 |
|------|------|
| `--force-regenerate` | 忽略已有 profile/checkpoint，强制重建 |
| `-v` | 输出更详细日志 |

补充前提：

- 当前默认模块分析路径依赖 `claude` 和 repo-local `ai-infra-module-modeler`
- 如果你改了 `config/software_profile_rule.yaml` 的 `analyzer_type` 或 `validation_mode`，这条前提会变化

## 5. `vuln-profile`

用途：根据 `vuln.json` 中的漏洞条目生成 `vulnerability_profile.json`。

### 选择输入条目

| 参数 | 说明 |
|------|------|
| `--vuln-index` | 指定 `vuln.json` 中的条目序号；不传时处理全部 |
| `--vuln-json` | 漏洞条目文件；不传时走 `config/paths.yaml` |

### Profile 与仓库路径

| 参数 | 说明 |
|------|------|
| `--profile-base-path` | profile 根目录 |
| `--software-profile-dirname` | 源 software profile 子目录名 |
| `--vuln-profile-dirname` | 漏洞 profile 子目录名，默认 `vuln` |
| `--soft-profile-dir` | 显式 software profile 目录，覆盖前两项组合 |
| `--output-dir` | 显式漏洞 profile 输出目录 |
| `--repo-base-path` | `vuln.json` 所引用仓库的根目录 |

### LLM 与重建

| 参数 | 说明 |
|------|------|
| `--llm-provider` / `--llm-name` | 与 `software-profile` 相同 |
| `--force-regenerate` | 即使存在兼容缓存结果也重新生成 |
| `-v` | 详细日志 |

## 6. `scanner`

用途：对单个漏洞画像执行单目标扫描，或自动选择多个目标仓库扫描。

### 必填

| 参数 | 说明 |
|------|------|
| `--vuln-repo` | 漏洞画像对应的源仓库名 |
| `--cve` | CVE 或漏洞 ID |

### 手动指定目标

| 参数 | 说明 |
|------|------|
| `--target-repo` | 指定目标仓库 |
| `--target-commit` | 指定目标提交；不传时会尝试推断 |

### 自动选目标

| 参数 | 说明 |
|------|------|
| `--top-k` | 最多选多少个候选目标，默认 3 |
| `--similarity-threshold` | 仅保留相似度不低于该值的候选 |
| `--include-same-repo` | 候选池中包含源仓库自身 |
| `--similarity-model-name` | 文本相似度模型名，模型目录位于 `paths.embedding_model_path` |
| `--similarity-device` | 相似度计算设备，常用 `cpu` |

### 路径与 profile

| 参数 | 说明 |
|------|------|
| `--repo-base-path` | 目标仓库根目录 |
| `--profile-base-path` | profile 根目录 |
| `--software-profile-dirname` | target software profile 子目录名 |
| `--vuln-profile-dirname` | vulnerability profile 子目录名 |
| `--output` | 扫描结果输出根目录 |

### 扫描控制

| 参数 | 说明 |
|------|------|
| `--max-iterations` | 单个 target 的最大迭代数 |
| `--stop-when-critical-complete` | 启用 priority-1 完成感知的提前停止 |
| `--critical-stop-mode` | `min` 或 `max` |
| `--critical-stop-max-priority` | 完成判断纳入到哪个优先级，`1` 或 `2` |
| `--verbose` | 详细日志 |

补充前提：

- target repo 需要是可 checkout 的 git working tree
- 自动目标选择时，除了 Python 包，还要确保本地模型目录存在
- repo 有本地改动时，如果命令需要切换 commit，扫描会失败

## 7. `batch-scanner`

用途：遍历 `vuln.json`，确保 profile 存在、选择目标仓库并批量扫描。

### 输入与目录

| 参数 | 说明 |
|------|------|
| `--vuln-json` | 输入漏洞条目 |
| `--source-repos-root` | source repo 根目录 |
| `--target-repos-root` | target repo 根目录 |
| `--profile-base-path` | profile 根目录 |
| `--source-soft-profiles-dir` | source software profile 目录名或绝对路径 |
| `--target-soft-profiles-dir` | target software profile 目录名或绝对路径 |
| `--vuln-profiles-dir` | vulnerability profile 目录名或绝对路径 |
| `--scan-output-dir` | 扫描输出根目录 |
| `--run-id` | 本次 batch run 的标识，用于共享 memory 与结果隔离 |

### 目标选择

| 参数 | 说明 |
|------|------|
| `--similarity-threshold` | 相似度下限，默认 0.7 |
| `--max-targets` | 每个漏洞最多扫多少个 target |
| `--fallback-top-n` | 如果没有目标达到阈值，回退扫描前 N 个 |
| `--include-same-repo` | 候选池中包含 source repo |
| `--scan-all-profiled-targets` | 忽略相似度筛选，直接扫描所有已有 profile 的 target |
| `--similarity-model-name` / `--similarity-device` | 相似度模型配置 |

### 扫描与并发控制

| 参数 | 说明 |
|------|------|
| `--max-iterations-cap` | 批量扫描下的单 target 迭代上限 |
| `--disable-critical-stop` | 关闭 priority-1 提前停止 |
| `--critical-stop-mode` | `min` 或 `max` |
| `--critical-stop-max-priority` | `1` 或 `2` |
| `--max-workers` | 扫描阶段 worker 总上限 |
| `--scan-workers` | target scan worker 数；不传时继承 `--max-workers` |
| `--jobs` | 每个漏洞的 target scan 并发数 |
| `--limit` | 只处理 `vuln.json` 前 N 条，适合小规模试跑 |

### 缓存与重跑

| 参数 | 说明 |
|------|------|
| `--force-regenerate-profiles` | 即使有缓存 profile 也重建 |
| `--skip-existing-scans` | 已有完整 coverage metadata 且 fingerprint 匹配时跳过扫描 |
| `-v` | 详细日志 |

补充前提：

- source / target repo 都应是 git working tree
- `--skip-existing-scans` 的 live fingerprint 校验最好配 clean tree
- 自动目标选择仍然需要本地 embedding 模型目录

## 8. `python -m cli.exploitability`

用途：对 scan result folder 做可利用性判定，并按需产出报告与聚合提交材料。

### 选择输入范围

| 参数 | 说明 |
|------|------|
| `--scan-results-dir` | 扫描结果根目录，必填 |
| `--folder` | 只处理某个子目录；不传时处理整个结果目录 |

### Profile 与仓库定位

| 参数 | 说明 |
|------|------|
| `--profile-base-path` | profile 根目录 |
| `--software-profile-dirname` | software profile 子目录名，默认 `soft` |
| `--soft-profile-dir` | 显式 software profile 目录 |
| `--repo-base-path` | 结果中引用到的仓库根目录 |

### 报告与聚合产物

| 参数 | 说明 |
|------|------|
| `--generate-report` | 生成 GHSA / 安全研究报告 |
| `--report-repo-url` | 报告中使用的 GitHub 仓库链接前缀 |
| `--cve-id` | 报告中显式写入的 CVE ID |
| `--report-only-exploitable` | 只为 `EXPLOITABLE` finding 生成报告/聚合 |
| `--submission-output-dir` | 聚合 JSON / CSV / index / markdown 的输出目录 |
| `--submission-prefix` | 聚合产物文件名前缀，默认 `exploitable_findings` |

### 运行时与并发

| 参数 | 说明 |
|------|------|
| `--timeout` | 单个 folder 的分析超时秒数，默认 1800 |
| `--skip-existing` | 只跳过已存在完整 `exploitability.json` 的目录 |
| `--claude-runtime-root` | Claude runtime 根目录 |
| `--claude-runtime-mode` | `shared`、`run`、`folder` |
| `--run-id` | runtime / 报告元数据中的运行标识 |
| `--jobs` | 并行处理多少个 folder |
| `-v` | 详细日志 |

补充前提：

- 需要 `claude -p` 可非交互运行；如果当前 CLI 不支持 `--output-format json`，代码会尝试纯文本回退
- 需要可写 `.claude-runtime` 或 `--claude-runtime-root`
- target repo 需要 clean worktree
- `EXPLOITABLE` finding 会自动触发 Docker PoC
- 当 `--jobs > 1` 时，必须使用 `--claude-runtime-mode folder`

并发注意事项：

- `shared` 和 `run` 更适合串行或低并发
- 并发时除了 runtime mode，还要避免多个任务同时改动同一个 target repo 工作树
