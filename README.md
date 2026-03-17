# llm-vulvariant

LLM 驱动的漏洞变种发现与可利用性验证框架。

给定一个已知漏洞（call chain + payload + commit），在相似仓库或新版本中发现同类漏洞变种，并自动完成可利用性判定与提交材料生成。

---

## 1. 架构与流程

整个流水线分为四个阶段，后一阶段依赖前一阶段的输出：

```
                       ┌──────────────────────────────────────────────────────────┐
                       │                  llm-vulvariant 流水线                    │
                       └──────────────────────────────────────────────────────────┘

  ┌───────────────┐   ┌───────────────┐   ┌──────────────────┐   ┌────────────────────┐
  │  Stage 1      │   │  Stage 2      │   │  Stage 3         │   │  Stage 4           │
  │  软件画像     │   │  漏洞画像     │   │  Agentic 扫描    │   │  可利用性验证      │
  │               │   │               │   │                  │   │  + 报告生成        │
  │  仓库 ──►     │   │ vuln.json +   │   │  漏洞画像 +      │   │  扫描发现 ──►      │
  │  software_    │   │ 软件画像 ──►  │   │  目标仓库 ──►    │   │  exploitability    │
  │  profile.json │   │ vuln_         │   │  agentic_vuln_   │   │  .json + report    │
  │               │   │ profile.json  │   │  findings.json   │   │  + submission      │
  └───────────────┘   └───────────────┘   └──────────────────┘   └────────────────────┘
        │                    │                     │                        │
        │              ┌─────┘                     │                        │
        ▼              ▼                           ▼                        ▼
  ┌──────────────────────────┐   ┌──────────────────────────────────────────────────┐
  │  profiles/               │   │  results/                                        │
  │  ├── soft/<repo>/<hash>/ │   │  ├── <scan-output-dir>/<cve>/<repo>-<hash12>/   │
  │  │   └── software_       │   │  │   ├── agentic_vuln_findings.json             │
  │  │       profile.json    │   │  │   ├── conversation_history.json              │
  │  └── vuln/<repo>/<cve>/  │   │  │   ├── exploitability.json                    │
  │      └── vulnerability_  │   │  │   ├── reports/security_report.md             │
  │          profile.json    │   │  │   └── evidence/<finding>/                    │
  │                          │   │  └── exploitable_findings_<run-id>.*            │
  └──────────────────────────┘   └──────────────────────────────────────────────────┘
```

### 各阶段说明

| 阶段 | 输入 | 处理 | 输出 |
|------|------|------|------|
| **Stage 1: 软件画像** | 仓库源码 | LLM 分析仓库描述、模块结构、依赖、数据流 | `software_profile.json` |
| **Stage 2: 漏洞画像** | `vuln.json` + 软件画像 | LLM 提取 Source / Sink / Flow 特征、利用条件 | `vulnerability_profile.json` |
| **Stage 3: Agentic 扫描** | 漏洞画像 + 目标仓库 | Agent 使用工具集（读文件、CodeQL、函数提取等）搜索变种 | `agentic_vuln_findings.json` |
| **Stage 4: 可利用性验证** | 扫描发现 | Claude Skill 判定 + Docker PoC 验证 | 判定结果、安全报告、提交材料 |

---

## 2. 项目结构

```
llm-vulvariant/
├── src/
│   ├── cli/                            # CLI 入口
│   │   ├── software.py                 #   software-profile 命令
│   │   ├── vulnerability.py            #   vuln-profile 命令
│   │   ├── agent_scanner.py            #   scanner 命令（单目标/自动目标）
│   │   ├── batch_scanner.py            #   batch-scanner 命令（批量）
│   │   ├── exploitability.py           #   可利用性验证 + 报告
│   │   └── common.py                   #   共享 CLI 工具
│   ├── profiler/                       # 画像生成
│   │   ├── software/                   #   软件画像（模块分析、仓库分析、数据流提取）
│   │   ├── vulnerability/              #   漏洞画像（Source/Sink/Flow 特征提取）
│   │   └── profile_storage.py          #   通用存储管理（checkpoint、恢复）
│   ├── scanner/                        # 扫描与验证
│   │   ├── agent/                      #   AgenticVulnFinder + 工具集（文件读取、CodeQL、函数提取）
│   │   ├── similarity/                 #   5 维画像相似度匹配与目标选择
│   │   └── checker/                    #   可利用性检查 + 安全报告生成
│   ├── llm/                            # LLM 客户端（Deepseek / OpenAI / Anthropic）
│   └── utils/                          # 工具库（日志、Git、CodeQL、语言检测等）
├── config/
│   ├── paths.yaml                      # 路径配置
│   ├── llm_config.yaml                 # LLM provider 配置
│   ├── codeql_config.yaml              # CodeQL 配置
│   └── software_profile_rule.yaml      # 软件画像规则（模块分析器类型、语言、排除项）
├── scripts/                            # 端到端运行脚本
├── tests/                              # 30+ 测试文件
└── pyproject.toml
```

---

## 3. 环境与安装

### 依赖

| 类别 | 依赖项 | 说明 |
|------|--------|------|
| **必须** | Python ≥ 3.10, Git | 基础运行环境 |
| **核心 Python 包** | `openai`, `anthropic`, `requests`, `pyyaml` | `pip install -e .` 自动安装 |
| **嵌入模型（可选）** | `transformers`, `sentence-transformers`, `torch` | 相似度匹配所需；不安装则无法使用自动目标选择 |
| **外部工具（可选）** | CodeQL CLI | 启用 CodeQL 查询能力 |
| **外部工具（可选）** | Claude CLI | SkillModuleAnalyzer 与可利用性检查依赖 |
| **外部工具（可选）** | Docker | EXPLOITABLE finding 的 PoC 验证 |

### 安装

```bash
# 基础安装
pip install -e .

# 若需要相似度匹配功能
pip install transformers sentence-transformers torch
```

### 环境变量

| 变量 | 用途 |
|------|------|
| `DEEPSEEK_API_KEY` | Deepseek provider API 密钥 |
| `NY_API_KEY` | OpenAI provider API 密钥（当前配置） |

---

## 4. 配置

所有配置文件位于 `config/` 目录。

### 路径配置 — `paths.yaml`

| 字段 | 说明 | 默认 |
|------|------|------|
| `project_root` | 项目根目录 | `~/vuln` |
| `profile_base_path` | 画像存储根目录 | `~/vuln/profiles` |
| `vuln_data_path` | 漏洞数据文件 | `~/vuln/data/vuln.json` |
| `repo_base_path` | 仓库源码目录 | `~/vuln/data/repos` |
| `codeql_db_path` | CodeQL 数据库目录 | `~/vuln/codeql_dbs` |
| `embedding_model_path` | 嵌入模型目录 | `~/vuln/models` |

画像子目录名通过 CLI 参数 `--software-profile-dirname` / `--vuln-profile-dirname` 指定，拼接到 `profile_base_path` 下。

### LLM 配置 — `llm_config.yaml`

支持的 provider：`deepseek`、`openai`。配置包含温度、重试策略、最大 token 数等。

### 软件画像规则 — `software_profile_rule.yaml`

| 配置项 | 说明 |
|--------|------|
| `module_analyzer_config.analyzer_type` | `skill`（使用 Claude Skill）或 `agent` |
| `repo_analyzer_config.languages` | `"auto"` 或语言列表 |
| `excluded_folders` / `code_extensions` | 文件扫描范围控制 |

---

## 5. 输入数据格式

### `vuln.json`

```json
[
  {
    "repo_name": "NeMo",
    "commit": "a1b2c3d4e5f6...",
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

每条必须包含 `repo_name`、`commit`、`call_chain`、`payload`。`cve_id` 可选，缺失时回退到 `vuln-{index}`。

`call_chain` 中带 `#` 的项解析为 `file#function`，不带 `#` 的项视为 sink 标识。

---

## 6. 快速开始

### 6.1 端到端最小示例（单条 CVE → 单目标）

以下四条命令串联执行完整流水线：

```bash
# 1) 为源仓库生成软件画像
software-profile \
  --repo-name NeMo \
  --repo-base-path ~/vuln/data/repos \
  --target-version a1b2c3d4e5f6 \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --llm-provider deepseek

# 2) 生成漏洞画像
vuln-profile \
  --vuln-index 0 \
  --vuln-json ~/vuln/data/vuln.json \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --vuln-profile-dirname vuln \
  --llm-provider deepseek

# 3) 对指定目标仓库执行 agentic 扫描
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --target-repo Megatron-LM \
  --target-commit a845aa7e12b3 \
  --repo-base-path ~/vuln/data/repos \
  --llm-provider deepseek \
  --max-iterations 3 \
  --output results/scan-results

# 4) 可利用性验证 + 报告
python -m cli.exploitability \
  --scan-results-dir results/scan-results \
  --soft-profile-dir ~/vuln/profiles/soft \
  --repo-base-path ~/vuln/data/repos \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir results/exploitability \
  --submission-prefix exploitable_findings \
  --run-id demo-001
```

上述命令会写出 `results/exploitability/exploitable_findings_demo-001_strict.json`、
`results/exploitability/exploitable_findings_demo-001_strict.csv`、
`results/exploitability/exploitable_findings_demo-001_strict_submission_index.json` 和
`results/exploitability/exploitable_findings_demo-001_strict_exploitable_security_report.md`。

### 6.2 自动目标选择扫描

不指定目标仓库，让系统通过画像相似度自动选择 Top-K 目标：

```bash
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --top-k 5 \
  --similarity-threshold 0.70 \
  --similarity-model-name BAAI--bge-large-en-v1.5 \
  --similarity-device cpu \
  --llm-provider deepseek
```

### 6.3 批量扫描流水线

对 `vuln.json` 中所有漏洞批量执行扫描：

```bash
batch-scanner \
  --vuln-json ~/vuln/data/vuln.json \
  --source-repos-root ~/vuln/data/repos \
  --target-repos-root ~/vuln/data/repos \
  --source-soft-profiles-dir ~/vuln/profiles/soft \
  --target-soft-profiles-dir ~/vuln/profiles/soft \
  --vuln-profiles-dir ~/vuln/profiles/vuln \
  --scan-output-dir results/full-batch-scan \
  --similarity-threshold 0.70 \
  --fallback-top-n 3 \
  --max-workers 8 \
  --scan-workers 4 \
  --max-iterations-cap 10 \
  --llm-provider deepseek
```

说明：
- `--max-workers` 是并发线程池总上限；
- `--scan-workers` 是 `batch_scanner` target scan 并发 worker 数；未设置时默认继承 `--max-workers`；
- `batch_scanner` 的相似度筛选与 profile 构建仍是串行阶段。

然后执行可利用性验证与报告生成：

```bash
python -m cli.exploitability \
  --scan-results-dir results/full-batch-scan \
  --soft-profile-dir ~/vuln/profiles/soft \
  --repo-base-path ~/vuln/data/repos \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir results/full-batch-exploitability \
  --submission-prefix exploitable_findings \
  --claude-runtime-root results/claude-runtime \
  --claude-runtime-mode folder \
  --max-workers 4 \
  --run-id run-20260303-001 \
  --timeout 1800
```

说明：`exploitability` 当前只在 `folder` runtime 下对 folder 切片并发，`--max-workers` 为并发上限；`run/shared` 目前保持串行。

### 6.4 一键全流水线脚本

```bash
bash scripts/run_nvidia_full_pipeline.sh
```

该脚本按顺序执行 5 个阶段：验证漏洞画像 → 链接源画像 → 构建目标软件画像 → 批量扫描 → 可利用性验证与报告。可通过环境变量控制主要路径、阈值、LLM provider/model 和 timeout 参数。

---

## 7. 核心设计

### 7.1 5 维画像相似度

目标仓库选择基于源仓库与候选仓库画像之间的 5 维相似度：

| 维度 | 说明 |
|------|------|
| `description_sim` | 仓库描述的语义相似度（embedding） |
| `target_application_sim` | 目标应用领域的匹配度 |
| `target_user_sim` | 目标用户群的匹配度 |
| `module_jaccard_sim` | 模块名称的 Jaccard 相似度 |
| `module_dependency_import_sim` | 模块依赖/导入关系的相似度 |

`overall_sim` 为加权平均。批量模式先按 `--similarity-threshold` 筛选；达标数不足时回退到 `--fallback-top-n`。

### 7.2 Agentic 扫描工具集

`AgenticVulnFinder` 通过 LLM 的 tool_choice 能力自主调用以下工具：

| 工具 | 功能 |
|------|------|
| `read_file` | 读取目标仓库源代码文件 |
| `search_keyword` | 关键字检索 |
| `get_call_paths` | 获取函数调用路径 |
| `run_codeql_query` | 执行 CodeQL 查询 |
| `report_finding` | 上报发现的漏洞 |

Agent 特性：
- 最大 300 轮迭代，自动检测 context limit 并优雅退出
- **Priority-1 提前停止**：当高优先级发现完成时可提前结束（支持 `min` / `max` 策略）
- **模块优先级排序**：根据漏洞画像自动计算目标模块的扫描优先级
- **可恢复**：`AgentMemoryManager` 跟踪已处理文件/模块，支持断点续扫

### 7.3 可恢复性设计

所有阶段均支持断点恢复，避免在长时间任务中丢失进度：

| 组件 | 恢复机制 |
|------|----------|
| 画像生成 | `ProfileStorageManager` 使用 checkpoint 文件，中断后从上次断点继续 |
| Agentic 扫描 | `AgentMemoryManager` 记录 pending files / processed modules / findings cache |
| 批量扫描 | `--skip-existing-scans` 跳过已存在 `agentic_vuln_findings.json` 的目标 |
| 可利用性检查 | `--skip-existing` 跳过已完成的判定；同目录重复执行自动续做 |

### 7.4 Claude Runtime 布局

`cli.exploitability` 支持三种运行时目录策略，用于控制 Claude Skill 的隔离粒度：

| 模式 | 目录结构 | 适用场景 |
|------|----------|----------|
| `shared` | 所有任务共用根目录 | 单次少量任务 |
| `run` | `<root>/<run-id>/` | 单次批量运行 |
| `folder` | `<root>/<run-id>/<cve>/<target>/` | 并行批处理（推荐） |

---

## 8. 输出产物

### 扫描阶段

| 路径 | 说明 |
|------|------|
| `<scan-dir>/<cve>/<repo>-<commit12>/agentic_vuln_findings.json` | 扫描原始发现 |
| `.../conversation_history.json` | Agent 对话历史 |
| `.../target_similarity.json` | 目标选择时的相似度详情 |

### 可利用性验证阶段

| 路径 | 说明 |
|------|------|
| `.../exploitability.json` | 每条 finding 的可利用性判定 |
| `.../evidence/<finding_id>/` | Docker PoC 证据（脚本、构建日志、执行输出） |
| `.../reports/security_report.md` | 汇总安全研究报告 |
| `.../reports/ghsa_*.md` | GHSA 格式漏洞报告 |

### 聚合提交产物

| 路径 | 说明 |
|------|------|
| `<prefix>_<run-id>[_strict].json` | `--report-only-exploitable` 时附加 `_strict` |
| `<prefix>_<run-id>[_strict].csv` | `--report-only-exploitable` 时附加 `_strict` |
| `<prefix>_<run-id>[_strict]_submission_index.json` | `--report-only-exploitable` 时附加 `_strict` |
| `<prefix>_<run-id>[_strict]_exploitable_security_report.md` | `--report-only-exploitable` 时附加 `_strict` |

---

## 9. 辅助脚本

| 脚本 | 功能 |
|------|------|
| `scripts/run_nvidia_full_pipeline.sh` | 端到端全流水线（5 阶段） |
| `scripts/run_all_software_profiles.sh` | 批量生成指定目录下所有仓库的软件画像 |
| `scripts/run_all_vulnerability_profiles.sh` | 批量生成 `vuln.json` 中所有条目的漏洞画像 |
| `scripts/run_all_vuln_software_profile.sh` | 为漏洞条目对应的源仓库生成软件画像 |
| `scripts/update_repos.sh` | 更新仓库到最新版本 |
| `scripts/checkout_main.sh` | 将仓库切换到主分支 |
| `scripts/small-scale-exp.sh` | 小规模实验脚本 |

---

## 10. 测试

```bash
# 全量测试
pytest -q

# CLI 回归测试
pytest -q tests/test_cli_batch_scanner.py tests/test_cli_exploitability.py tests/test_cli_agent_scanner.py

# 相似度模块
pytest -q tests/test_similarity_retriever.py tests/test_similarity_embedding.py

# 画像模型
pytest -q tests/test_profile_models_and_storage.py
```

---

## 11. 常见问题

**Software profile not found**
- 确认 `profiles/soft/<repo>/<commit>/software_profile.json` 已存在
- 检查 `--source-soft-profiles-dir` 和 `--target-soft-profiles-dir` 是否指向正确目录

**Vulnerability profile not found**
- 先执行 `vuln-profile` 生成
- 路径应为 `profiles/vuln/<repo>/<cve>/vulnerability_profile.json`

**Claude CLI not found**
- 安装 Claude CLI 并确保 `claude` 在 `PATH`
- 确认 `skill_path` 配置下存在 `check-exploitability` 与 `ai-infra-module-modeler`

**CodeQL 不可用**
- 安装 CodeQL CLI 并确认 `codeql` 命令可执行
- 检查 `config/codeql_config.yaml`

**Docker PoC 失败**
- 检查 `evidence/<finding_id>/docker_build.log`
- 检查 `evidence/<finding_id>/execution_output.txt`

---

## 12. 安全声明

本项目用于漏洞研究、变种挖掘与防御修复验证。请仅在授权环境中运行扫描、验证和 PoC 相关流程。
