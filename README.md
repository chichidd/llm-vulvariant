# llm-vulvariant

LLM 驱动的漏洞变种发现与可利用性验证框架。  
项目把“已知漏洞”的语义特征转成结构化画像，然后在相似仓库或指定仓库上做 agentic 扫描，并对候选发现执行可利用性判定与报告生成。

## 1. 项目定位

`llm-vulvariant` 解决的是安全研究中的一个常见问题:

- 已经知道一个漏洞（通常有 `call_chain + payload + commit`）
- 需要在新版本或其他相似项目里找到“同类漏洞变种”
- 需要把“疑似漏洞”进一步筛成“可利用漏洞”，并输出可提交材料

核心流程是四段:

1. 软件画像（Software Profile）
2. 漏洞画像（Vulnerability Profile）
3. Agentic 漏洞扫描（单仓或批量）
4. 可利用性验证与报告聚合（Claude Skill + Docker PoC）

## 2. 核心能力

- 多阶段画像生成:
  - 软件画像: 仓库描述、模块结构、依赖关系、数据流相关特征
  - 漏洞画像: Source / Sink / Flow 特征、利用条件、攻击场景
- 相似仓库检索:
  - 画像相似度由 5 个维度综合计算（描述、目标应用、目标用户、模块 Jaccard、模块依赖/导入相似度）
- Agentic 扫描:
  - LLM 原生工具调用（读文件、检索、函数提取、CodeQL 查询、漏洞上报）
  - 支持 Priority-1 完成感知的提前停止策略
- 可利用性检查:
  - 按 finding 单条分析并可恢复
  - 对 `EXPLOITABLE` 执行 Docker PoC 验证并保存证据
- 报告与提交产物:
  - `security_report.md`
  - `ghsa_*.md`
  - `exploitable_findings.json/.csv`
  - `submission_index.json`

## 3. 项目结构

```text
llm-vulvariant/
├── config/
│   ├── paths.yaml
│   ├── llm_config.yaml
│   ├── codeql_config.yaml
│   └── software_profile_rule.yaml
├── src/
│   ├── cli/                    # software / vulnerability / scanner / batch_scanner / exploitability
│   ├── profiler/               # 软件画像 + 漏洞画像
│   ├── scanner/
│   │   ├── agent/              # AgenticVulnFinder 与工具集
│   │   ├── similarity/         # profile similarity
│   │   └── checker/            # exploitability + report generator
│   ├── llm/                    # LLM client 与重试封装
│   └── utils/
├── scripts/
└── tests/
```

## 4. 环境要求

最小要求:

- Python `>= 3.10`
- Git

建议安装:

- CodeQL CLI（启用 CodeQL 相关扫描能力）
- Claude CLI（SkillModuleAnalyzer 与 exploitability 检查依赖）
- Docker（EXPLOITABLE finding 的 PoC 验证依赖）

Python 依赖安装:

```bash
pip install -e .
```

当前代码运行时还常用到:

```bash
pip install transformers sentence-transformers torch
```

## 5. 配置说明

### 5.1 路径配置 `config/paths.yaml`

关键字段:

- `project_root`
- `profile_base_path`
- `vuln_data_path`
- `repo_base_path`
- `codeql_db_path`
- `embedding_model_path`

说明:

- software/vulnerability profile 的子目录名通过 CLI 参数传入（例如 `--software-profile-dirname`、`--vuln-profile-dirname`），并拼接到 `profile_base_path` 下。

默认约定是 `~/vuln/...` 目录布局。

### 5.2 LLM 配置 `config/llm_config.yaml`

当前可用 provider（代码真实支持）:

- `deepseek`
- `lab`
- `openai`
- `mock`

常用环境变量:

- `DEEPSEEK_API_KEY`
- `LAB_LLM_API_KEY`
- `NY_API_KEY`（openai provider 在当前配置下读取该变量）

### 5.3 软件画像规则 `config/software_profile_rule.yaml`

关注以下项:

- `module_analyzer_config.analyzer_type`:
  - `skill`（默认，使用 `.claude/skills/ai-infra-module-modeler`）
  - `agent`
- `repo_analyzer_config`:
  - `languages`（支持 `"auto"` 或多语言列表）
  - `max_slice_depth`
  - `max_slice_files`
- 文件扫描范围:
  - `excluded_folders`
  - `code_extensions`

## 6. 输入数据格式

`vuln.json` 是列表，每条至少包含:

- `repo_name`
- `commit`
- `call_chain`
- `payload`
- `cve_id`（可选，缺失时批量模式会回退到 `vuln-{index}`）

示例:

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

说明:

- `call_chain` 中带 `#` 的项会被解析为 `file#function`
- 不带 `#` 的项被视为 sink 标识

## 7. 快速开始

### 7.1 生成软件画像

```bash
software-profile \
  --repo-name NeMo \
  --repo-base-path ~/vuln/data/repos \
  --target-version a1b2c3d4e5f6 \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --llm-provider deepseek
```

输出:

- `~/vuln/profiles/soft/NeMo/<commit>/software_profile.json`
- 若要忽略已有 `software_profile.json` 和 checkpoints，追加 `--force-regenerate`

### 7.2 生成漏洞画像

```bash
vuln-profile \
  --vuln-index 0 \
  --vuln-json ~/vuln/data/vuln.json \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --vuln-profile-dirname vuln \
  --llm-provider deepseek
```

输出:

- `~/vuln/profiles/vuln/<repo_name>/<cve_id>/vulnerability_profile.json`

### 7.3 单目标扫描（手动指定目标仓库）

```bash
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --target-repo Megatron-LM \
  --target-commit a845aa7e12b3 \
  --repo-base-path ~/vuln/data/repos \
  --llm-provider deepseek \
  --max-iterations 3 \
  --output results/scan-results
```

### 7.4 自动目标扫描（按相似度选 Top-K）

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

### 7.5 批量扫描（全量 vuln.json）

```bash
batch-scanner \
  --vuln-json ~/vuln/data/vuln.json \
  --repos-root ~/vuln/data/repos \
  --profile-base-path ~/vuln/profiles \
  --soft-profiles-dir soft \
  --vuln-profiles-dir vuln \
  --scan-output-dir results/full-batch-scan \
  --similarity-threshold 0.70 \
  --fallback-top-n 3 \
  --max-iterations-cap 10 \
  --llm-provider deepseek
```

输出:

- `results/full-batch-scan/batch-summary-YYYYMMDD-HHMMSS.json`
- 每个目标扫描目录下的 finding 与会话产物

### 7.6 可利用性验证 + 报告生成

```bash
python -m cli.exploitability \
  --scan-results-dir results/full-batch-scan \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --repo-base-path ~/vuln/data/repos \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir results/full-batch-exploitability \
  --submission-prefix exploitable_findings \
  --claude-runtime-root results/claude-runtime \
  --claude-runtime-mode run \
  --run-id run-20260303-001 \
  --timeout 1800
```

## 8. 关键输出产物

| 路径 | 说明 |
|---|---|
| `scan-results/<cve>/<repo>-<commit12>/agentic_vuln_findings.json` | Agentic 扫描原始发现 |
| `scan-results/.../conversation_history.json` | 扫描对话历史 |
| `scan-results/.../target_similarity.json` | 目标仓库相似度详情 |
| `scan-results/.../exploitability.json` | 可利用性判定结果 |
| `scan-results/.../evidence/<finding_id>/` | Docker PoC 证据（脚本、构建日志、执行输出） |
| `scan-results/.../reports/security_report.md` | 汇总研究报告 |
| `scan-results/.../reports/ghsa_*.md` | GHSA 格式报告 |
| `results/full-batch-exploitability/exploitable_findings.json` | 聚合提交 JSON |
| `results/full-batch-exploitability/exploitable_findings.csv` | 聚合提交 CSV |
| `results/full-batch-exploitability/submission_index.json` | 按 CVE 分组索引 |

## 9. 相似度策略

目标选择默认使用以下 5 维特征:

- `description_sim`
- `target_application_sim`
- `target_user_sim`
- `module_jaccard_sim`
- `module_dependency_import_sim`

最终 `overall_sim` 为加权平均。批量模式先按阈值筛选；如果没有目标达标，会回退到 `fallback_top_n`。

## 10. 批量模式与恢复能力

批量扫描:

- `--skip-existing-scans`: 已存在 `agentic_vuln_findings.json` 时跳过
- `--force-regenerate-profiles`: 强制重建 software/vulnerability profiles

可利用性检查:

- `--skip-existing`: 已存在 `exploitability.json` 时跳过
- 同一目录重复执行时，会复用已有结果并继续剩余 finding

## 11. Claude Runtime 布局

`cli.exploitability` 支持三种运行时目录策略:

- `shared`: 所有任务共用同一 runtime 根目录
- `run`: 每次运行一个子目录（`<root>/<run-id>`）
- `folder`: 每个扫描目录一个子目录（`<root>/<run-id>/<cve>/<target>`）

用于并行批处理时，推荐 `folder` 或 `run`，减少状态互相影响。

## 12. 运行脚本

仓库内提供了端到端脚本示例:

```bash
bash scripts/run_nvidia_full_pipeline.sh
```

该脚本串联:

1. 画像检查
2. 软件画像补齐
3. 批量扫描
4. exploitability 验证与提交产物生成

## 13. 测试

运行全部测试:

```bash
pytest -q
```

常用回归集:

```bash
pytest -q tests/test_cli_batch_scanner.py tests/test_cli_exploitability.py tests/test_cli_agent_scanner.py
```

## 14. 常见问题

1. `Software profile not found`:
   - 先确认 `~/vuln/profiles/soft/<repo>/<commit>/software_profile.json` 已存在
   - 检查 `--soft-profiles-dir` 与 `config/paths.yaml` 是否一致

2. `Vulnerability profile not found`:
   - 先执行 `vuln-profile`
   - 注意路径是 `~/vuln/profiles/vuln/<repo>/<cve>/vulnerability_profile.json`

3. `Claude CLI not found`:
   - 安装 Claude CLI 并确保 `claude` 在 `PATH`
   - 确认 `.claude/skills/check-exploitability` 与 `.claude/skills/ai-infra-module-modeler` 存在

4. CodeQL 工具不可用:
   - 安装 CodeQL CLI
   - 确认 `codeql` 命令可执行并检查 `config/codeql_config.yaml`

5. Docker PoC 阶段失败:
   - 查看 `evidence/<finding_id>/docker_build.log`
   - 查看 `evidence/<finding_id>/execution_output.txt`

## 15. 安全与使用声明

本项目用于漏洞研究、变种挖掘与防御修复验证。  
请仅在授权环境中运行扫描、验证和 PoC 相关流程。
