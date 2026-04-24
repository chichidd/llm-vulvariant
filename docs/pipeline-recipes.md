# 流水线操作手册

这一页按“要完成什么任务”组织，而不是按内部模块组织。默认假设你已经完成：

- 环境安装
- API Key 配置
- `vuln.json` 准备
- source repo / target repo 准备
- [runtime-requirements.md](runtime-requirements.md) 里的前提检查

如果还没做这些，先看 [getting-started.md](getting-started.md) 和 [data-and-repositories.md](data-and-repositories.md)。

## Recipe 1: 单漏洞 -> 单目标仓库

这是最容易排查问题的最小闭环。

额外前提：

- 默认 `software-profile` 模块分析依赖 `claude` + `.claude/skills/ai-infra-module-modeler`
- `python -m cli.exploitability` 依赖 `claude` CLI、可写 `.claude-runtime`
- 如果某条 finding 被判定为 `EXPLOITABLE`，exploitability 会自动进入 Docker PoC
- target repo 应该是 clean git worktree

### Step 1. 生成源仓库的软件画像

```bash
software-profile \
  --repo-name NeMo \
  --repo-base-path ~/vuln/data/repos \
  --target-version <source_commit> \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --llm-provider deepseek
```

### Step 2. 生成漏洞画像

```bash
vuln-profile \
  --vuln-index 0 \
  --vuln-json ~/vuln/data/vuln.json \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --vuln-profile-dirname vuln \
  --repo-base-path ~/vuln/data/repos \
  --llm-provider deepseek
```

### Step 3. 扫描一个指定目标仓库

```bash
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --target-repo Megatron-LM \
  --target-commit <target_commit> \
  --repo-base-path ~/vuln/data/repos \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --vuln-profile-dirname vuln \
  --llm-provider deepseek \
  --max-iterations 3 \
  --output ~/vuln/results/scan-results
```

### Step 4. 做 exploitability 检查与报告

```bash
python -m cli.exploitability \
  --scan-results-dir ~/vuln/results/scan-results \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft \
  --repo-base-path ~/vuln/data/repos \
  --generate-report \
  --submission-output-dir ~/vuln/results/exploitability \
  --submission-prefix exploitable_findings \
  --run-id demo-001
```

### 关键输出

- `profiles/soft/<repo>/<commit>/software_profile.json`
- `profiles/vuln/<repo>/<cve>/vulnerability_profile.json`
- `results/scan-results/<cve>/<target>-<commit>/agentic_vuln_findings.json`
- `results/scan-results/<cve>/<target>-<commit>/exploitability.json`

## Recipe 2: 自动选择目标仓库

不显式指定 `--target-repo` 时，`scanner` 会基于已存在的 target software profile 做相似度检索。

额外前提：

- 已安装 `transformers sentence-transformers torch`
- 候选 target repo 已经有 software profile
- `config/scanner_config.yaml` 或 CLI 中配置的 embedding 模型在本地 `paths.embedding_model_path` 下真实存在

示例：

```bash
scanner \
  --vuln-repo NeMo \
  --cve CVE-2025-23361 \
  --top-k 5 \
  --similarity-threshold 0.70 \
  --similarity-model-name jinaai--jina-code-embeddings-1.5b \
  --similarity-device cpu \
  --profile-base-path ~/vuln/profiles \
  --software-profile-dirname soft-nvidia \
  --vuln-profile-dirname vuln \
  --repo-base-path ~/vuln/data/repos-nvidia \
  --llm-provider deepseek \
  --output ~/vuln/results/scan-results
```

常用调节项：

- `--top-k`: 最多扫多少个候选目标
- `--similarity-threshold`: 相似度下限
- `--include-same-repo`: 是否把 source repo 自己也算进候选池
- `--max-iterations`: 单个 target 的扫描轮数

## Recipe 3: 批量扫描 `vuln.json`

`batch-scanner` 适合一口气处理整个 `vuln.json`。它会按条目确保 profile 可用、选择目标仓库，并发执行 target scan。

额外前提：

- source repo / target repo 都应是可 checkout 的 git working tree
- 如果你启用 `--skip-existing-scans`，target repo 最好保持 clean tree，避免 live fingerprint 校验被跳过
- 自动目标选择场景仍然需要本地 embedding 模型目录

```bash
batch-scanner \
  --vuln-json ~/vuln/data/vuln.json \
  --source-repos-root ~/vuln/data/repos \
  --target-repos-root ~/vuln/data/repos-nvidia \
  --source-soft-profiles-dir ~/vuln/profiles/soft \
  --target-soft-profiles-dir ~/vuln/profiles/soft-nvidia \
  --vuln-profiles-dir ~/vuln/profiles/vuln \
  --scan-output-dir ~/vuln/results/nvidia-batch-scan \
  --run-id run-20260408-001 \
  --similarity-threshold 0.70 \
  --fallback-top-n 3 \
  --jobs 4 \
  --max-iterations-cap 10 \
  --llm-provider deepseek
```

常用参数：

- `--max-targets`: 限制每个漏洞最多扫描多少个目标
- `--scan-all-profiled-targets`: 跳过相似度筛选，直接扫描所有已有 profile 的 target repo
- `--skip-existing-scans`: 已有完整结果时跳过
- `--force-regenerate-profiles`: 忽略缓存 profile，重新生成
- `--jobs`: 每个漏洞下的 target scan 并发数

什么时候适合先用批量脚本而不是直接上 `batch-scanner`：

- 你想先单独补齐 source software profile
- 你想先单独补齐 target software profile
- 你想把 profile 生成和扫描分批跑，方便复用结果

## Recipe 4: 批量 exploitability、报告与聚合提交材料

额外前提：

- `claude -p` 可非交互运行；如果当前 CLI 不支持 `--output-format json`，代码会尝试纯文本回退
- `.claude-runtime` 或 `--claude-runtime-root` 可写
- `--jobs > 1` 时使用 `--claude-runtime-mode folder`
- target repo 是 clean git worktree
- Docker 可用，因为 `EXPLOITABLE` finding 会自动进入 Phase 5 Docker PoC

```bash
python -m cli.exploitability \
  --scan-results-dir ~/vuln/results/nvidia-batch-scan \
  --soft-profile-dir ~/vuln/profiles/soft-nvidia \
  --repo-base-path ~/vuln/data/repos-nvidia \
  --jobs 4 \
  --generate-report \
  --report-only-exploitable \
  --submission-output-dir ~/vuln/results/nvidia-batch-exploitability \
  --submission-prefix exploitable_findings \
  --claude-runtime-root ~/vuln/results/claude-runtime \
  --claude-runtime-mode folder \
  --run-id run-20260408-001
```

注意：

- `--jobs > 1` 时，使用 `--claude-runtime-mode folder`
- `--skip-existing` 只跳过已经有完整 `exploitability.json` 的目录
- `--report-only-exploitable` 会让聚合文件名带 `_strict`

常见聚合产物：

- `<prefix>_<run-id>.json`
- `<prefix>_<run-id>.csv`
- `<prefix>_<run-id>_submission_index.json`
- `<prefix>_<run-id>_exploitable_security_report.md`

## Recipe 5: 一键运行 NVIDIA 全流水线脚本

仓库内置了 `scripts/run_nvidia_full_pipeline.sh`，适合已有一套 NVIDIA target repo 时直接串起完整流程。

额外前提：

- `python` 或 `python3` 可用，或显式设置 `PYTHON_BIN`
- target repo 对应 commit 可 checkout
- 如果 `EXPLOITABILITY_JOBS > 1`，脚本会自动强制 `folder` runtime mode
- exploitability 阶段的 Claude / Docker 前提仍然全部成立

最小示例：

```bash
LLM_PROVIDER=deepseek \
SCAN_JOBS=4 \
EXPLOITABILITY_JOBS=4 \
bash scripts/run_nvidia_full_pipeline.sh
```

脚本会按顺序执行 5 个阶段：

1. 检查漏洞画像是否齐全
2. 链接 source software profile
3. 为 `repos-nvidia` 生成缺失 software profile
4. 批量扫描
5. 批量 exploitability 与报告

最重要的环境变量：

| 变量 | 作用 |
|------|------|
| `VULN_JSON` | 漏洞条目文件 |
| `REPOS_NVIDIA` | target repo 根目录 |
| `PROFILES_ROOT` | profiles 根目录 |
| `SCAN_OUTPUT_DIR` | 扫描结果目录 |
| `EXP_OUTPUT_DIR` | exploitability 聚合输出目录 |
| `SCAN_JOBS` | 扫描并发度 |
| `EXPLOITABILITY_JOBS` | exploitability 并发度 |
| `LLM_PROVIDER` / `LLM_NAME` | provider 与模型 |
| `RUN_ID` | 运行标识 |

## 其他内置脚本注意事项

- `scripts/run_microsoft_scan_full.sh` 使用 `PYTHON_BIN` 或回退到 `python` / `python3`，默认 `LLM_PROVIDER=lab`
- `scripts/run_all_vuln_software_profile.sh` 需要 `jq`
- `scripts/run_all_vulnerability_profiles.sh` 需要 `vuln-profile` 在 `PATH`，并且当前脚本内部直接用 `python -`
