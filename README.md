# LLM-VulVariant：基于 LLM 的漏洞变种检测系统

## 项目简介

LLM-VulVariant 是一个利用大语言模型（LLM）和代码查询（CodeQL）技术，自动检测软件项目中潜在漏洞变种的智能系统。该系统通过构建软件画像和漏洞画像，使用 LLM 进行智能推理，识别代码库中可能存在相似漏洞的模块。

---

## 系统架构

```
llm-vulvariant/
├── core/                      # 核心模块
│   ├── software_profile.py    # 软件画像生成器
│   ├── vuln_profile.py        # 漏洞画像生成器
│   ├── scanner.py             # 漏洞扫描器
│   ├── codeql_native.py       # CodeQL 分析器封装
│   ├── llm_client.py          # LLM 客户端封装
│   └── config.py              # 配置管理
├── utils/                     # 工具模块
│   ├── llm_utils.py           # LLM 相关工具
│   └── git_utils.py           # Git 仓库操作工具
├── test/                      # 测试用例
├── scripts/                   # 辅助脚本
├── repo-profiles/             # 软件画像存储目录
├── vuln-profiles/             # 漏洞画像存储目录
└── scan-results/              # 扫描结果存储目录
```

---

## 核心模块说明

### 1. 软件画像模块 (`core/software_profile.py`)

**功能**：分析目标软件仓库，构建全面的软件架构特征画像。

**主要类**：
- `SoftwareProfile`：软件画像数据结构
- `SoftwareProfiler`：软件画像生成器

**画像内容**：
```python
{
  "basic_info": {
    "name": "项目名称",
    "version": "版本/提交哈希",
    "description": "项目描述",
    "target_application": ["应用场景"],
    "target_user": ["目标用户群"]
  },
  "repo_info": {
    "files": ["文件列表"],
    "structure": "目录结构"
  },
  "modules": ["核心模块列表"]
}
```

**使用示例**：
```python
from core.software_profile import SoftwareProfiler
from core.llm_client import create_llm_client, LLMConfig

# 创建 LLM 客户端
llm_config = LLMConfig(provider="hku")
llm_client = create_llm_client(llm_config)

# 创建软件画像生成器
profiler = SoftwareProfiler(
    config=None,
    llm_client=llm_client,
    output_dir="./repo-profiles/"
)

# 生成软件画像
profile = profiler.generate_profile(
    repo_path="/path/to/repository",
    target_version="commit_hash",
    force_full_analysis=True
)

# 保存画像
with open("software_profile.json", "w") as f:
    f.write(profile.to_json())
```

---

### 2. 漏洞画像模块 (`core/vuln_profile.py`)

**功能**：基于已知漏洞信息，提取多维度漏洞特征，构建漏洞画像。

**主要类**：
- `VulnerabilityProfile`：漏洞画像数据结构
- `VulnerabilityProfiler`：漏洞画像生成器
- `SourceFeature`：Source 特征（数据来源）
- `SinkFeature`：Sink 特征（危险点）
- `FlowFeature`：Flow 特征（污点传播路径）

**画像内容**：
```python
{
  "cve_id": "CVE-XXXX-XXXXX",
  "vuln_type": "command_injection",
  "source_features": {
    "description": "用户输入来源",
    "api": "request.args.get",
    "data_type": "user_input",
    "trust_level": "untrusted"
  },
  "sink_features": {
    "type": "code_execution",
    "function": "os.system",
    "description": "执行系统命令"
  },
  "flow_features": {
    "call_path": [...],
    "operations": ["拼接", "传递"],
    "sanitizers": []
  },
  "payload": "恶意 payload 示例",
  "impact": "影响描述"
}
```

**使用示例**：
```python
from core.vuln_profile import VulnerabilityProfiler, VulnEntry
from core.llm_client import create_llm_client, LLMConfig

# 创建漏洞条目
vuln_entry = VulnEntry(
    repo_name="NeMo",
    commit="2919fedf260120766d8c714749d5e18494dcf67b",
    cve_id="CVE-2025-23361",
    call_chain=[
        "nemo/collections/nlp/models/language_modeling/megatron_finetune_model.py#MegatronGPTFinetuneModel.on_pretrain_routine_start",
        "nemo/utils/model_utils.py#inject_model_parallel_rank",
        "torch/serialization.py#load"
    ]
)

# 创建 LLM 客户端
llm_config = LLMConfig(provider="hku")
llm_client = create_llm_client(llm_config)

# 创建漏洞画像生成器
profiler = VulnerabilityProfiler(
    llm_client=llm_client,
    output_dir="./vuln-profiles/"
)

# 生成漏洞画像
profile = profiler.generate_vulnerability_profile(
    vuln_entry=vuln_entry,
    repo_path="/path/to/repository"
)

# 保存画像
with open("vulnerability_profile.json", "w") as f:
    f.write(profile.to_json())
```

---

### 3. LLM 客户端模块 (`core/llm_client.py`)

**功能**：统一封装多个 LLM 服务商的 API 调用，支持自动重试和错误处理。

**支持的 LLM 提供商**：
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- DeepSeek
- HKU（香港大学内部服务）
- Mock（用于测试）

**主要类**：
- `BaseLLMClient`：LLM 客户端基类
- `OpenAIClient`：OpenAI 客户端
- `AnthropicClient`：Anthropic 客户端
- `DeepSeekClient`：DeepSeek 客户端
- `HKULLMClient`：HKU 客户端

**配置示例**：
```python
from core.llm_client import create_llm_client, LLMConfig

# 配置 OpenAI
config = LLMConfig(
    provider="openai",
    model="gpt-4",
    api_key="your-api-key",
    max_tokens=4096,
    temperature=0.7
)

# 创建客户端
client = create_llm_client(config)

# 调用 LLM
response = client.chat(
    messages=[
        {"role": "system", "content": "You are a security expert."},
        {"role": "user", "content": "Analyze this code..."}
    ]
)

print(response)
```

---

### 4. CodeQL 分析器模块 (`core/codeql_native.py`)

**功能**：封装 CodeQL CLI 工具，提供数据库创建、查询执行、结果解析等功能。

**主要类**：
- `CodeQLAnalyzer`：CodeQL 分析器
- `CodeQLConfig`：CodeQL 配置
- `CodeQLFinding`：检测结果数据结构

**使用示例**：
```python
from core.codeql_native import CodeQLAnalyzer, CodeQLConfig

# 创建分析器
config = CodeQLConfig(
    codeql_cli_path="/path/to/codeql",
    database_dir="./codeql_dbs/"
)
analyzer = CodeQLAnalyzer(config)

# 创建 CodeQL 数据库
success, db_path = analyzer.create_database(
    source_path="/path/to/repository",
    language="python",
    database_name="my_project"
)

# 运行查询
results = analyzer.run_query(
    database_path=db_path,
    query_path="./queries/dangerous_call.ql"
)

# 解析结果
for finding in results:
    print(f"发现问题：{finding.message}")
    print(f"位置：{finding.file_path}:{finding.start_line}")
```

---

### 5. 扫描器模块 (`core/scanner.py`)

**功能**：整合软件画像、漏洞画像和 CodeQL 分析，执行完整的漏洞检测流程。

**工作流程**：
1. 加载软件画像和漏洞画像
2. 使用 LLM 推理可能存在漏洞的模块
3. 生成针对性的 CodeQL 查询
4. 执行 CodeQL 扫描
5. 验证和过滤结果

---

## 完整工作流程

### 步骤 1：构建软件画像

```python
from core.software_profile import SoftwareProfiler
from core.llm_client import create_llm_client, LLMConfig

# 初始化
llm_client = create_llm_client(LLMConfig(provider="hku"))
profiler = SoftwareProfiler(llm_client=llm_client, output_dir="./repo-profiles/")

# 生成画像
profile = profiler.generate_profile(
    repo_path="/data/repos/NeMo",
    target_version="914c9ce7a54de813e04226dd44277fe159c07a75"
)
```

**输出**：`repo-profiles/NeMo/914c9ce7a54de813e04226dd44277fe159c07a75/software_profile.json`

---

### 步骤 2：构建漏洞画像

```python
from core.vuln_profile import VulnerabilityProfiler, VulnEntry

# 定义漏洞条目
vuln_entry = VulnEntry(
    repo_name="NeMo",
    commit="914c9ce7a54de813e04226dd44277fe159c07a75",
    cve_id="CVE-2025-23361",
    call_chain=[...]  # 漏洞调用链
)

# 生成漏洞画像
profiler = VulnerabilityProfiler(llm_client=llm_client, output_dir="./vuln-profiles/")
vuln_profile = profiler.generate_vulnerability_profile(
    vuln_entry=vuln_entry,
    repo_path="/data/repos/NeMo"
)
```

**输出**：`vuln-profiles/NeMo/914c9ce7a54de813e04226dd44277fe159c07a75/CVE-2025-23361/vulnerability_profile.json`

---

### 步骤 3：使用 LLM 推理相似模块

```python
from pathlib import Path
import json

# 加载画像
def load_profiles(repo_name, commit_hash, cve_id):
    software_path = Path(f"repo-profiles/{repo_name}/{commit_hash}/software_profile.json")
    vuln_path = Path(f"vuln-profiles/{repo_name}/{commit_hash}/{cve_id}/vulnerability_profile.json")
    
    with open(software_path) as f:
        software = json.load(f)
    with open(vuln_path) as f:
        vuln = json.load(f)
    
    return software, vuln

# LLM 推理
from core.llm_client import create_llm_client, LLMConfig

software, vuln = load_profiles("NeMo", "914c9ce7a54de813e04226dd44277fe159c07a75", "CVE-2025-23361")

llm_client = create_llm_client(LLMConfig(provider="hku", max_tokens=32768))

prompt = f"""
基于以下软件画像和漏洞画像，推理可能存在相似漏洞的模块：

软件画像：
{json.dumps(software, indent=2, ensure_ascii=False)}

漏洞画像：
{json.dumps(vuln, indent=2, ensure_ascii=False)}

请列出可能存在相似漏洞的模块，包括推理依据和置信度。
"""

response = llm_client.chat([
    {"role": "system", "content": "你是一个安全专家，擅长漏洞模式分析。"},
    {"role": "user", "content": prompt}
])

print(response)
```

**参考脚本**：`llm-reason-similar-module.py`

---

### 步骤 4：生成并执行 CodeQL 查询

```python
from core.codeql_native import CodeQLAnalyzer, CodeQLConfig

# 初始化 CodeQL 分析器
analyzer = CodeQLAnalyzer(CodeQLConfig(database_dir="./codeql_dbs/"))

# 基于漏洞画像生成 CodeQL 查询
sink_function = vuln["sink_features"]["function"]  # 如 "torch.load"

query = f"""
/**
 * @name Dangerous deserialization
 * @kind problem
 * @id python/dangerous-deserialize
 */

import python

from Call call, Attribute attr
where
  call.getFunc() = attr and
  attr.getName() = "load" and
  attr.getObject().(Name).getId() = "torch"
select call, "Potentially unsafe torch.load() call"
"""

# 保存查询
with open("generated_query.ql", "w") as f:
    f.write(query)

# 执行查询
results = analyzer.run_query(
    database_path="./codeql_dbs/NeMo-python-db/",
    query_path="generated_query.ql"
)

# 输出结果
for result in results:
    print(f"文件：{result.file_path}")
    print(f"行号：{result.start_line}")
    print(f"消息：{result.message}")
```

**参考脚本**：`codeql-search-similar-module.py`

---

### 步骤 5：验证漏洞可利用性

```python
# 使用 LLM 验证检测结果的可利用性
verification_prompt = f"""
检测到以下可疑代码：

文件：{result.file_path}
行号：{result.start_line}
代码：{code_snippet}

已知漏洞画像：
{json.dumps(vuln, indent=2, ensure_ascii=False)}

请分析：
1. 此代码是否真的存在漏洞？
2. 可利用性如何？
3. 与已知漏洞的相似度？
"""
