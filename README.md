# LLM-VulVariant：基于 LLM 的漏洞变种检测系统

## 项目简介

LLM-VulVariant 是一个利用大语言模型（LLM）和代码查询（CodeQL）技术，自动检测软件项目中潜在漏洞变种的智能系统。该系统通过构建软件画像和漏洞画像，使用 LLM **智能体（Agent）** 模式进行自主推理和探索，识别代码库中可能存在相似漏洞的模块。

### ✨ 核心特性

- 🤖 **智能体模式**：采用原生工具调用（Native Tool Calling），LLM 自主决策和探索
- 🔍 **深度分析**：模块分析器自动浏览代码库，理解架构和模块边界
- 🎯 **精准匹配**：基于漏洞画像特征，智能推理相似漏洞位置
- 🛡️ **多层验证**：结合 CodeQL 静态分析和 LLM 语义理解
- 🔧 **统一接口**：支持多个 LLM 提供商（OpenAI、DeepSeek、Anthropic 等）

### 📋 最近更新

**2026-01-10**：
- ✅ 重构模块分析器，采用智能体模式和原生工具调用
- ✅ 添加 `ModuleAnalyzerToolkit` 工具集（`list_folder`, `read_file`, `finalize`）
- ✅ 更新 `OpenAIClient` 支持工具调用（与 `DeepSeekClient` 保持一致）
- ✅ 修复对话压缩中的连续 assistant 消息错误
- ✅ 优化智能体对话管理和上下文压缩机制

---

## 系统架构

```
llm-vulvariant/
├── src/                       # 源代码目录
│   ├── llm/                   # LLM 客户端模块
│   │   ├── client.py          # 统一 LLM 客户端（支持工具调用）
│   │   └── config.py          # LLM 配置
│   ├── profiler/              # 画像生成器
│   │   ├── software/          # 软件画像
│   │   │   ├── profiler.py    # 软件画像生成器
│   │   │   ├── module_analyzer.py  # 模块分析智能体
│   │   │   ├── toolkit.py     # 模块分析工具集
│   │   │   └── prompts.py     # 提示词模板
│   │   └── vuln/              # 漏洞画像
│   │       └── profiler.py    # 漏洞画像生成器
│   ├── scanner/               # 漏洞扫描器
│   │   ├── agent/             # 智能体扫描
│   │   │   ├── finder.py      # 漏洞查找智能体
│   │   │   └── toolkit.py     # 扫描工具集
│   │   └── scanner.py         # 扫描协调器
│   ├── codeql/                # CodeQL 分析器
│   │   └── native.py          # CodeQL 封装
│   └── utils/                 # 工具模块
│       ├── agent_conversation.py  # 智能体对话管理
│       ├── llm_utils.py       # LLM 工具
│       └── git_utils.py       # Git 工具
├── test/                      # 测试用例
├── scripts/                   # 辅助脚本
├── config/                    # 配置文件
├── repo-profiles/             # 软件画像存储
├── vuln-profiles/             # 漏洞画像存储
└── scan-results/              # 扫描结果存储
```

---

## 🔧 核心技术特性

### 1. 原生工具调用（Native Tool Calling）

系统采用 OpenAI 标准的函数调用（Function Calling）接口，LLM 可以直接调用预定义的工具：

- **模块分析工具**：`list_folder`, `read_file`, `finalize`
- **漏洞扫描工具**：`search_code`, `read_file`, `run_codeql`, `report_finding`

### 2. 智能体模式（Agent Pattern）

- 自主决策：LLM 自行决定何时调用哪个工具
- 多轮交互：工具结果反馈给 LLM，支持多轮探索
- 对话压缩：自动压缩历史对话以控制上下文长度

### 3. 统一 LLM 客户端

所有 LLM 提供商通过统一接口访问，支持：
- 自动重试机制
- 错误处理
- 原生工具调用（OpenAI、DeepSeek）

---

## 🤖 智能体架构详解

### 工作原理

系统采用 **智能体-工具** 架构，LLM 作为推理核心，通过工具调用与代码库交互：

```
┌─────────────────────────────────────────────────────┐
│                   LLM Agent                         │
│  (GPT-4 / DeepSeek / Claude)                       │
└─────────────────┬───────────────────────────────────┘
                  │ Tool Calls
                  ▼
┌─────────────────────────────────────────────────────┐
│                   Toolkit                           │
│  • list_folder()  - 列出目录内容                    │
│  • read_file()    - 读取文件片段                    │
│  • finalize()     - 提交分析结果                    │
└─────────────────┬───────────────────────────────────┘
                  │ Execution
                  ▼
┌─────────────────────────────────────────────────────┐
│                Code Repository                      │
└─────────────────────────────────────────────────────┘
```

### 智能体循环

```python
while not done:
    # 1. LLM 决策
    message = llm_client.chat(
        messages=conversation_history,
        tools=toolkit.get_available_tools()
    )
    
    # 2. 执行工具
    if message.tool_calls:
        for tool_call in message.tool_calls:
            result = toolkit.execute_tool(
                tool_call.function.name,
                tool_call.function.arguments
            )
            conversation_history.append(result)
    
    # 3. 检查是否完成
    if tool_call.function.name == "finalize":
        done = True
```

### 对话压缩策略

为控制上下文长度，系统在每次迭代后自动压缩对话历史：

```python
# 原始对话（可能很长）
[
    {"role": "user", "content": "请分析模块..."},
    {"role": "assistant", "tool_calls": [...]},
    {"role": "tool", "content": "list_folder 结果..."},
    {"role": "assistant", "tool_calls": [...]},
    {"role": "tool", "content": "read_file 结果..."},
    # ... 更多工具调用
]

# 压缩后
[
    {"role": "user", "content": "请分析模块..."},
    {"role": "user", "content": "请继续分析。以下是上一轮的分析总结："},
    {"role": "assistant", "content": "{ 
        iteration_number: 1,
        summary: '分析了 src/ 目录',
        findings: ['发现核心模块在 src/core/'],
        next_steps: ['需要深入分析 src/core/module.py']
    }"},
    {"role": "user", "content": "请继续你的分析..."}
]
```

### 工具定义示例

```python
class ModuleAnalyzerToolkit:
    def get_available_tools(self) -> List[Dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_folder",
                    "description": "列出指定目录下的文件和子目录",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "相对于仓库根目录的路径"
                            }
                        },
                        "required": ["path"]
                    }
                }
            },
            # ... 其他工具定义
        ]
```

---

## 核心模块说明

### 1. 软件画像模块 (`src/profiler/software/`)

**功能**：分析目标软件仓库，构建全面的软件架构特征画像。使用**智能体模式（Agent Pattern）**和**原生工具调用**进行模块分析。

**主要类**：
- `SoftwareProfile`：软件画像数据结构
- `SoftwareProfiler`：软件画像生成器
- `ModuleAnalyzer`：模块分析智能体（使用原生工具调用）
- `ModuleAnalyzerToolkit`：模块分析工具集（list_folder, read_file, finalize）

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

**模块分析智能体架构**：

模块分析器采用智能体模式，通过原生工具调用自主探索代码库：

1. **工具定义**（`ModuleAnalyzerToolkit`）：
   - `list_folder(path)`：列出目录内容
   - `read_file(path, start_line, end_line)`：读取文件片段
   - `finalize(modules)`：提交最终模块列表

2. **智能体循环**（`ModuleAnalyzer._run_turn()`）：
   - LLM 通过 `llm_client.chat(messages, tools=...)` 决定调用哪些工具
   - 执行工具并将结果添加到对话历史
   - 循环直到 LLM 调用 `finalize` 工具

3. **对话压缩**（`ModuleAnalyzer._compress_iteration()`）：
   - 自动压缩历史对话以控制上下文长度
   - 保留关键分析步骤和发现

**使用示例**：
```python
from profiler.software import SoftwareProfiler
from llm.client import create_llm_client, LLMConfig

# 创建 LLM 客户端（需支持工具调用）
llm_config = LLMConfig(provider="openai", model="gpt-4")
llm_client = create_llm_client(llm_config)

# 创建软件画像生成器
profiler = SoftwareProfiler(
    config=None,
    llm_client=llm_client,
    output_dir="./repo-profiles/"
)

# 生成软件画像（包含智能体模块分析）
profile = profiler.generate_profile(
    repo_path="/path/to/repository",
    target_version="commit_hash",
    enable_deep_analysis=True  # 启用智能体深度分析
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

### 3. LLM 客户端模块 (`src/llm/client.py`)

**功能**：统一封装多个 LLM 服务商的 API 调用，支持自动重试、错误处理和**原生工具调用（Tool Calling）**。

**支持的 LLM 提供商**：
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- DeepSeek
- HKU（香港大学内部服务）
- Mock（用于测试）

**主要类**：
- `BaseLLMClient`：LLM 客户端基类
- `OpenAIClient`：OpenAI 客户端（**支持工具调用**）
- `AnthropicClient`：Anthropic 客户端
- `DeepSeekClient`：DeepSeek 客户端（**支持工具调用**）
- `HKULLMClient`：HKU 客户端

**配置示例**：
```python
from llm.client import create_llm_client, LLMConfig

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

# 基础聊天调用
response = client.chat(
    messages=[
        {"role": "system", "content": "You are a security expert."},
        {"role": "user", "content": "Analyze this code..."}
    ]
)

print(response.content)
```

**原生工具调用示例**：
```python
# 定义工具
tools = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "读取文件内容",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "文件路径"
                    }
                },
                "required": ["file_path"]
            }
        }
    }
]

# 调用 LLM 并获取工具调用
message = client.chat(
    messages=[{"role": "user", "content": "请读取 config.py 文件"}],
    tools=tools,
    tool_choice="auto"
)

# 处理工具调用
if message.tool_calls:
    for tool_call in message.tool_calls:
        function_name = tool_call.function.name
        arguments = json.loads(tool_call.function.arguments)
        # 执行工具...
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
