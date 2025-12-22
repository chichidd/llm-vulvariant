# DeepSeek Tool+Thinking Mode Implementation

## Overview

实现了对 DeepSeek API 的 Tool+Thinking 模式的完整支持，基于官方文档：
https://api-docs.deepseek.com/guides/thinking_mode

## 核心改进

### 1. LLM Client 更新 (`core/llm_client.py`)

#### 新增参数支持

在 `DeepSeekClient._make_chat_request()` 方法中新增：

- **`clear_reasoning`**: 清除历史消息中的 `reasoning_content`（开始新问题时使用）
- **`separate_reasoning`**: 返回分离的 reasoning 和 content（无 tool_calls 时）

#### 关键实现

```python
# 1. 清除历史 reasoning_content（新轮次开始）
if kwargs.get("clear_reasoning", False):
    messages = [
        {k: v for k, v in msg.items() if k != 'reasoning_content'} if isinstance(msg, dict) else msg
        for msg in messages
    ]

# 2. 启用 thinking 模式
if self.config.enable_thinking:
    request_params["extra_body"] = {"thinking": {"type": "enabled"}}

# 3. 返回包含 reasoning 的响应
if hasattr(message, 'tool_calls') and message.tool_calls:
    result = {
        "content": message.content,
        "tool_calls": [...],
        "reasoning": message.reasoning_content  # 关键！
    }
```

### 2. 测试代码更新 (`test/test-llm.py`)

#### 新增测试函数

`test_deepseek_tool_calling_with_thinking()` - 完整测试 Tool+Thinking 模式

测试场景：
- **Turn 1**: "How's the weather in Hangzhou tomorrow?"
  - Sub-turn 1.1: 调用 `get_date` 工具
  - Sub-turn 1.2: 调用 `get_weather` 工具
  - Sub-turn 1.3: 提供最终答案
- **Turn 2**: "What clothes should I wear for that weather?"
  - Sub-turn 2.1: 基于上下文直接回答

#### 关键实现模式

```python
# 1. 构建包含 reasoning_content 的 assistant 消息
assistant_msg = {
    "role": "assistant",
    "content": response.get('content'),
    "tool_calls": response.get('tool_calls'),  # 如有
    "reasoning_content": response.get('reasoning')  # 必须包含！
}
messages.append(assistant_msg)

# 2. 添加工具执行结果
messages.append({
    "role": "tool",
    "tool_call_id": tc['id'],
    "content": tool_result
})

# 3. 开始新问题时清除历史 reasoning
response = llm_client.chat(
    messages=messages,
    tools=tools,
    clear_reasoning=True  # 清除历史 reasoning_content
)
```

## API 使用要点

### Tool+Thinking 模式的多轮对话规则

根据 DeepSeek 文档，在 Tool+Thinking 模式下：

1. **同一问题的子轮次**：必须将 `reasoning_content` 传回 API
   - 这允许模型延续之前的推理思路
   - Assistant 消息必须包含 `content`, `tool_calls`, `reasoning_content`

2. **新问题开始时**：应清除历史 `reasoning_content`
   - 使用 `clear_reasoning=True` 参数
   - 节省网络带宽
   - API 会忽略新问题中的历史 reasoning

3. **启用 thinking 模式**：
   ```python
   # 方法1：使用 deepseek-reasoner 模型
   llm_config.model = 'deepseek-reasoner'
   
   # 方法2：使用 thinking 参数
   llm_config.enable_thinking = True
   # 会在请求中添加 extra_body={"thinking": {"type": "enabled"}}
   ```

## 运行测试

```bash
# 激活 conda 环境
source /mnt/raid/home/dongtian/miniconda3/bin/activate dsocr

# 运行 Tool+Thinking 模式测试
cd /home/dongtian/vuln/llm-vulvariant
PYTHONPATH=/home/dongtian/vuln/llm-vulvariant:$PYTHONPATH python test/test-llm.py thinking

# 运行所有测试
PYTHONPATH=/home/dongtian/vuln/llm-vulvariant:$PYTHONPATH python test/test-llm.py
```

## 测试输出示例

```
============================================================
Testing DeepSeek Tool+Thinking Mode (Multi-Turn)
============================================================

[TURN 1] User asks about weather tomorrow
User: How's the weather in Hangzhou tomorrow?

[Turn 1.1] Calling LLM...
Reasoning: I need to get tomorrow's date first...
Tool Calls: 1 call(s)
  Tool Call #1:
    Function: get_date
    Arguments: {}
    Result: 2025-12-22

[Turn 1.2] Calling LLM...
Reasoning: Tomorrow is 2025-12-23. Now I can get the weather...
Tool Calls: 1 call(s)
  Tool Call #1:
    Function: get_weather
    Arguments: {"location": "Hangzhou", "date": "2025-12-23"}
    Result: Cloudy 7~13°C

[Turn 1.3] Calling LLM...
Response: Tomorrow in Hangzhou will be cloudy with temperatures...
[Turn 1.3] Final answer received!

[TURN 2] User asks a new question
User: What clothes should I wear for that weather?
[INFO] Clearing reasoning_content from history messages...

[Turn 2.1] Calling LLM...
Response: For cloudy weather with 7-13°C, I recommend...
[Turn 2.1] Final answer received!

[SUMMARY]
Total turns: 2
Turn 1 sub-turns: 3
Turn 2 sub-turns: 1
Total messages: 8
```

## 响应格式

### 有 tool_calls 时
```python
{
    "content": str,              # 可能为空
    "tool_calls": [              # 工具调用列表
        {
            "id": str,
            "type": "function",
            "function": {
                "name": str,
                "arguments": str  # JSON 字符串
            }
        }
    ],
    "reasoning": str             # thinking 内容（如果启用）
}
```

### 无 tool_calls 时（最终答案）
```python
# 默认：合并的字符串
"<think>推理过程</think>最终答案"

# 使用 separate_reasoning=True：
{
    "reasoning": str,
    "content": str
}
```

## 重要注意事项

1. **reasoning_content 是必需的**：在 tool calling 的多轮对话中，必须将 `reasoning_content` 包含在 assistant 消息中，否则 API 会返回 400 错误

2. **消息结构**：直接使用 `response.choices[0].message` 对象或手动构建包含所有字段的字典

3. **工具结果**：工具执行结果必须以 `tool` role 消息添加，包含 `tool_call_id`

4. **带宽优化**：新问题开始时使用 `clear_reasoning=True` 清除历史推理内容

## 与 SGLang/HKU 部署的区别

| 特性 | DeepSeek Native | SGLang/HKU |
|------|-----------------|------------|
| API Endpoint | api.deepseek.com | hkucvm.dynv6.net |
| Thinking 启用 | `extra_body={"thinking": {"type": "enabled"}}` | `extra_body={"chat_template_kwargs": {"thinking": True}}` |
| Reasoning 字段 | `reasoning_content` | `reasoning_content` |
| Tool Choice 默认 | `auto` | `auto` |
| 清除 Reasoning | 手动清除或 `clear_reasoning=True` | 不需要 |

## 参考文档

- DeepSeek API 文档: https://api-docs.deepseek.com/
- Thinking Mode 指南: https://api-docs.deepseek.com/guides/thinking_mode
- Tool Calls 文档: https://api-docs.deepseek.com/guides/tool_calls
