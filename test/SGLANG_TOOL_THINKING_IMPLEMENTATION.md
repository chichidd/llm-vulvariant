# SGLang Tool+Thinking 模式实现文档

## 概述

本文档记录了如何在 HKULLMClient 中实现 SGLang 后端的 Tool+Thinking 模式支持。HKU 使用 SGLang 来 host DeepSeek 模型（与 DeepSeekClient 的 deepseek-chat 相同模型），但 API 调用方式略有不同。

## 关键特性

### 1. 推理内容分离（Separate Reasoning）

**启用方式：**
```python
response = client.chat.completions.create(
    model="DeepSeek-V3.2",
    messages=[...],
    tools=[...],
    extra_body={
        "separate_reasoning": True,  # SGLang 特定参数
        "chat_template_kwargs": {
            "thinking": True  # 启用思考模式
        }
    }
)
```

**响应格式：**
- `reasoning_content`: 模型的推理过程（思考链）
- `content`: 最终回复内容
- `tool_calls`: 工具调用数组（如果需要调用工具）

### 2. 工具调用（Tool Calling）

**工具定义：**
```python
tools = [{
    "type": "function",
    "function": {
        "name": "get_current_weather",
        "description": "Get the current weather in a city",
        "parameters": {
            "type": "object",
            "properties": {
                "city": {"type": "string"},
                "state": {"type": "string"},
                "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
            },
            "required": ["city", "state"]
        }
    }
}]
```

**tool_choice 参数：**
- `"auto"`: 模型自动决定是否调用工具（推荐）
- `"required"`: 强制模型调用工具
- `"none"`: 禁止调用工具

### 3. 多轮对话历史管理

**规则：**
1. **相同问题的后续轮次**：保留 `reasoning_content`
   - 模型需要基于之前的推理来决定下一步
   - 例如：工具调用后的响应

2. **新问题**：清除历史 `reasoning_content`（使用 `clear_reasoning=True`）
   - 节省 token 使用
   - 避免旧推理干扰新问题

**示例：**
```python
# 第一轮：获取天气
response_1 = client.chat(
    messages=[{"role": "user", "content": "天气查询"}],
    tool_choice="auto",
    separate_reasoning=True
)

# 处理工具调用，保留 reasoning_content
messages.append({
    "role": "assistant", 
    "content": response_1.get("content"),
    "reasoning_content": response_1.get("reasoning"),  # 保留推理
    "tool_calls": response_1.get("tool_calls")
})

# 第二轮：新问题，清除历史推理
response_2 = client.chat(
    messages=messages,
    tool_choice="auto",
    separate_reasoning=True,
    clear_reasoning=True  # 清除历史推理
)
```

## API 对比

| 特性 | DeepSeek 原生 API | SGLang API |
|-----|------------------|-----------|
| 启用思考模式 | `extra_body={"thinking": {"type": "enabled"}}` | `extra_body={"separate_reasoning": True, "chat_template_kwargs": {"thinking": True}}` |
| 推理字段名 | `reasoning_content` | `reasoning_content` |
| 工具调用格式 | OpenAI 兼容 | OpenAI 兼容 |
| tool_choice 支持 | ✅ | ✅ |
| 清除推理参数 | `clear_reasoning=True` | `clear_reasoning=True` |

## 实现细节

### HKULLMClient._make_chat_request() 核心逻辑

```python
def _make_chat_request(self, messages: List[Dict[str, Any]], **kwargs) -> Any:
    # 1. 处理 clear_reasoning 参数
    clear_reasoning = kwargs.pop('clear_reasoning', False)
    if clear_reasoning:
        messages = [
            {k: v for k, v in msg.items() if k != 'reasoning_content'}
            for msg in messages
        ]
    
    # 2. 处理 separate_reasoning 参数（SGLang 特定）
    separate_reasoning = kwargs.pop('separate_reasoning', False)
    
    # 3. 构建请求参数
    request_kwargs = {
        "model": self.config.model,
        "messages": messages,
        "temperature": kwargs.get('temperature', self.config.temperature),
        "max_tokens": kwargs.get('max_tokens', self.config.max_tokens or 2048),
    }
    
    # 4. 添加工具定义
    if 'tools' in kwargs:
        request_kwargs['tools'] = kwargs['tools']
        request_kwargs['tool_choice'] = kwargs.get('tool_choice', 'auto')
    
    # 5. 配置 extra_body（SGLang 特定）
    if self.config.enable_thinking or separate_reasoning:
        request_kwargs['extra_body'] = {}
        if separate_reasoning:
            request_kwargs['extra_body']['separate_reasoning'] = True
        if self.config.enable_thinking:
            request_kwargs['extra_body']['chat_template_kwargs'] = {
                'thinking': True
            }
    
    # 6. 调用 API
    response = self.client.chat.completions.create(**request_kwargs)
    
    # 7. 处理响应
    choice = response.choices[0]
    
    # 如果有工具调用
    if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
        return {
            'reasoning': getattr(choice.message, 'reasoning_content', ''),
            'content': choice.message.content,
            'tool_calls': [
                {
                    'id': tc.id,
                    'type': tc.type,
                    'function': {
                        'name': tc.function.name,
                        'arguments': tc.function.arguments
                    }
                }
                for tc in choice.message.tool_calls
            ]
        }
    
    # 如果是最终答案
    if separate_reasoning and hasattr(choice.message, 'reasoning_content'):
        return {
            'reasoning': choice.message.reasoning_content,
            'content': choice.message.content
        }
    
    return choice.message.content
```

## 测试用例

测试函数：`test_multi_turn_tool_calling_with_thinking()`

**场景：** 三轮对话，涉及两次工具调用
1. 获取波士顿天气（摄氏度）
2. 转换温度到华氏度
3. 提供最终答案

**测试结果：**
```
============================================================
Testing Multi-Turn Tool Calling with Thinking (HKU/SGLang)
============================================================

[ROUND 1] Initial user request
User: What's the weather like in Boston today? Please use the get_current_weather tool...

[RESPONSE 1] LLM decides to call get_current_weather
Reasoning: We are going to use two tools as instructed.
 First, get the weather in Boston in Celsius.
 Then, convert that temperature to Fahrenheit.
Content: None
Tool Calls: 1 call(s)
  Tool Call #1: get_current_weather(Boston, MA, celsius)
  Result: 22°C

[ROUND 2] LLM should now convert temperature to Fahrenheit
[RESPONSE 2]
Reasoning: We have the value 22, from_unit: celsius, to_unit: fahrenheit.
 We'll use the convert_temperature tool.
Content: None
Tool Calls: 1 call(s)
  Tool Call #1: convert_temperature(celsius → fahrenheit, 22)
  Result: 71.6°F

[ROUND 3] LLM should now provide final answer
[RESPONSE 3] Final Answer
Reasoning: Based on the information from both tools:
**Current Weather in Boston, MA:**
- Temperature: 22°C (71.6°F)
Content: None

============================================================
[SUMMARY]
Total rounds: 3
Tool calls executed: 2
Messages in history: 6
```

## 关键区别总结

### SGLang vs DeepSeek 原生 API

**相同点：**
- ✅ 都使用 `reasoning_content` 字段
- ✅ 都支持 OpenAI 兼容的工具调用格式
- ✅ 都支持 `clear_reasoning` 参数
- ✅ 都支持 `tool_choice` 参数

**不同点：**

| 特性 | DeepSeek 原生 | SGLang |
|-----|--------------|--------|
| 启用推理分离 | `thinking: {type: "enabled"}` | `separate_reasoning: True` |
| 聊天模板配置 | 不需要 | `chat_template_kwargs: {thinking: True}` |
| extra_body 结构 | 一层配置 | 两层配置（分离 + 模板） |

## 最佳实践

1. **默认使用 `tool_choice="auto"`**
   - 让模型自动决定是否需要工具
   - 比 `"required"` 更灵活

2. **合理使用 `clear_reasoning`**
   - 相同问题的多轮对话：保留推理（`False`）
   - 新问题：清除推理（`True`）

3. **响应处理**
   - 检查是否有 `tool_calls`
   - 处理 dict 和 string 两种响应格式
   - 提取 `reasoning_content` 和 `content`

4. **消息历史管理**
   - 保存完整的 assistant 消息（包括 reasoning_content）
   - 工具调用结果作为 tool 角色消息
   - 新问题时清除历史推理内容

## 参考资料

- [SGLang Separate Reasoning 文档](https://docs.sglang.io/advanced_features/separate_reasoning.html)
- [DeepSeek API 文档](https://api-docs.deepseek.com/guides/thinking_mode)
- [OpenAI Tool Calling 规范](https://platform.openai.com/docs/guides/function-calling)
