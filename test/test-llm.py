from src.llm import create_llm_client, LLMConfig

import json


"""
Test Suite for LLM Client

This test suite includes:
1. test_basic_chat(): Test basic chat functionality without tools
2. test_multi_turn_tool_calling_with_thinking(): Test multi-turn tool calling with thinking/reasoning (HKU/SGLang deployed DeepSeek)
3. test_deepseek_tool_calling_with_thinking(): Test DeepSeek native Tool+Thinking mode (multi-turn)
4. test_deepseek_tool_calling(): Test DeepSeek tool calling functionality (basic)

DeepSeek Tool+Thinking Mode:
- Based on DeepSeek API documentation: https://api-docs.deepseek.com/guides/thinking_mode
- In same question's sub-turns, reasoning_content must be passed back to API
- When starting new question, use clear_reasoning=True to remove historical reasoning_content
- Assistant messages must contain: content, tool_calls (if any), reasoning_content (if any)
- The model can perform multiple rounds of thinking + tool calls before final answer

Multi-Turn Tool Calling with Thinking Feature:
- Tests realistic scenario with multiple tool calls in sequence
- Demonstrates proper handling of reasoning_content in assistant messages
- Shows how to maintain conversation history with tool calls
- Uses separate_reasoning=True to get thinking process separately
- Simulates: weather query (Celsius) -> temperature conversion (Fahrenheit) -> final answer

Example Workflow (DeepSeek Tool+Thinking):
    Turn 1: User asks "How's the weather in Hangzhou tomorrow?"
      Sub-turn 1.1: Model thinks -> calls get_date tool -> gets "2025-12-22"
      Sub-turn 1.2: Model thinks -> calls get_weather tool -> gets "Cloudy 7~13°C"
      Sub-turn 1.3: Model thinks -> provides final answer
    Turn 2: User asks "What clothes should I wear?"
      Sub-turn 2.1: Model thinks (using previous context) -> provides answer

Key Points:
- Always include reasoning_content in assistant messages when present
- Use tool_choice: "auto" for natural tool selection, "none" to disable, "required" to force
- Message history must include tool role messages with tool_call_id
- Use clear_reasoning=True when starting a new question/turn
- SGLang (via HKU deployment) follows OpenAI/DeepSeek API format for tool calling
"""


def test_basic_chat():
    """测试基本的聊天功能"""
    print("=" * 60)
    print("Testing basic chat functionality")
    print("=" * 60)
    
    llm_config = LLMConfig(provider='lab')
    print(llm_config)
    llm_client = create_llm_client(llm_config)
    
    prompt = "请解释以下Python代码的功能：\n\n```python\ndef add(a, b):\n    return a + b\n```"
    
    response = llm_client.chat([{"role": "user", "content": prompt}])
    
    print("LLM Response:")
    print(response)
    print()

    print('' + '=' * 60)
    llm_config = LLMConfig(provider='lab')
    llm_config.enable_thinking = False
    print(llm_config)
    llm_client = create_llm_client(llm_config)
    
    prompt = "请解释以下Python代码的功能：\n\n```python\ndef add(a, b):\n    return a + b\n```"
    
    response = llm_client.chat([{"role": "user", "content": prompt}])
    
    print("LLM Response:")
    print(response)
    print()

    print('' + '=' * 60)
    llm_config = LLMConfig(provider='deepseek')
    llm_config.model = 'deepseek-chat'
    print(llm_config)
    llm_client = create_llm_client(llm_config)
    
    prompt = "请解释以下Python代码的功能：\n\n```python\ndef add(a, b):\n    return a + b\n```"
    
    response = llm_client.chat([{"role": "user", "content": prompt}])
    
    print("LLM Response:")
    print(response)
    print()
    print('' + '=' * 60)
    llm_config = LLMConfig(provider='deepseek')
    llm_config.model = 'deepseek-reasoner'
    print(llm_config)
    llm_client = create_llm_client(llm_config)
    
    prompt = "请解释以下Python代码的功能：\n\n```python\ndef add(a, b):\n    return a + b\n```"
    
    response = llm_client.chat([{"role": "user", "content": prompt}])
    
    print("LLM Response:")
    print(response)
    print()


def test_multi_turn_tool_calling_with_thinking():
    """测试多轮工具调用和thinking功能 (LAB/SGLang部署的DeepSeek)
    
    这个测试展示了：
    1. 使用 separate_reasoning=True 分离思考内容
    2. 多轮工具调用（模拟真实场景：天气查询 + 单位转换）
    3. reasoning_content 的正确处理
    4. assistant message 中包含 reasoning_content 和 tool_calls
    5. 使用 clear_reasoning 在新问题时清除历史推理
    """
    print("=" * 60)
    print("Testing Multi-Turn Tool Calling with Thinking (HKU/SGLang)")
    print("=" * 60)
    
    # 创建HKU LLM客户端 (SGLang部署的 DeepSeek 模型)
    llm_config = LLMConfig(provider='lab')
    llm_config.enable_thinking = True  # 启用 thinking 模式
    print(f"\n[CONFIG] {llm_config}\n")
    llm_client = create_llm_client(llm_config)
    
    # 定义工具 - 包含天气查询和温度转换
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_current_weather",
                "description": "Get the current weather in a given location",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {
                            "type": "string",
                            "description": "The city to find the weather for, e.g. 'San Francisco'",
                        },
                        "state": {
                            "type": "string",
                            "description": "the two-letter abbreviation for the state that the city is in, e.g. 'CA' which would mean 'California'",
                        },
                        "unit": {
                            "type": "string",
                            "description": "The unit to fetch the temperature in",
                            "enum": ["celsius", "fahrenheit"],
                        },
                    },
                    "required": ["city", "state", "unit"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "convert_temperature",
                "description": "Convert temperature between Celsius and Fahrenheit",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "number",
                            "description": "The temperature value to convert",
                        },
                        "from_unit": {
                            "type": "string",
                            "description": "The unit to convert from",
                            "enum": ["celsius", "fahrenheit"],
                        },
                        "to_unit": {
                            "type": "string",
                            "description": "The unit to convert to",
                            "enum": ["celsius", "fahrenheit"],
                        },
                    },
                    "required": ["value", "from_unit", "to_unit"],
                },
            },
        }
    ]
    
    # 初始化对话历史
    messages = [
        {
            "role": "user",
            "content": "What's the weather like in Boston today? Please use the get_current_weather tool to get it in Celsius first, then use the convert_temperature tool to convert it to Fahrenheit. Use both tools separately.",
        }
    ]
    
    print("[ROUND 1] Initial user request")
    print(f"User: {messages[0]['content']}\n")
    
    # ========== 第一轮：获取天气 ==========
    print("[ROUND 1] Calling LLM with tool definitions...")
    
    response = llm_client.chat(
        messages=messages,
        tools=tools,
        tool_choice="auto",  # 让模型自动决定是否使用工具
        separate_reasoning=True,  # SGLang 特性：分离推理内容
        temperature=0.7,
        max_tokens=2048
    )
    
    print("\n[RESPONSE 1] LLM decides to call get_current_weather")
    if isinstance(response, dict):
        reasoning = response.get('reasoning', '')
        content = response.get('content', '')
        tool_calls = response.get('tool_calls', [])
        
        print(f"Reasoning: {reasoning[:200]}..." if len(reasoning) > 200 else f"Reasoning: {reasoning}")
        print(f"Content: {content}")
        print(f"Tool Calls: {len(tool_calls)} call(s)")
        
        if tool_calls:
            for i, tc in enumerate(tool_calls, 1):
                print(f"\n  Tool Call #{i}:")
                print(f"    ID: {tc['id']}")
                print(f"    Function: {tc['function']['name']}")
                print(f"    Arguments: {tc['function']['arguments']}")
            
            # 构建 assistant message (关键：包含 reasoning_content)
            assistant_msg = {
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls
            }
            # 如果有 reasoning，添加 reasoning_content 字段
            if reasoning:
                assistant_msg['reasoning_content'] = reasoning
            
            messages.append(assistant_msg)
            
            # 模拟工具执行 - get_current_weather
            tool_call_1 = tool_calls[0]
            args_1 = json.loads(tool_call_1['function']['arguments'])
            mock_weather_result = "22"  # 22°C in Boston
            print(f"\n[TOOL EXECUTION 1] {tool_call_1['function']['name']}({args_1})")
            print(f"Result: {mock_weather_result}°C")
            
            # 添加工具结果到消息历史
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call_1['id'],
                "content": mock_weather_result
            })
    else:
        print(f"Unexpected response type: {type(response)}")
        print(response)
        return
    
    # ========== 第二轮：转换温度 ==========
    print("\n" + "=" * 60)
    print("[ROUND 2] LLM should now convert temperature to Fahrenheit")
    
    # 添加一个明确的用户消息要求转换
    messages.append({
        "role": "user",
        "content": "Now please use the convert_temperature tool to convert 22°C to Fahrenheit."
    })
    
    response_2 = llm_client.chat(
        messages=messages,
        tools=tools,
        tool_choice="auto",
        separate_reasoning=True,  # 继续分离推理内容
        temperature=0.7,
        max_tokens=2048
    )
    
    print("\n[RESPONSE 2]")
    if isinstance(response_2, dict):
        reasoning_2 = response_2.get('reasoning', '')
        content_2 = response_2.get('content', '')
        tool_calls_2 = response_2.get('tool_calls', [])
        
        print(f"Reasoning: {reasoning_2[:200]}..." if len(reasoning_2) > 200 else f"Reasoning: {reasoning_2}")
        print(f"Content: {content_2}")
        print(f"Tool Calls: {len(tool_calls_2)} call(s)")
        
        if tool_calls_2:
            print("LLM decides to call convert_temperature")
            for i, tc in enumerate(tool_calls_2, 1):
                print(f"\n  Tool Call #{i}:")
                print(f"    ID: {tc['id']}")
                print(f"    Function: {tc['function']['name']}")
                print(f"    Arguments: {tc['function']['arguments']}")
            
            # 构建 assistant message
            assistant_msg_2 = {
                "role": "assistant",
                "content": content_2,
                "tool_calls": tool_calls_2
            }
            if reasoning_2:
                assistant_msg_2['reasoning_content'] = reasoning_2
            
            messages.append(assistant_msg_2)
            
            # 模拟工具执行 - convert_temperature
            tool_call_2 = tool_calls_2[0]
            args_2 = json.loads(tool_call_2['function']['arguments'])
            # 22°C = 71.6°F
            mock_converted_temp = "71.6"
            print(f"\n[TOOL EXECUTION 2] {tool_call_2['function']['name']}({args_2})")
            print(f"Result: {mock_converted_temp}°F")
            
            # 添加工具结果
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call_2['id'],
                "content": mock_converted_temp
            })
            
            # ========== 第三轮：给出最终答案 ==========
            print("\n" + "=" * 60)
            print("[ROUND 3] LLM should now provide final answer")
            
            response_3 = llm_client.chat(
                messages=messages,
                tool_choice="auto",  # 可能不需要工具或者需要更多工具
                separate_reasoning=True,  # 继续分离推理内容
                temperature=0.7,
                max_tokens=2048
            )
            
            print("\n[RESPONSE 3] Final Answer")
            if isinstance(response_3, dict):
                reasoning_3 = response_3.get('reasoning', '')
                content_3 = response_3.get('content', '')
                
                print(f"Reasoning: {reasoning_3[:200]}..." if len(reasoning_3) > 200 else f"Reasoning: {reasoning_3}")
                print(f"Content: {content_3}")
            else:
                print(f"Content: {response_3}")
            
            print("\n" + "=" * 60)
            print("Multi-turn tool calling with thinking test completed!")
            print("=" * 60)
            print("\n[SUMMARY]")
            print(f"Total rounds: 3")
            print(f"Tool calls executed: 2 (get_current_weather, convert_temperature)")
            print(f"Messages in history: {len(messages)}")
        else:
            # LLM 可能直接完成了转换（有些模型会在思考中计算）
            print("LLM provides answer without additional tool calls")
            print("This is acceptable - the model might have done the conversion in reasoning")
            
            print("\n" + "=" * 60)
            print("Multi-turn tool calling with thinking test completed!")
            print("=" * 60)
            print("\n[SUMMARY]")
            print(f"Total rounds: 2")
            print(f"Tool calls executed: 1 (get_current_weather)")
            print(f"Messages in history: {len(messages)}")
            print("Note: Model completed task without explicit convert_temperature call")
    else:
        # 可能LLM直接给出了最终答案（字符串形式）
        print(f"Final answer (no more tool calls): {response_2}")
        print("\n" + "=" * 60)
        print("Multi-turn tool calling test completed!")
        print("=" * 60)
        print("\n[SUMMARY]")
        print(f"Total rounds: 2")
        print(f"Tool calls executed: 1")
        print(f"Messages in history: {len(messages)}")


def test_deepseek_tool_calling_with_thinking():
    """测试DeepSeek的Tool+Thinking模式（多轮工具调用）
    
    根据 DeepSeek API 文档 (https://api-docs.deepseek.com/guides/thinking_mode):
    1. 在同一个问题的多个子轮次中，需要将 reasoning_content 传回 API
    2. 当开始新问题时，应清除历史消息中的 reasoning_content
    3. Assistant 消息需要包含 content, tool_calls (如有), reasoning_content (如有)
    """
    print("=" * 60)
    print("Testing DeepSeek Tool+Thinking Mode (Multi-Turn)")
    print("=" * 60)
    
    # 创建DeepSeek客户端，启用thinking模式
    llm_config = LLMConfig(provider='deepseek')
    llm_config.model = 'deepseek-chat'
    llm_config.enable_thinking = True  # 启用thinking模式
    print(f"\n[CONFIG] {llm_config}\n")
    llm_client = create_llm_client(llm_config)
    
    # 定义工具
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_date",
                "description": "Get the current date",
                "parameters": {
                    "type": "object",
                    "properties": {}
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather of a location, the user should supply the location and date.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {
                            "type": "string",
                            "description": "The city name",
                        },
                        "date": {
                            "type": "string",
                            "description": "The date in format YYYY-mm-dd",
                        }
                    },
                    "required": ["location", "date"],
                },
            },
        }
    ]
    
    # 模拟工具函数
    def get_date_mock():
        return "2025-12-22"
    
    def get_weather_mock(location, date):
        return "Cloudy 7~13°C"
    
    TOOL_CALL_MAP = {
        "get_date": get_date_mock,
        "get_weather": get_weather_mock,
    }
    
    # ========== Turn 1: 第一个问题 ==========
    print("[TURN 1] User asks about weather tomorrow")
    messages = [
        {
            "role": "user",
            "content": "How's the weather in Hangzhou tomorrow?"
        }
    ]
    print(f"User: {messages[0]['content']}\n")
    
    # Turn 1 的多个子轮次
    turn = 1
    sub_turn = 1
    turn1_sub_turns = 0
    
    while True:
        print(f"[Turn {turn}.{sub_turn}] Calling LLM...")
        
        response = llm_client.chat(
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_tokens=2048
        )
        
        # 将完整的 message 对象添加到历史中
        # response 可能是字典（有 tool_calls）或字符串（最终答案）
        if isinstance(response, dict):
            # 构建 assistant message
            assistant_msg = {
                "role": "assistant",
                "content": response.get('content'),
            }
            
            # 添加 tool_calls（如有）
            if response.get('tool_calls'):
                assistant_msg['tool_calls'] = response['tool_calls']
            
            # 添加 reasoning_content（如有）- 这是关键！
            if response.get('reasoning'):
                assistant_msg['reasoning_content'] = response['reasoning']
            
            messages.append(assistant_msg)
            
            # 打印响应
            reasoning = response.get('reasoning', '')
            content = response.get('content', '')
            tool_calls = response.get('tool_calls', [])
            
            print(f"Reasoning: {reasoning[:150]}..." if len(reasoning) > 150 else f"Reasoning: {reasoning}")
            print(f"Content: {content}")
            print(f"Tool Calls: {len(tool_calls)} call(s)")
            
            # 如果没有工具调用，说明得到了最终答案
            if not tool_calls:
                print(f"\n[Turn {turn}.{sub_turn}] Final answer received!\n")
                break
            
            # 执行工具调用
            for i, tc in enumerate(tool_calls, 1):
                print(f"\n  Tool Call #{i}:")
                print(f"    Function: {tc['function']['name']}")
                print(f"    Arguments: {tc['function']['arguments']}")
                
                # 执行工具
                tool_function = TOOL_CALL_MAP[tc['function']['name']]
                args = json.loads(tc['function']['arguments'])
                tool_result = tool_function(**args) if args else tool_function()
                print(f"    Result: {tool_result}")
                
                # 添加工具结果到消息历史
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc['id'],
                    "content": tool_result
                })
            
            sub_turn += 1
            print()
        elif isinstance(response, str):
            # 返回字符串说明是最终答案（合并了 thinking 和 content）
            print(f"Response (merged thinking+content): {response[:200]}..." if len(response) > 200 else f"Response: {response}")
            messages.append({
                "role": "assistant",
                "content": response
            })
            print(f"\n[Turn {turn}.{sub_turn}] Final answer received (as string)!\n")
            turn1_sub_turns = sub_turn
            break
        else:
            print(f"Unexpected response type: {type(response)}")
            turn1_sub_turns = sub_turn - 1
            break
    
    # ========== Turn 2: 第二个问题 ==========
    print("=" * 60)
    print("[TURN 2] User asks a new question")
    
    # 添加新的用户消息
    messages.append({
        "role": "user",
        "content": "What clothes should I wear for that weather?"
    })
    print(f"User: {messages[-1]['content']}\n")
    
    # 开始新问题时，清除历史消息中的 reasoning_content
    # 根据 DeepSeek 文档建议，这样可以节省网络带宽
    print("[INFO] Clearing reasoning_content from history messages...")
    
    turn = 2
    sub_turn = 1
    turn2_sub_turns = 0
    
    while True:
        print(f"[Turn {turn}.{sub_turn}] Calling LLM...")
        
        # 使用 clear_reasoning=True 参数清除历史 reasoning_content
        response = llm_client.chat(
            messages=messages,
            tools=tools,
            tool_choice="auto",
            clear_reasoning=True,  # 新问题开始时清除历史 reasoning
            max_tokens=2048
        )
        
        if isinstance(response, dict):
            # 构建 assistant message
            assistant_msg = {
                "role": "assistant",
                "content": response.get('content'),
            }
            
            if response.get('tool_calls'):
                assistant_msg['tool_calls'] = response['tool_calls']
            
            if response.get('reasoning'):
                assistant_msg['reasoning_content'] = response['reasoning']
            
            messages.append(assistant_msg)
            
            # 打印响应
            reasoning = response.get('reasoning', '')
            content = response.get('content', '')
            tool_calls = response.get('tool_calls', [])
            
            print(f"Reasoning: {reasoning[:150]}..." if len(reasoning) > 150 else f"Reasoning: {reasoning}")
            print(f"Content: {content}")
            print(f"Tool Calls: {len(tool_calls)} call(s)")
            
            # 如果没有工具调用，说明得到了最终答案
            if not tool_calls:
                print(f"\n[Turn {turn}.{sub_turn}] Final answer received!\n")
                break
            
            # 执行工具调用
            for tc in tool_calls:
                tool_function = TOOL_CALL_MAP[tc['function']['name']]
                args = json.loads(tc['function']['arguments'])
                tool_result = tool_function(**args) if args else tool_function()
                
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc['id'],
                    "content": tool_result
                })
            
            sub_turn += 1
            print()
        elif isinstance(response, str):
            # 返回字符串说明是最终答案
            print(f"Response (merged thinking+content): {response[:200]}..." if len(response) > 200 else f"Response: {response}")
            messages.append({
                "role": "assistant",
                "content": response
            })
            print(f"\n[Turn {turn}.{sub_turn}] Final answer received (as string)!\n")
            turn2_sub_turns = sub_turn
            break
        else:
            print(f"Unexpected response type: {type(response)}")
            turn2_sub_turns = sub_turn - 1
            break
    
    print("=" * 60)
    print("DeepSeek Tool+Thinking mode test completed!")
    print("=" * 60)
    print(f"\n[SUMMARY]")
    print(f"Total turns: 2")
    print(f"Turn 1 sub-turns: {turn1_sub_turns}")
    print(f"Turn 2 sub-turns: {turn2_sub_turns}")
    print(f"Total messages: {len(messages)}")


def test_deepseek_tool_calling():
    """测试DeepSeek工具调用功能"""
    print("=" * 60)
    print("Testing DeepSeek Tool Calling")
    print("=" * 60)
    
    # 创建DeepSeek客户端
    llm_config = LLMConfig(provider='deepseek')
    llm_config.model = 'deepseek-chat'
    llm_client = create_llm_client(llm_config)
    
    # 定义工具
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather of a location, the user should supply a location first.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {
                            "type": "string",
                            "description": "The city and state, e.g. San Francisco, CA",
                        }
                    },
                    "required": ["location"],
                },
            },
        }
    ]
    
    # 准备消息
    messages = [
        {
            "role": "user",
            "content": "How's the weather in Hangzhou, Zhejiang? Please use the tool to check.",
        }
    ]
    
    print("\n[REQUEST]")
    print(f"Message: {messages[0]['content']}")
    print(f"Tools: {tools[0]['function']['name']}")
    
    try:
        # 第一次调用 - 获取tool_calls
        response = llm_client.chat(
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_tokens=1024
        )
        
        print("\n[RESPONSE 1 - Tool Call Request]")
        if isinstance(response, dict):
            print("✓ Tool calling triggered!")
            print(f"\nContent: {response.get('content')}")
            
            if response.get('tool_calls'):
                print(f"\nTool Calls ({len(response['tool_calls'])} total):")
                for i, tc in enumerate(response['tool_calls'], 1):
                    print(f"  [{i}] {tc['function']['name']}")
                    print(f"      Arguments: {tc['function']['arguments']}")
                    try:
                        args = json.loads(tc['function']['arguments'])
                        print(f"      Parsed: {args}")
                        
                        # 模拟工具执行
                        print(f"\n[SIMULATING TOOL EXECUTION]")
                        print(f"Calling {tc['function']['name']}({args})")
                        mock_result = "24℃"
                        print(f"Result: {mock_result}")
                        
                        # 第二次调用 - 提供工具执行结果
                        # 构建assistant消息，reasoner模型需要包含reasoning_content
                        assistant_msg = {
                            "role": "assistant",
                            "content": response.get('content'),
                            "tool_calls": [tc]
                        }
                        # 如果有reasoning，添加reasoning_content字段（DeepSeek reasoner模型必需）
                        if 'reasoning' in response:
                            assistant_msg['reasoning_content'] = response['reasoning']
                        
                        messages.append(assistant_msg)
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc['id'],
                            "content": mock_result
                        })
                        
                    except Exception as e:
                        print(f"      Error parsing arguments: {e}")
                
                # 第二次调用，包含工具结果
                print(f"\n[REQUEST 2 - With Tool Results]")
                final_response = llm_client.chat(
                    messages=messages,
                    tools=tools,
                    max_tokens=1024
                )
                
                print(f"\n[RESPONSE 2 - Final Answer]")
                if isinstance(final_response, dict):
                    print(f"Content: {final_response.get('content')}")
                else:
                    print(f"Content: {final_response}")
        else:
            print("Response (no tool calls):", response)
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("DeepSeek tool calling test completed!")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    
    # Check command line arguments
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        if test_name == "basic":
            test_basic_chat()
        elif test_name == "tool_lab" or test_name == "tool":
            test_multi_turn_tool_calling_with_thinking()
        elif test_name == "tool_deepseek":
            test_deepseek_tool_calling()
        elif test_name == "tool_deepseek_thinking" or test_name == "thinking":
            test_deepseek_tool_calling_with_thinking()
        else:
            print(f"Unknown test: {test_name}")
            print("Available tests: basic, tool (or tool_lab), tool_deepseek, thinking (or tool_deepseek_thinking)")
    else:
        # Run all tests
        print("\n" + "="*70)
        print("Running all tests...")
        print("="*70 + "\n")
        
        test_basic_chat()
        print("\n" + "="*70 + "\n")
        
        test_multi_turn_tool_calling_with_thinking()
        print("\n" + "="*70 + "\n")
        
        test_deepseek_tool_calling_with_thinking()
        print("\n" + "="*70 + "\n")
        
        test_deepseek_tool_calling()