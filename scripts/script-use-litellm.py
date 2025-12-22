
import json
import os
from typing import Any, Dict, List

from litellm import completion

BASE_URL = "https://hkucvm.dynv6.net/v1"
API_KEY = os.getenv("HKU_LLM_API_KEY")
MODEL = "DeepSeek-V3.2"

# LiteLLM 通常用 "openai/xxx" 来表示走 OpenAI-compatible 协议
LITELLM_MODEL = f"openai/{MODEL}"

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_current_weather",
            "description": "Get the current weather in a given location",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "state": {"type": "string"},
                    "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                },
                "required": ["city", "state", "unit"],
            },
        },
    }
]


def get_current_weather(city: str, state: str, unit: str) -> Dict[str, Any]:
    temp_c = 3.0
    temp_f = temp_c * 9 / 5 + 32
    return {
        "location": f"{city}, {state}",
        "unit": unit,
        "temperature": temp_c if unit == "celsius" else temp_f,
        "conditions": "cloudy",
    }


def call_llm(messages: List[Dict[str, Any]], tools=None, tool_choice=None) -> Any:
    # separate_reasoning + chat_template_kwargs 作为“非标准参数”透传到 body
    resp = completion(
        model=LITELLM_MODEL,
        api_base=BASE_URL,
        api_key=API_KEY,
        messages=messages,
        tools=tools,
        tool_choice=tool_choice,
        temperature=0.0,
        max_tokens=512,
        separate_reasoning=True,
        chat_template_kwargs={"thinking": True},
        drop_params=True,
    )
    return resp


def test_thinking() -> None:
    messages = [{"role": "user", "content": "判断 A=10^50 与 B=2^200 大小并解释。"}]
    resp = call_llm(messages)
    msg = resp.choices[0].message
    # LiteLLM 会尽力标准化字段，但不同版本/上游返回可能略有差异
    reasoning = getattr(msg, "reasoning_content", None) or msg.get("reasoning_content")
    content = getattr(msg, "content", None) or msg.get("content")
    print("===== THINKING / REASONING =====")
    print("reasoning_content:\n", reasoning)
    print("\nfinal content:\n", content)


def run_tool_loop() -> None:
    messages: List[Dict[str, Any]] = [
        {
            "role": "user",
            "content": "先输出 reasoning 再行动：请查询 Boston, MA 今天的天气（分别给出摄氏和华氏）。",
        }
    ]

    for step in range(1, 6):
        resp = call_llm(messages, tools=TOOLS, tool_choice="auto")
        msg = resp.choices[0].message

        # message 既可能是对象也可能是 dict（取决于 LiteLLM 版本/配置）
        reasoning = getattr(msg, "reasoning_content", None) if hasattr(msg, "reasoning_content") else msg.get("reasoning_content")
        content = getattr(msg, "content", None) if hasattr(msg, "content") else msg.get("content")
        tool_calls = getattr(msg, "tool_calls", None) if hasattr(msg, "tool_calls") else msg.get("tool_calls")

        print(f"\n===== ROUND {step} =====")
        print("reasoning_content:\n", reasoning)
        print("assistant content:\n", content)

        if not tool_calls:
            print("\n(No tool_calls) Done.")
            return

        # 回填 assistant tool_calls
        messages.append(
            {
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls,
            }
        )

        # 执行并回填 role="tool"
        for tc in tool_calls:
            func = tc["function"]
            name = func["name"]
            args = json.loads(func.get("arguments") or "{}")
            tool_call_id = tc.get("id")

            if name == "get_current_weather":
                result = get_current_weather(**args)
            else:
                result = {"error": f"Unknown tool: {name}"}

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "name": name,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )

    raise RuntimeError("Tool loop exceeded max rounds.")


if __name__ == "__main__":
    print("BASE_URL =", BASE_URL)
    print("MODEL    =", MODEL)
    print("LITELLM_MODEL =", LITELLM_MODEL)
    test_thinking()
    run_tool_loop()