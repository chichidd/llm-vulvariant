from openai import OpenAI

# Initialize OpenAI-like client
client = OpenAI(api_key="sk-vY79mrExwVtHsjHWv36b4sIsVEZYRdkQyUv6XP95LQsDh938", base_url=f"https://hkucvm.dynv6.net/v1")
model_name = client.models.list().data[0].id

messages = [
    {
        "role": "user",
        "content": "What is 1+3?",
    }
]

response_non_stream = client.chat.completions.create(
    model=model_name,
    messages=messages,
    temperature=0.6,
    top_p=0.95,
    stream=False,  # Non-streaming
    extra_body={"separate_reasoning": True, "chat_template_kwargs":{"thinking": True}}
)
print("==== Reasoning ====")
print(response_non_stream.choices[0].message.reasoning_content)

print("==== Text ====")
print(response_non_stream.choices[0].message.content)


# Define tools
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
                        "description": "the two-letter abbreviation for the state that the city is"
                        " in, e.g. 'CA' which would mean 'California'",
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
    }
]
def get_messages():
    return [
        {
            "role": "user",
            "content": "What's the weather like in Boston today? Output a reasoning before act, then use the tools to help you.",
        }
    ]


messages = get_messages()
# Non-streaming mode test
response_non_stream = client.chat.completions.create(
    model=model_name,
    messages=messages,
    temperature=0,
    top_p=0.95,
    max_tokens=1024,
    stream=False,  # Non-streaming
    tools=tools,
    tool_choice="required",
    extra_body={"separate_reasoning": True, "chat_template_kwargs":{"thinking": True}}

)
print("Non-stream response:")
print(response_non_stream)
print("==== content ====")
print(response_non_stream.choices[0].message.content)
print("==== tool_calls ====")
print(response_non_stream.choices[0].message.tool_calls)