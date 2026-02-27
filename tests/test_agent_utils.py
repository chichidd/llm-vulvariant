from types import SimpleNamespace

from scanner.agent.utils import clear_reasoning_content, compress_iteration_conversation, make_serializable


class MessageObj:
    def __init__(self):
        self.role = "assistant"
        self.content = "ok"
        self.reasoning_content = "secret"


class DummyLLM:
    def __init__(self, content):
        self._content = content

    def chat(self, messages):
        return SimpleNamespace(content=self._content)


def test_clear_reasoning_content_for_object_and_dict():
    msg_obj = MessageObj()
    msg_dict = {"role": "assistant", "content": "ok", "reasoning_content": "hidden"}

    cleaned = clear_reasoning_content([msg_obj, msg_dict])

    assert cleaned[0].reasoning_content is None
    assert "reasoning_content" not in cleaned[1]


def test_make_serializable_handles_nested_custom_objects():
    obj = SimpleNamespace(x=1, y=SimpleNamespace(z="v"))

    out = make_serializable({"obj": obj})

    assert out == {"obj": {"x": 1, "y": {"z": "v"}}}


def test_compress_iteration_conversation_parses_json_code_block():
    llm = DummyLLM("```json\n{\"summary\":\"s\"}\n```")

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=2,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 2
    assert result["content"]["summary"] == "s"


def test_compress_iteration_conversation_returns_error_payload_on_invalid_json():
    llm = DummyLLM("not-json")

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=3,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 3
    assert result["summary"] == "Compression failed"
    assert "error" in result
