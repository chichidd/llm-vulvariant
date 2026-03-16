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
    llm = DummyLLM(
        "```json\n"
        "{\"summary\":\"s\",\"reasoning\":{\"analysis\":\"validated the relevant sink path\"}}\n"
        "```"
    )

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=2,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 2
    assert result["content"]["summary"] == "s"
    assert result["content"]["reasoning"]["analysis"] == "validated the relevant sink path"


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


def test_compress_iteration_conversation_accepts_empty_json_object():
    llm = DummyLLM("{}")

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=4,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 4
    assert result["summary"] == "Compression failed"


def test_compress_iteration_conversation_rejects_summary_only_payload():
    llm = DummyLLM('{"summary":"tmp"}')

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=4,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 4
    assert result["summary"] == "Compression failed"


def test_compress_iteration_conversation_skips_example_json_before_final_summary():
    llm = DummyLLM(
        'Example: {"summary":"tmp"}\n'
        'Final: {"summary":"s","reasoning":{"analysis":"x"},"failed_attempts":[],"next_step_insights":[]}'
    )

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=5,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 5
    assert result["content"]["summary"] == "s"
    assert result["content"]["reasoning"]["analysis"] == "x"


def test_compress_iteration_conversation_rejects_placeholder_example_payload():
    llm = DummyLLM(
        "```json\n"
        "{"
        '"iteration_number":"<iteration_number>",'
        '"summary":"<one-sentence summary of what this iteration did>",'
        '"reasoning":{'
        '"motivation":"<why these checks were performed>",'
        '"analysis":"<key insights and analysis logic>",'
        '"conclusions":["<conclusion_1>"]'
        "},"
        '"failed_attempts":[{"what":"<what was tried>","why_failed":"<why it failed or why no issue was found>"}],'
        '"next_step_insights":["<hypothesis or strategy to validate>"]'
        "}\n"
        "```"
    )

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=6,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 6
    assert result["summary"] == "Compression failed"
