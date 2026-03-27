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
        "{"
        "\"summary\":\"s\","
        "\"reasoning\":{\"analysis\":\"validated the relevant sink path\"},"
        "\"shared_memory_hits\":[\"query=os.system\"],"
        "\"rejected_hypotheses\":[\"subprocess path is sanitized\"],"
        "\"next_best_queries\":[\"shell=True\"],"
        "\"evidence_gaps\":[\"need source-to-sink trace\"],"
        "\"files_completed_this_iteration\":[\"app/exec.py\"]"
        "}\n"
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
    assert result["content"]["shared_memory_hits"] == ["query=os.system"]


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


def test_compress_iteration_conversation_rejects_missing_required_schema_fields():
    llm = DummyLLM(
        '{"summary":"tmp","reasoning":{"analysis":"x"},"failed_attempts":[],"next_step_insights":[]}'
    )

    result = compress_iteration_conversation(
        llm_client=llm,
        iteration=7,
        iteration_history=[{"role": "assistant", "content": "x"}],
        verbose=False,
    )

    assert result["iteration_number"] == 7
    assert result["summary"] == "Compression failed"


def test_compress_iteration_conversation_skips_example_json_before_final_summary():
    llm = DummyLLM(
        'Example: {"summary":"tmp"}\n'
        'Final: {"summary":"s","reasoning":{"analysis":"x"},"shared_memory_hits":["q"],'
        '"rejected_hypotheses":["h"],"next_best_queries":["n"],'
        '"evidence_gaps":["g"],"files_completed_this_iteration":["f.py"]}'
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
    assert result["content"]["next_best_queries"] == ["n"]


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
        '"shared_memory_hits":["<shared memory query or hit>"],'
        '"rejected_hypotheses":["<rejected hypothesis and why>"],'
        '"next_best_queries":["<next best query>"],'
        '"evidence_gaps":["<missing evidence>"],'
        '"files_completed_this_iteration":["<completed file path>"]'
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
