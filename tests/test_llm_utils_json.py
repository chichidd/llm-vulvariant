from utils.llm_utils import parse_llm_json


class RepairLLM:
    def __init__(self, repaired_response):
        self.repaired_response = repaired_response
        self.calls = 0

    def chat(self, messages, temperature=0.0):
        self.calls += 1
        return self.repaired_response


def test_parse_llm_json_parses_fenced_json():
    response = "prefix\n```json\n{\"a\": 1, \"b\": \"x\"}\n```\nsuffix"
    parsed = parse_llm_json(
        response,
        required_keys=["a", "b"],
        expected_types={"a": int, "b": str},
    )
    assert parsed == {"a": 1, "b": "x"}


def test_parse_llm_json_parses_plain_json():
    response = "{\"description\": \"ok\", \"target_application\": [], \"target_user\": []}"
    parsed = parse_llm_json(
        response,
        required_keys=["description", "target_application", "target_user"],
        expected_types={
            "description": str,
            "target_application": list,
            "target_user": list,
        },
    )
    assert parsed is not None
    assert parsed["description"] == "ok"


def test_parse_llm_json_returns_none_on_schema_mismatch_without_repair():
    response = "{\"description\": 123}"
    parsed = parse_llm_json(
        response,
        required_keys=["description"],
        expected_types={"description": str},
    )
    assert parsed is None


def test_parse_llm_json_uses_repair_llm_on_invalid_json():
    repair_llm = RepairLLM(
        "{\"description\": \"fixed\", \"target_application\": [], \"target_user\": []}"
    )
    response = "{not valid json"
    parsed = parse_llm_json(
        response,
        required_keys=["description", "target_application", "target_user"],
        expected_types={
            "description": str,
            "target_application": list,
            "target_user": list,
        },
        llm_client=repair_llm,
        max_repair_attempts=2,
        task_hint="software basic information extraction",
    )
    assert parsed is not None
    assert parsed["description"] == "fixed"
    assert repair_llm.calls == 1


def test_parse_llm_json_returns_none_when_repair_remains_invalid():
    repair_llm = RepairLLM("still not json")
    response = "{not valid json"
    parsed = parse_llm_json(
        response,
        required_keys=["description"],
        expected_types={"description": str},
        llm_client=repair_llm,
        max_repair_attempts=2,
        task_hint="source feature extraction",
    )
    assert parsed is None
    assert repair_llm.calls == 2
