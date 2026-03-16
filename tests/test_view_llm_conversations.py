from utils.view_llm_conversations import parse_conversation_filename


def test_parse_conversation_filename_supports_current_and_legacy_names():
    timestamp, step_name = parse_conversation_filename("basic_info.json")
    assert timestamp is None
    assert step_name == "basic_info"

    legacy_timestamp, legacy_step_name = parse_conversation_filename(
        "20251211_143025_123_module_analysis_iter_01.json"
    )
    assert legacy_timestamp == "20251211_143025_123"
    assert legacy_step_name == "module_analysis_iter_01"
