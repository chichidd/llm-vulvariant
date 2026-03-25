from __future__ import annotations

import profiler.software.module_analyzer.base as module_base
import scanner.agent.finder as finder_module
from llm.tool_arguments import normalize_tool_arguments


CHECK_FILE_STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "file_paths": {
            "type": "array",
            "items": {"type": "string"},
        }
    },
    "required": ["file_paths"],
}


FINALIZE_SCHEMA = {
    "type": "object",
    "properties": {
        "modules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "category": {"type": "string"},
                    "description": {"type": "string"},
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "key_functions": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "dependencies": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": ["name", "category", "description", "files"],
            },
        }
    },
    "required": ["modules"],
}


def test_lab_provider_coerces_stringified_array_field() -> None:
    parameters, error = normalize_tool_arguments(
        raw_arguments='{"file_paths": "[\\"a.py\\", \\"b.py\\"]"}',
        parameters_schema=CHECK_FILE_STATUS_SCHEMA,
        provider="lab",
    )

    assert error is None
    assert parameters == {"file_paths": ["a.py", "b.py"]}


def test_lab_provider_recursively_coerces_nested_stringified_arrays() -> None:
    parameters, error = normalize_tool_arguments(
        raw_arguments=(
            '{"modules": [{"name": "module.a", "category": "core", "description": "desc", '
            '"files": "[\\"src/a.py\\"]", "key_functions": "[\\"run\\"]", '
            '"dependencies": "[\\"module.b\\"]"}]}'
        ),
        parameters_schema=FINALIZE_SCHEMA,
        provider="lab",
    )

    assert error is None
    assert parameters == {
        "modules": [
            {
                "name": "module.a",
                "category": "core",
                "description": "desc",
                "files": ["src/a.py"],
                "key_functions": ["run"],
                "dependencies": ["module.b"],
            }
        ]
    }


def test_lab_provider_returns_parse_error_when_value_still_violates_schema() -> None:
    parameters, error = normalize_tool_arguments(
        raw_arguments='{"file_paths": "not-an-array"}',
        parameters_schema=CHECK_FILE_STATUS_SCHEMA,
        provider="lab",
    )

    assert parameters is None
    assert error == "Tool arguments field 'file_paths' must be array, got string"


def test_non_lab_provider_keeps_existing_non_recursive_behavior() -> None:
    parameters, error = normalize_tool_arguments(
        raw_arguments='{"file_paths": "[\\"a.py\\", \\"b.py\\"]"}',
        parameters_schema=CHECK_FILE_STATUS_SCHEMA,
        provider="openai",
    )

    assert error is None
    assert parameters == {"file_paths": '["a.py", "b.py"]'}


def test_agent_finder_parser_uses_lab_schema_coercion() -> None:
    parameters, error = finder_module.AgenticVulnFinder._parse_tool_arguments(
        raw_arguments='{"file_paths": "[\\"a.py\\", \\"b.py\\"]"}',
        parameter_schema=CHECK_FILE_STATUS_SCHEMA,
        provider="lab",
    )

    assert error is None
    assert parameters == {"file_paths": ["a.py", "b.py"]}


def test_module_analyzer_parser_reports_lab_schema_mismatch() -> None:
    parameters, error = module_base._parse_tool_arguments(
        raw_arguments='{"file_paths": "not-an-array"}',
        parameter_schema=CHECK_FILE_STATUS_SCHEMA,
        provider="lab",
    )

    assert parameters is None
    assert error == "Tool arguments field 'file_paths' must be array, got string"
