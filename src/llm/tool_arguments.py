from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple


def normalize_tool_arguments(
    raw_arguments: Any,
    *,
    parameters_schema: Optional[Dict[str, Any]] = None,
    provider: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalize one tool-call argument payload into a JSON object.

    Args:
        raw_arguments: Raw tool-call arguments from the provider.
        parameters_schema: Optional JSON schema for the tool parameters.
        provider: Provider name for provider-specific normalization.

    Returns:
        A tuple of ``(normalized_arguments, error_message)``.
    """
    if isinstance(raw_arguments, dict):
        parsed_arguments = raw_arguments
    elif isinstance(raw_arguments, str):
        try:
            parsed_arguments = json.loads(raw_arguments)
        except json.JSONDecodeError as exc:
            return None, f"Failed to parse tool arguments: {exc}"
    else:
        return None, f"Tool arguments must be a JSON string or object, got {type(raw_arguments).__name__}"

    if not isinstance(parsed_arguments, dict):
        return None, f"Tool arguments must decode to an object, got {type(parsed_arguments).__name__}"

    if str(provider or "").strip().lower() != "lab" or not isinstance(parameters_schema, dict):
        return parsed_arguments, None

    normalized_arguments, error = _normalize_value_for_schema(
        parsed_arguments,
        parameters_schema,
        path="arguments",
    )
    if error:
        return None, f"Tool arguments {error}"
    if not isinstance(normalized_arguments, dict):
        return None, f"Tool arguments must decode to an object, got {type(normalized_arguments).__name__}"
    return normalized_arguments, None


def _normalize_value_for_schema(
    value: Any,
    schema: Dict[str, Any],
    *,
    path: str,
) -> Tuple[Any, Optional[str]]:
    """Coerce and validate container-shaped fields against a small schema subset."""
    schema_type = str(schema.get("type") or "").strip()
    normalized_value = _maybe_decode_container_string(value, schema_type=schema_type)

    if schema_type == "object":
        if not isinstance(normalized_value, dict):
            return None, _format_type_error(path, expected_type="object", value=normalized_value)

        required = schema.get("required", [])
        for field_name in required if isinstance(required, list) else []:
            if field_name not in normalized_value:
                return None, f"missing required field '{_field_path(path, str(field_name))}'"

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return normalized_value, None

        coerced_object = dict(normalized_value)
        for field_name, field_schema in properties.items():
            if field_name not in coerced_object or not isinstance(field_schema, dict):
                continue
            coerced_field_value, error = _normalize_value_for_schema(
                coerced_object[field_name],
                field_schema,
                path=_field_path(path, str(field_name)),
            )
            if error:
                return None, error
            coerced_object[field_name] = coerced_field_value
        return coerced_object, None

    if schema_type == "array":
        if not isinstance(normalized_value, list):
            return None, _format_type_error(path, expected_type="array", value=normalized_value)

        item_schema = schema.get("items")
        if not isinstance(item_schema, dict):
            return normalized_value, None

        coerced_items = []
        for index, item in enumerate(normalized_value):
            coerced_item, error = _normalize_value_for_schema(
                item,
                item_schema,
                path=f"{path}[{index}]",
            )
            if error:
                return None, error
            coerced_items.append(coerced_item)
        return coerced_items, None

    return normalized_value, None


def _maybe_decode_container_string(value: Any, *, schema_type: str) -> Any:
    """Decode one stringified JSON container for schema-aware lab normalization."""
    if not isinstance(value, str):
        return value

    stripped = value.strip()
    if schema_type == "array" and stripped.startswith("[") and stripped.endswith("]"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return value
    if schema_type == "object" and stripped.startswith("{") and stripped.endswith("}"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return value
    return value


def _field_path(path: str, field_name: str) -> str:
    """Build one dotted field path relative to the tool arguments root."""
    if not path or path == "arguments":
        return field_name
    return f"{path}.{field_name}"


def _format_type_error(path: str, *, expected_type: str, value: Any) -> str:
    """Format one schema type mismatch error."""
    return f"field '{path}' must be {expected_type}, got {_json_type_name(value)}"


def _json_type_name(value: Any) -> str:
    """Return a JSON-schema-style type label for one Python value."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__
