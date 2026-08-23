"""扫描实验的失败关闭证据约束。"""

from __future__ import annotations

from typing import Any, Dict, Mapping


MODULE_SIMILARITY_BYTE_BINDING_STATUS = "unattested"
MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE = (
    "consumed-embedding-bytes-unattested"
)
FORMAL_RESPONSE_MODEL_ID = "GLM-5.2"


class EvaluationEvidenceUnavailableError(ValueError):
    """缺少实验所需运行证据。"""

    blocker_code = MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE


def module_similarity_byte_binding() -> Dict[str, str]:
    """返回嵌入字节证明的真实状态。"""
    return {
        "status": MODULE_SIMILARITY_BYTE_BINDING_STATUS,
        "blocker_code": MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE,
    }


def observed_module_similarity_metadata(
    config: Mapping[str, Any],
    artifact_signature: Mapping[str, Any],
) -> Dict[str, Any]:
    """提取已有模块相似度元数据的五个字段。"""
    return {
        "threshold": float(config.get("threshold", 0.8)),
        "model_name": str(config.get("model_name", "")).strip(),
        "device": str(config.get("device", "cpu")).strip(),
        "resolved_model_path": str(
            artifact_signature.get("resolved_model_path", "") or ""
        ),
        "artifact_hash": str(
            artifact_signature.get("artifact_hash", "") or ""
        ),
    }


def require_evaluation_embedding_byte_binding(
    evaluation_mode: bool,
) -> None:
    """无法证明已消费嵌入字节时拒绝实验模式。"""
    if evaluation_mode:
        raise EvaluationEvidenceUnavailableError(
            MODULE_SIMILARITY_BYTE_BINDING_BLOCKER_CODE
        )


def require_evaluation_response_identity_usage(usage: Any) -> None:
    """正式运行必须证明每个已记录响应都来自固定模型。"""
    if not isinstance(usage, Mapping):
        raise EvaluationEvidenceUnavailableError(
            "response-identity-usage-missing"
        )
    count_fields = (
        "calls_total",
        "response_identity_checks_total",
        "response_identity_matches_total",
        "response_identity_mismatches_total",
        "calls_without_response_identity_check",
    )
    if any(
        type(usage.get(field)) is not int or usage[field] < 0
        for field in count_fields
    ):
        raise EvaluationEvidenceUnavailableError(
            "response-identity-counts-invalid"
        )
    calls_total = usage["calls_total"]
    checks_total = usage["response_identity_checks_total"]
    matches_total = usage["response_identity_matches_total"]
    if (
        calls_total <= 0
        or checks_total != calls_total
        or matches_total != checks_total
        or usage["response_identity_mismatches_total"] != 0
        or usage["calls_without_response_identity_check"] != 0
        or usage.get("response_identity_all_matched") is not True
    ):
        raise EvaluationEvidenceUnavailableError(
            "response-identity-not-fully-matched"
        )
    expected_ids = [FORMAL_RESPONSE_MODEL_ID]
    for field in (
        "request_model_ids",
        "expected_response_model_ids",
        "observed_response_model_ids",
    ):
        if usage.get(field) != expected_ids:
            raise EvaluationEvidenceUnavailableError(
                "response-identity-model-set-mismatch"
            )
