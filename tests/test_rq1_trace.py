import pytest

from profiler import rq1_trace


@pytest.mark.parametrize(
    "raw, secret",
    [
        ("Authorization: Basic proxy-secret", "proxy-secret"),
        ("Authorization=Basic equals-secret", "equals-secret"),
        ("HTTP_AUTHORIZATION=Basic env-secret", "env-secret"),
        ("Proxy-Authorization: Token upstream-secret", "upstream-secret"),
        ("API_KEY=repository-secret", "repository-secret"),
        ("https://user:password@example.com/path", "password"),
        (
            "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
            "private-material",
        ),
    ],
)
def test_redact_removes_embedded_repository_credentials(raw, secret):
    redacted = rq1_trace._redact(raw)

    assert secret not in redacted
    assert "[REDACTED" in redacted


def test_redact_preserves_non_secret_token_configuration():
    payload = {"max_tokens": 32000, "context_limit": 200000}

    assert rq1_trace._redact(payload) == payload
