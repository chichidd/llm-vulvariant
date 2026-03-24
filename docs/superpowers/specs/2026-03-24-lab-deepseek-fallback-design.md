# Lab To DeepSeek Fallback Design

## Summary

Add a provider-aware fallback for `lab` in the shared LLM client layer.

When a `lab` request exhausts its configured retries due to a retriable transport or server-side failure, the client should retry the same logical request once through `deepseek`. This fallback must not trigger for parse errors, tool-argument validation errors, or other non-retriable business failures.

The change should be implemented centrally so that software profiling, vulnerability profiling, and agent scanning all inherit the behavior without per-call-site changes.

## Goals

- Add automatic `lab -> deepseek` fallback for retry-exhausted retriable failures.
- Keep the fallback policy configurable from YAML.
- Keep fallback behavior limited to `provider=lab`.
- Preserve the existing call sites and public CLI surface.
- Make fallback usage visible in logs and usage metadata.

## Non-Goals

- No fallback for JSON parse failures, tool schema failures, or prompt-quality issues.
- No multi-hop fallback chain.
- No fallback for providers other than `lab`.
- No changes to tool parsing, scanner heuristics, or result schema beyond minimal metadata needed to record fallback usage.

## Current State

- LLM configuration is loaded through `LLMConfig` in `src/llm/client.py`.
- Retries are implemented centrally in `BaseLLMClient._execute_with_retry(...)`.
- Client construction is centralized in `create_llm_client(...)`.
- `lab` is currently mapped to `OpenAIClient`.
- When retries are exhausted, the client raises `LLMRetryExhaustedError` and the request fails.

This makes the client layer the correct insertion point for fallback behavior.

## Design

### Configuration

Extend provider configuration to support optional fallback settings.

For `lab`, add:

```yaml
llm:
  providers:
    lab:
      base_url: "https://hkucvm.dynv6.net/v1"
      model: "DeepSeek-V3.2"
      api_key_env: "LAB_LLM_API_KEY"
      max_tokens: 65536
      context_limit: 65536
      fallback_provider: "deepseek"
      fallback_on_retry_exhausted: true
```

Add matching fields to `LLMConfig`:

- `fallback_provider: Optional[str]`
- `fallback_on_retry_exhausted: bool`

These fields should be loaded from YAML in the same way other provider defaults are loaded.

### Fallback Trigger

Fallback is allowed only when all of the following are true:

- current provider is `lab`
- `fallback_on_retry_exhausted` is `true`
- `fallback_provider` is set to `deepseek`
- the primary request exhausted retries inside `_execute_with_retry(...)`
- the final exception is still considered retriable by `_should_retry(...)`

Fallback must not trigger for:

- non-retriable API errors
- parse failures after a successful API response
- tool-argument normalization failures
- schema validation failures

### Fallback Execution

When fallback is triggered:

1. Build a new `LLMConfig(provider="deepseek")`.
2. Construct a new client through `create_llm_client(...)`.
3. Reconstruct the same logical request against the fallback client.
4. Do not reuse the original bound method from the `lab` client.
5. Do not recursively allow fallback from the fallback client.

The fallback path must be single-hop only:

- `lab -> deepseek` is allowed
- `deepseek -> anything else` is not allowed

Implementation note:

- The retry helper cannot invoke the original `func` object directly because it is bound to the original client instance.
- The implementation must either:
  - refactor the retry path so it knows which high-level operation is being retried and can call the corresponding method on the fallback client, or
  - pass an explicit request descriptor that can be replayed on the fallback client.
- The plan should assume the fallback request is replayed as an equivalent client operation, not as a raw re-call of the original bound method.

### Usage And Metadata

Fallback success must be visible in the resulting usage metadata.

Add these fields to the last usage summary when fallback succeeds:

- `fallback_used: true`
- `fallback_from_provider: "lab"`
- `fallback_to_provider: "deepseek"`

The existing usage totals should reflect the request that actually succeeded, while the metadata should make it clear that the original provider was `lab`.

Fallback metadata must be visible in both places:

- the raw result of `get_last_usage_summary()`
- aggregated summaries produced from the client usage history during the same run

This means aggregation must preserve the fallback markers at least at summary level. It is acceptable for aggregation to expose one consolidated fallback marker set for the successful request rather than attempt to merge multiple fallback records across many calls.

### Logging

When fallback starts, log a warning with:

- original provider
- fallback provider
- exhausted retry count
- final retriable exception type

When fallback succeeds, log one info line indicating that the request completed via fallback.

When fallback fails, log one error line and raise the fallback failure.

## Implementation Scope

### Files To Change

- `config/llm_config.yaml`
- `src/llm/client.py`
- relevant LLM client tests

### Expected Code Changes

In `src/llm/client.py`:

- extend `LLMConfig` fields and YAML loading
- add a small helper that decides whether fallback is permitted
- add a small helper that constructs and runs the fallback client once
- integrate fallback into `BaseLLMClient._execute_with_retry(...)`

No caller changes should be required in:

- `src/cli/software.py`
- `src/cli/vulnerability.py`
- `src/cli/agent_scanner.py`
- profiler or scanner modules

## Testing

Add or update unit tests to cover:

1. `lab` success path does not trigger fallback
2. `lab` retry exhaustion with retriable error triggers `deepseek`
3. `lab` non-retriable error does not trigger fallback
4. non-`lab` providers never trigger fallback
5. successful fallback records fallback metadata in usage summary
6. fallback runs at most once and does not recurse

Tests should use stubs or mocks for client construction and request execution rather than real network calls.

## Risks

- Hidden provider switching could confuse later debugging if metadata is not explicit.
- Reconstructing the fallback client must not accidentally inherit `lab` credentials or base URL.
- Fallback must not swallow the original failure class in cases where the fallback also fails; logs need to preserve enough context for debugging.

## Recommendation

Implement the fallback in the shared client layer and keep the policy YAML-driven.

This is the smallest change that covers all current `llm-vulvariant` execution paths while keeping the behavior tightly scoped to `lab`.
