---
name: ai-infra-check-ops-governance
description: Determine whether a repository contains LLMOps/MLOps modules (observability, monitoring, registry, security, governance) and record evidence.
metadata:
  short-description: Check ops/observability/lifecycle governance
---

# ai-infra-check-ops-governance

## Scope
Operational capabilities around running LLM systems in production.

### Evidence checklist
Provide 2+ signals:
1. Observability: OpenTelemetry, tracing spans, structured logging, metrics endpoints.
2. Monitoring/analytics: latency & cost tracking, prompt/version logs, dashboards.
3. Lifecycle: experiment tracking, model registry, artifact store, deployment rollout.
4. Security: auth, RBAC, secrets management, multi-tenancy.

### Fine-grained labels
- `ops_and_governance.observability.*`
- `ops_and_governance.lifecycle_management.*`

## Output
Record label, evidence file paths, and confidence.
