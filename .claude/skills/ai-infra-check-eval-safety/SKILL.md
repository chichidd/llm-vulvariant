---
name: ai-infra-check-eval-safety
description: Determine whether a repository contains evaluation or safety/guardrail infrastructure and record evidence.
metadata:
  short-description: Check eval, benchmarking, and guardrails modules
---

# ai-infra-check-eval-safety

## Scope
Evaluation harnesses, benchmarks, test suites, and guardrails/policy enforcement.

### Evidence checklist
Provide 2+ signals:
1. Benchmark/eval entry points: `eval/`, `benchmarks/`, `lm-eval`, `harness`, metrics scripts.
2. Datasets/metrics: BLEU/ROUGE, judge-based evaluation, golden tests/regression snapshots.
3. Safety features: input/output filtering, policy templates, red teaming, PII detection.
4. CI tests focused on model quality (not only unit tests).

### Fine-grained labels
- `evaluation_and_safety.evaluation.*`
- `evaluation_and_safety.safety_and_guardrails.*`

## Output
Record label, evidence file paths, and confidence.
