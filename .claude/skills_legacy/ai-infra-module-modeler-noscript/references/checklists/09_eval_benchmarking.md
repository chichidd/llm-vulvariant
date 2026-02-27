# Checklist: Evaluation, Testing & Benchmarking

## Scope
Covers offline/online evaluation and testing: benchmarks, regression tests, golden sets, safety evals, quality metrics, and unit/integration tests for infra.

## Include when you see
- Eval harnesses (task suites, dataset-driven scoring), prompt-based eval, judge models.
- Online eval or shadow-traffic evaluation pipelines.
- Safety evals (jailbreak/red-teaming, policy tests).
- Benchmark scripts for throughput/latency/memory, CI perf regression.
- Unit/integration tests specifically targeting model behavior or retrieval quality.

## Exclude / avoid double counting
- Pure monitoring/telemetry belongs in **Observability & LLMOps**.
- Core training metrics collection belongs in **Training & Optimization** unless it is a general evaluation framework.

## Common (but not all) signals 
- Directories: `eval/`, `benchmarks/`, `tests/`, `metrics/`, `leaderboard/`.
- Keywords: `evaluate`, `benchmark`, `perplexity`, `rouge`, `bleu`, `mmlu`, `gsm`, `truthful`, `toxicity`, `jailbreak`, `red team`, `safety eval`, `latency`, `throughput`.

## Typical submodules
- Offline eval harness + datasets
- Online eval + feedback loops
- Safety eval + red-teaming
- Unit/integration tests for infra
- Perf benchmarks + load testing

## Evidence to collect
- Example commands in README for running evals/benchmarks.
- Metric definitions and result artifacts.
