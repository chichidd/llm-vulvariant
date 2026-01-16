# Checklist: Evaluation & Benchmarking

## Scope
Covers offline and online evaluation: benchmarks, regression tests, golden sets, quality metrics, safety evals, and performance benchmarks.

## Include when you see
- Eval harnesses (task suites, dataset-driven scoring), prompt-based eval, judge models.
- Benchmark scripts for throughput/latency/memory, CI perf regression.
- Unit/integration tests specifically targeting model behavior or retrieval quality.

## Exclude / avoid double counting
- Pure monitoring/telemetry belongs in **Observability & LLMOps**.
- Core training metrics collection belongs in **Training & Optimization** unless it is a general evaluation framework.

## Common signals
- Directories: `eval/`, `benchmarks/`, `tests/`, `metrics/`, `leaderboard/`.
- Keywords: `evaluate`, `benchmark`, `perplexity`, `rouge`, `bleu`, `mmlu`, `gsm`, `truthful`, `toxicity`, `safety eval`, `latency`, `throughput`.

## Typical submodules
- Task suites + datasets
- Scorers/metrics + judge pipelines
- Perf benchmarks + load testing

## Evidence to collect
- Example commands in README for running evals/benchmarks.
- Metric definitions and result artifacts.
