# Checklist: Observability & LLMOps

## Scope
Covers operational visibility and governance: tracing/logs, cost/latency monitoring, experiment tracking, and prompt/version governance for LLM systems.

## Include when you see
- Tracing, structured logs, metrics export, dashboards (OpenTelemetry, Prometheus, Grafana).
- Cost/latency monitoring (token usage, GPU utilization, cache hit rates).
- Experiment tracking and artifacts (runs, datasets, model registry).
- Prompt/version governance (approval workflows, rollback, audit trails).

## Exclude / avoid double counting
- One-off benchmarks or load tests without ongoing monitoring belong in **Evaluation, Testing & Benchmarking**.

## Common (but not all) signals
- Directories: `observability/`, `monitoring/`, `telemetry/`, `tracing/`, `ops/`, `registry/`.
- Files: `grafana/`, `prometheus/`, `otel/`, `.github/workflows/*` (ops/release automation).
- Keywords: `otel`, `tracing`, `metrics`, `logging`, `prometheus`, `grafana`, `mlflow`, `wandb`, `registry`, `governance`.

## Typical submodules
- Tracing & logs
- Cost/latency monitoring
- Experiment tracking
- Prompt/version governance

## Evidence to collect
- Telemetry initialization code and dashboards.
- Tracking/registry configuration and governance docs.
