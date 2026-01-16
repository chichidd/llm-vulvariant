# Checklist: Observability, LLMOps & MLOps

## Scope
Covers production operations: experiment tracking, model registry, prompt/version management, tracing, metrics, logging, monitoring, CI/CD, and governance.

## Include when you see
- Experiment tracking / artifacts: MLflow, W&B integration, tracking DB.
- Observability: tracing, structured logs, metrics export (Prometheus/OpenTelemetry), dashboards.
- Model/prompt registry: versioning, approval workflows, rollback.
- CI/CD for models: build/test/deploy pipelines, perf regression gates.

## Exclude / avoid double counting
- Benchmarks that only measure latency/throughput without ongoing monitoring → **Evaluation & Benchmarking**.

## Common signals
- Directories: `observability/`, `monitoring/`, `telemetry/`, `ops/`, `pipelines/`.
- Files: `.github/workflows/*`, `grafana/`, `prometheus/`, `otel/`.
- Keywords: `mlflow`, `registry`, `tracing`, `span`, `otel`, `prometheus`, `grafana`, `metrics`, `logging`.

## Typical submodules
- Tracking + lineage
- Monitoring + alerting
- Registry + governance
- CI/CD automation

## Evidence to collect
- Workflow files and telemetry initialization code
- Docs describing operational procedures and SLOs
