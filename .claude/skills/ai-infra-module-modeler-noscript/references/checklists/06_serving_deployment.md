# Checklist: Serving & Deployment

## Scope
Covers turning models into **online services** and operating them: APIs, request routing, containers, Kubernetes/Helm, authN/authZ, rate limiting, autoscaling, and multi-tenant isolation.

## Include when you see
- HTTP/gRPC serving (FastAPI, Flask, gRPC, OpenAI-compatible endpoints).
- Deployment manifests: Dockerfile, docker-compose, Helm charts, K8s YAML, Terraform, systemd.
- Load balancing, routing, canary, A/B, multi-model serving.
- AuthN/AuthZ, API keys, rate limiting, tenant isolation.

## Exclude / avoid double counting
- Model-inference kernels belong in **Inference Engine & Acceleration**.
- UI-only repos belong in **UI & Developer Experience** unless they embed serving.

## Common (but not all) signals
- Directories: `server/`, `api/`, `gateway/`, `deploy/`, `k8s/`, `helm/`, `charts/`.
- Files: `Dockerfile*`, `docker-compose.yml`, `values.yaml`, `Ingress`, `Service`, `Deployment`, `HPA`.
- Keywords: `OpenAI compatible`, `chat/completions`, `stream`, `grpc`, `uvicorn`, `gunicorn`, `nginx`, `auth`, `jwt`, `rate limit`.

## Typical submodules
- API layer (protocol + schema)
- Packaging & images
- Orchestration & scaling
- AuthN/AuthZ + rate limiting
- Multi-tenant isolation

## Evidence to collect
- API route definitions + protocol docs
- Deployment manifests + Helm values
- README sections on deployment, scaling, auth
