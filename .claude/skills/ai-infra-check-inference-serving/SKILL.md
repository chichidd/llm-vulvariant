---
name: ai-infra-check-inference-serving
description: Determine whether a repository contains inference/runtime or serving/deployment infrastructure and record evidence.
metadata:
  short-description: Check inference engines and serving frameworks
---

# ai-infra-check-inference-serving

## Scope
Covers optimized inference engines/runtimes and model serving/deployment layers.

### Includes
- Inference engines: KV-cache, batching/streaming, speculative decoding, quantized inference.
- Serving: HTTP/gRPC servers, OpenAI-compatible APIs, Triton/TGI, Kubernetes inference (KServe/Seldon).
- Deployment packaging: Docker images, Helm charts, autoscaling configs.

### Evidence checklist
Provide 2+ signals:
1. Libraries: `vllm`, `tensorrt_llm`, `triton`, `text-generation-inference`, `llama.cpp` bindings.
2. Server code: `fastapi`, `grpc`, `uvicorn`, `openai`-style routes, streaming responses.
3. Perf features: continuous batching, paged attention/KV cache, speculative decoding.
4. Deployment: `Dockerfile`, `helm/`, `k8s/`, `ingress`, `hpa`.

### Fine-grained labels
- `inference_and_serving.inference_engines.*`
- `inference_and_serving.serving_frameworks.*`
- `inference_and_serving.deployment_targets.*`

## Output
Record label, evidence file paths, and confidence.
