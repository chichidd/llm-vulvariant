# Checklist: Inference Engine & Acceleration

## Scope
Covers components that make inference **fast, memory-efficient, and scalable**: optimized decoding, batching, KV cache management, speculative decoding, quantization runtimes, kernel fusions.

## Include when you see
- Dedicated inference runtime/engine (batch scheduler, streaming generation).
- Memory managers for KV-cache, paged attention, offload policies.
- Quantization frameworks and kernel backends used in inference.
- Benchmarks for throughput/latency, perf CI.

## Exclude / avoid double counting
- Pure API wrappers (FastAPI REST endpoints) belong to **Serving & Deployment** unless they implement batching/engine internals.

## Common signals
- Directories: `engine/`, `inference/`, `decode/`, `runtime/`, `scheduler/`, `kv_cache/`, `kernels/`, `quant/`.
- Keywords: `paged attention`, `kv cache`, `speculative`, `continuous batching`, `prefill`, `decode`, `tensorRT`, `onnxruntime`, `triton`.
- Dependencies: `vllm`, `tensorrt`, `onnxruntime`, `sglang`, `lmdeploy`, `flash-attn`.

## Typical submodules
- Decoding + batching
- Cache/memory + parallelism
- Quantization + kernels
- Performance testing

## Evidence to collect
- Engine implementation files (core decode loop, schedulers).
- README claims about throughput, batching, cache, and supported backends.
