---
name: ai-infra-check-model-assets
description: Determine whether a repository contains model asset management (loading, checkpoint formats, tokenizers/processors, conversion/quantization) and record evidence.
metadata:
  short-description: Check model loading and conversion modules
---

# ai-infra-check-model-assets

## Scope
This check module covers modules that represent, load, transform, or package models and their associated assets.

### Includes
- **Model loading APIs**: wrappers around Hugging Face `from_pretrained`, custom checkpoint readers, sharded loading, streaming weights.
- **Artifact formats & conversion**: safetensors, GGUF, ONNX, TensorRT export, weight packing.
- **Tokenization & processors**: text tokenizers; vision/audio pre/post processing.
- **Quantization & compression tooling**: GPTQ/AWQ, bitsandbytes, weight-only quantization pipelines.

### Excludes
- Pure training loop code (belongs in `training`).
- Pure inference server glue (belongs in `inference_and_serving`), unless it contains reusable conversion/packaging.

## Evidence checklist
High-signal indicators include:
1. Calls to `AutoModel*`, `AutoTokenizer`, `AutoProcessor`, `from_pretrained`, `snapshot_download`.
2. Format/tool mentions: `safetensors`, `gguf`, `onnx`, `tensorrt`, `torchscript`.
3. Dedicated converters: `convert_*.py`, `export_*.py`, `quantize_*.py`.
4. Registry/config patterns: model manifests, YAML/JSON configs, plugin registries.

## Fine-grained labels
- `model_assets.loading_and_registry.*`
- `model_assets.conversion_and_optimization.*`

## Boundary tests
- If code primarily runs a server and only indirectly loads models, classify as serving.
- If code focuses on training checkpoints (save/resume) without general conversion, keep it in training.

## Output
For each matched item, record label, evidence file paths, and confidence.

## Examples
- `scripts/export_onnx.py` + `onnxruntime` dependency ⇒ `model_assets.conversion_and_optimization.export(onnx...)`.
- `hf_hub_download` + `AutoTokenizer.from_pretrained` ⇒ `model_assets.loading_and_registry.checkpoint_loading(...)`.
