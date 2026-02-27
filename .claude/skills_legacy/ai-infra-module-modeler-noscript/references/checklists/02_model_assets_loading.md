# Checklist: Model Assets & Loading

## Scope
Covers how the repo **defines models** and **handles model artifacts**: configs, checkpoints, tokenizers/processors, export/import.

## Include when you see
- Architecture definitions or wrappers around foundation models.
- Model loading pipelines (`from_pretrained`, config resolution, adapter injection).
- Checkpoint formats (`safetensors`, sharded ckpts, `gguf`/`ggml`), conversion/export tools.
- Processor/tokenizer assets, vocab handling, normalization.

## Exclude / avoid double counting
- Training code that just *uses* model loading belongs in Training; only tag this module if the repo provides reusable loading/asset tooling.
- Inference-server code belongs in Inference/Serving even if it loads checkpoints.

## Common (but not all) signals
- Directories: `models/`, `modeling_*/`, `tokenizers/`, `processors/`, `weights/`, `convert/`, `export/`.
- Files: `config.json`, `tokenizer.json`, `tokenizer.model`, `*.safetensors`, `*.bin`, `*.pt`, `*.gguf`.
- Keywords: `from_pretrained`, `AutoModel`, `AutoTokenizer`, `safetensors`, `state_dict`, `checkpoint`, `shard`, `merge_lora`.

## Typical submodules
- Model definitions
- Artifact formats and conversion
- Load/compose (base + adapters)
- Export (ONNX/TensorRT/TorchScript/GGUF)

## Evidence to collect
- Key entrypoints for model loading and configuration.
- Converter scripts / CLI usage in README.
- List of supported model families and weight formats.
