---
name: ai-infra-check-foundation
description: Determine whether a repository contains foundation-layer AI infra (runtime, kernels, distributed, scheduling) and record evidence.
metadata:
  short-description: Check foundation/runtime/distributed modules
---

# ai-infra-check-foundation

## Scope
This check module covers *non-model-specific* infrastructure that enables scaling or accelerating AI workloads.

### Includes
- **Hardware runtime support**: CUDA/ROCm/TPU/Metal backends, custom C++/CUDA extensions, kernel fusion, attention kernels.
- **Distributed compute**: collectives, process launchers, tensor/pipeline/data parallel utilities, checkpoint sharding.
- **Scheduling & orchestration**: cluster scheduling integrations (Kubernetes/Slurm), autoscaling policies, placement.

### Excludes
- Pure model architectures/layers *without* infra/runtime innovations.
- Pure app frameworks (agents/RAG) with no systems component.

## Evidence checklist (high confidence)
Provide 2+ independent signals per asserted capability:
1. **Native code**: `csrc/`, `cuda/`, `kernels/`, `*.cu`, `CMakeLists.txt`, `setup.py` building extensions.
2. **Distributed stack**: imports/configs referencing `torch.distributed`, NCCL, MPI, Gloo, FSDP, ZeRO, Megatron utilities.
3. **Runtime integration**: explicit support matrices for CUDA/ROCm/TPU; kernel flags; build docs.
4. **Cluster artifacts**: `helm/`, `k8s/`, operators/controllers, Slurm scripts.

## Fine-grained labels (use when supported)
- `foundation.hardware_and_runtime.*`
- `foundation.distributed_and_scheduling.*`
- `foundation.build_and_packaging.*`

## Common dependency signals
- `triton`, `xformers`, `flash-attn`, `cuda-python`, `ninja`, `pybind11`
- `deepspeed`, `ray`, `kubernetes`, `kuberay`, `slurm`

## Output
For each matched item, record:
- Label (coarse or fine)
- Evidence: file paths + brief rationale
- Confidence: high/medium/low

## Examples
- Presence of `csrc/` + `setup.py` compiling CUDA kernels ⇒ `foundation.hardware_and_runtime`.
- `torch.distributed` + tensor parallel utilities ⇒ `foundation.distributed_and_scheduling`.
