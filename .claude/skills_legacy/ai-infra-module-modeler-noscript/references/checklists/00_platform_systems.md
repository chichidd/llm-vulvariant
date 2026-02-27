# Checklist: Platform & Systems

## Scope
Covers repo parts that provide **system-level foundations** enabling AI workloads: build & packaging, runtime/hardware abstraction, and distributed compute/orchestration.

## Include when you see
- Build & packaging systems (pyproject/setup, wheels, multi-language builds, bindings).
- CUDA/ROCm/Metal/oneAPI backends, kernels, Triton, custom ops, fused attention, FP8 kernels.
- Device discovery, mixed-precision/quantization backends, runtime abstraction layers.
- Distributed compute/orchestration: launcher, scheduler integration, multi-node comms (NCCL/Gloo).

## Exclude / avoid double counting
- Pure model-serving YAML/Helm belongs in **Serving & Deployment** unless it implements cluster scheduling.
- Training scripts belong in **Training & Optimization** even if they launch multi-node jobs.

## Common (but not all) signals 
- Directories: `csrc/`, `kernels/`, `triton/`, `cuda/`, `cmake/`, `bazel/`, `ops/`, `runtime/`, `bindings/`.
- Files: `CMakeLists.txt`, `BUILD.bazel`, `setup.py` building extensions, `pyproject.toml` with `setuptools.build_meta` + extensions.
- Keywords: `nvcc`, `cublas`, `cutlass`, `hip`, `rocblas`, `xla`, `triton`, `kernel`, `fused`, `operator`.

## Typical submodules
- Build & packaging
- Runtime/hardware abstraction + kernels
- Distributed compute & orchestration

## Evidence to collect (for module_map.json)
- Path-level evidence (e.g., `csrc/flash_attn/*`)
- Build manifests referencing CUDA/Rust/Go.
- README sections describing kernels, runtime, or platform support.
