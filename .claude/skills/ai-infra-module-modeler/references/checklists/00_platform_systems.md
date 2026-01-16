# Checklist: Platform & Systems

## Scope
Covers repo parts that provide **system-level foundations** enabling AI workloads: builds, kernels, multi-language bindings, cluster runtime integration, and resource orchestration.

## Include when you see
- CUDA/ROCm/Metal kernels, Triton, custom ops, fused attention, FP8 kernels.
- Multi-language core (C++/CUDA/Rust/Go) with Python bindings.
- Cluster runtime or job submission integration (Ray, Slurm, Kubernetes operators).
- Build tooling: CMake/Bazel, wheel build pipelines, container toolchains.

## Exclude / avoid double counting
- Pure model-serving YAML/Helm belongs in **Serving & Deployment** unless it includes cluster schedulers.
- Training scripts belong in **Training & Optimization** even if they launch multi-node jobs.

## Common signals
- Directories: `csrc/`, `kernels/`, `triton/`, `cuda/`, `cmake/`, `bazel/`, `ops/`, `runtime/`, `bindings/`.
- Files: `CMakeLists.txt`, `BUILD.bazel`, `setup.py` building extensions, `pyproject.toml` with `setuptools.build_meta` + extensions.
- Keywords: `nvcc`, `cublas`, `cutlass`, `hip`, `rocblas`, `xla`, `triton`, `kernel`, `fused`, `operator`.

## Typical submodules
- Build/packaging
- Hardware abstraction + kernels
- Distributed runtime integration
- Performance tooling (microbench, CI perf)

## Evidence to collect (for module_map.json)
- Path-level evidence (e.g., `csrc/flash_attn/*`)
- Build manifests referencing CUDA/Rust/Go.
- README sections describing kernels, runtime, or platform support.
