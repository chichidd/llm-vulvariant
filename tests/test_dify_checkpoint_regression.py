import json
from pathlib import Path

import pytest

from config import _path_config
from profiler.software.analyzer import SoftwareProfiler


_DIFY_CHECKPOINT = Path(
    _path_config["profile_base_path"]
    / "soft"
    / "dify"
    / "fbacb9f7a279611190f0476256d94dff9a38d991"
    / "checkpoints"
)


def _load_dify_checkpoint():
    checkpoint_dir = _DIFY_CHECKPOINT
    if not checkpoint_dir.is_absolute():
        root = Path(__file__).resolve().parents[1]
        checkpoint_dir = root / checkpoint_dir
    if not checkpoint_dir.exists():
        pytest.skip(f"Dify checkpoint not found: {checkpoint_dir}")

    modules = json.loads((checkpoint_dir / "modules.json").read_text(encoding="utf-8")).get("modules", [])
    repo_info = json.loads((checkpoint_dir / "repo_info.json").read_text(encoding="utf-8"))
    if not modules:
        pytest.skip("Dify modules checkpoint is empty")
    return modules, repo_info


def _profiler_stub() -> SoftwareProfiler:
    profiler = SoftwareProfiler.__new__(SoftwareProfiler)
    profiler.detection_rules = {
        "data_sources": {},
        "data_formats": {},
        "processing_operations": {},
    }
    profiler._detect_patterns = lambda _functions, _pattern_type: []
    return profiler


def test_dify_checkpoint_repo_file_fallback_preserves_module_files():
    modules, repo_info = _load_dify_checkpoint()
    profiler = _profiler_stub()

    selected_modules = [m for m in modules if m.get("files")][:3]
    selected_repo_files = []
    for module in selected_modules:
        selected_repo_files.extend(module.get("files", [])[:3])

    enhanced = profiler._enhance_modules_with_repo_analysis(
        selected_modules,
        {"functions": [], "call_graph_edges": [], "dependencies": []},
        repo_files=selected_repo_files,
    )

    assert enhanced
    assert all(module.files for module in enhanced)


def test_dify_checkpoint_module_call_mapping_with_synthetic_edge():
    modules, _repo_info = _load_dify_checkpoint()
    profiler = _profiler_stub()

    selected_modules = [m for m in modules if m.get("files")][:2]
    if len(selected_modules) < 2:
        pytest.skip("Need at least two dify modules with files")

    caller_module = selected_modules[0]
    callee_module = selected_modules[1]
    caller_file = caller_module["files"][0]
    callee_file = callee_module["files"][0]

    repo_analysis = {
        "functions": [
            {"file": caller_file, "name": "caller_fn"},
            {"file": callee_file, "name": "callee_fn"},
        ],
        "call_graph_edges": [
            {
                "caller": "caller_fn",
                "caller_file": caller_file,
                "caller_line": 10,
                "callee": "callee_fn",
                "callee_file": callee_file,
                "callee_line": 20,
            }
        ],
        "dependencies": [],
    }

    enhanced = profiler._enhance_modules_with_repo_analysis(
        selected_modules,
        repo_analysis,
        repo_files=[caller_file, callee_file],
    )
    by_name = {module.name: module for module in enhanced}

    assert callee_module["name"] in by_name[caller_module["name"]].calls_modules
    assert caller_module["name"] in by_name[callee_module["name"]].called_by_modules
