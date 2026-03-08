from profiler.software.repo_collector import RepoInfoCollector


def test_repo_info_collector_collects_frontend_and_cpp_extensions(tmp_path):
    files_to_create = [
        "frontend/src/app.tsx",
        "frontend/src/view.jsx",
        "frontend/src/runtime.mjs",
        "native/include/kernel.hpp",
        "native/include/kernel.h",
        "native/src/kernel.cc",
        "native/cuda/op.cuh",
        "service/main.py",
    ]
    for rel_path in files_to_create:
        path = tmp_path / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// test\n", encoding="utf-8")

    collector = RepoInfoCollector()
    info = collector.collect(tmp_path)

    assert set(info["files"]) == set(files_to_create)
    assert {"Python", "JavaScript", "TypeScript", "C/C++"} <= set(info["languages"])
