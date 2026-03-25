import json
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


def _load_scan_repo_module():
    script_path = Path(
        "/mnt/raid/home/dongtian/vuln/llm-vulvariant/.claude/skills/ai-infra-module-modeler/scripts/scan_repo.py"
    )
    script_dir = script_path.parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    spec = importlib.util.spec_from_file_location("test_ai_infra_scan_repo_module", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_scan_repo_respects_max_files_for_classification(monkeypatch, tmp_path):
    module = _load_scan_repo_module()
    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(3):
        (repo / f"file_{index}.py").write_text("print('x')\n", encoding="utf-8")

    seen = {}

    def _fake_classify(**kwargs):
        group_summaries = kwargs["group_summaries"]
        seen["file_count"] = sum(item.file_count for item in group_summaries)
        return {".": "platform_systems"}, {}

    monkeypatch.setattr(module, "classify_groups_with_llm", _fake_classify)

    signals, _evidences, file_index = module.scan(
        repo=repo,
        exclude_dirs=set(),
        max_files=1,
        max_bytes=1000,
        group_depth=10,
        group_sample_files=4,
        group_snippets=1,
        snippet_bytes=100,
        batch_size=1,
        llm_client=SimpleNamespace(
            config=SimpleNamespace(provider="deepseek", model="deepseek-chat", temperature=0.1),
        ),
        require_llm=False,
        file_list=None,
        max_workers=1,
        analysis_mode="validation_script",
    )

    assert seen["file_count"] == 1
    assert signals.files_scanned == 1
    assert len(file_index) == 1


def test_process_batch_worker_aggregates_usage_since_snapshot(monkeypatch):
    module = _load_scan_repo_module()

    class FakeClient:
        def chat(self, _messages):
            return {
                "content": json.dumps(
                    {
                        "assignments": [
                            {"group": "pkg", "module": "platform_systems"},
                        ]
                    }
                )
            }

        def usage_history_snapshot(self):
            return 7

        def aggregate_usage_since(self, snapshot):
            assert snapshot == 7
            return {
                "source": "llm_client",
                "sessions_total": 2,
                "calls_total": 2,
                "input_tokens": 11,
                "output_tokens": 13,
                "cost_usd": 0.42,
            }

    monkeypatch.setattr(module, "_ensure_llm_import", lambda: True)
    monkeypatch.setattr(module, "create_llm_client", lambda _config: FakeClient())
    monkeypatch.setattr(module, "capture_llm_usage_snapshot", lambda client: client.usage_history_snapshot())
    monkeypatch.setattr(
        module,
        "aggregate_llm_usage_since",
        lambda client, snapshot: client.aggregate_usage_since(snapshot),
    )

    batch = [
        module.GroupSummary(
            group="pkg",
            file_count=1,
            sample_paths=["pkg/a.py"],
            snippets=[{"path": "pkg/a.py", "content": "print('x')"}],
        )
    ]

    batch_index, assignments, usage_summary = module._process_batch_worker(
        batch_index=0,
        batch=batch,
        taxonomy_ref="taxonomy",
        llm_config=SimpleNamespace(provider="deepseek", model="deepseek-chat"),
        require_llm=True,
    )

    assert batch_index == 0
    assert assignments == {"pkg": "platform_systems"}
    assert usage_summary["sessions_total"] == 2
    assert usage_summary["calls_total"] == 2
    assert usage_summary["input_tokens"] == 11
