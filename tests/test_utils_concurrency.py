from __future__ import annotations

from utils.concurrency import run_thread_pool_tasks


def _run_task(task_id: str) -> str:
    if task_id == "bad":
        raise RuntimeError("boom")
    return f"done-{task_id}"


def test_run_thread_pool_tasks_preserves_task_order():
    results = run_thread_pool_tasks(
        tasks=["a", "b", "c"],
        worker_fn=_run_task,
        max_workers=3,
        fail_fast=False,
    )

    assert [result.task_id for result in results] == ["0", "1", "2"]
    assert [result.status for result in results] == ["success", "success", "success"]
    assert [result.result for result in results] == ["done-a", "done-b", "done-c"]


def test_run_thread_pool_tasks_captures_worker_exception_as_error():
    results = run_thread_pool_tasks(
        tasks=["ok", "bad", "ok"],
        worker_fn=_run_task,
        max_workers=3,
        fail_fast=False,
    )

    assert results[0].status == "success"
    assert results[1].status == "error"
    assert results[1].error == "RuntimeError: boom"
    assert results[1].result is None
    assert results[2].status == "success"


def test_run_thread_pool_tasks_fail_fast_marks_remaining_tasks_canceled():
    results = run_thread_pool_tasks(
        tasks=["bad", "ok", "ok"],
        worker_fn=_run_task,
        max_workers=1,
        fail_fast=True,
    )

    assert results[0].status == "error"
    assert results[1].status == "canceled"
    assert results[2].status == "canceled"
    assert "canceled due to fail_fast" in (results[1].error or "")
    assert "canceled due to fail_fast" in (results[2].error or "")
