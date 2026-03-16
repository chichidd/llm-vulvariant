"""Utilities for deterministic multithreading behavior."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TypeVar


TaskType = TypeVar("TaskType")
ResultType = TypeVar("ResultType")


@dataclass
class ConcurrencyConfig:
    """Configuration used by batch and exploitability CLI.

    Args:
        max_workers: Global worker cap.
        scan_workers: Worker count used by batch target scanning.
        exploitability_workers: Worker count used by exploitability folder checks.
        fail_fast: Stop collecting new results once an exception is observed.
    """

    max_workers: int = 1
    scan_workers: int = 1
    exploitability_workers: int = 1
    fail_fast: bool = False


@dataclass
class RepoPathLockManager:
    """Provide deterministic lock instances for repository paths.

    The same repository physical path always maps to the same lock key.
    """

    _locks: Dict[str, threading.Lock] = field(default_factory=dict)
    _mutex: threading.Lock = field(default_factory=threading.Lock)

    def _normalize_path(self, repo_path: str | Path) -> str:
        return str(Path(repo_path).resolve())

    def get_lock(self, repo_path: str | Path) -> threading.Lock:
        """Return a shared lock object for the resolved repository path."""
        lock_key = self._normalize_path(repo_path)
        with self._mutex:
            lock = self._locks.get(lock_key)
            if lock is None:
                lock = threading.Lock()
                self._locks[lock_key] = lock
            return lock


@dataclass
class ConcurrencyTaskResult:
    """Structured result object returned for each task."""

    task_id: str
    status: str
    task: Any
    result: Any = None
    error: Optional[str] = None


def run_thread_pool_tasks(
    *,
    tasks: Sequence[TaskType],
    worker_fn: Callable[[TaskType], ResultType],
    max_workers: int,
    fail_fast: bool = False,
) -> List[ConcurrencyTaskResult]:
    """Run tasks with a thread pool and return structured outcomes.

    Args:
        tasks: Iterable tasks.
        worker_fn: Callable that receives one task and returns a result object.
        max_workers: Thread pool size.
        fail_fast: If True, cancel pending tasks when one task fails.

    Returns:
        A list of :class:`ConcurrencyTaskResult`, aligned with ``tasks`` order.
    """
    if max_workers <= 0:
        max_workers = 1

    results: List[ConcurrencyTaskResult] = []
    if not tasks:
        return results

    task_count = len(tasks)
    results = [ConcurrencyTaskResult(task_id="", status="pending", task=None) for _ in range(task_count)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(worker_fn, task): idx
            for idx, task in enumerate(tasks)
        }
        fail_fast_triggered = False

        for future in as_completed(future_to_index):
            idx = future_to_index[future]
            task = tasks[idx]
            task_id = getattr(task, "task_id", str(idx))
            try:
                output = future.result()
                results[idx] = ConcurrencyTaskResult(
                    task_id=task_id,
                    status="success",
                    task=task,
                    result=output,
                )
            except Exception as exc:  # pylint: disable=broad-except
                results[idx] = ConcurrencyTaskResult(
                    task_id=task_id,
                    status="error",
                    task=task,
                    error=f"{type(exc).__name__}: {exc}",
                )
                if fail_fast:
                    for f in future_to_index:
                        if not f.done():
                            f.cancel()
                    fail_fast_triggered = True
                    break

        if fail_fast_triggered:
            for f, task_index in future_to_index.items():
                task = tasks[task_index]
                task_id = getattr(task, "task_id", str(task_index))
                if results[task_index].status == "pending":
                    results[task_index] = ConcurrencyTaskResult(
                        task_id=task_id,
                        status="canceled",
                        task=task,
                        error="canceled due to fail_fast",
                    )

    return results
