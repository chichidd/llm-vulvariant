"""Shared concurrency utilities for batch scan and exploitability workflows."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Sequence


@dataclass(frozen=True)
class ConcurrencyConfig:
    """Configuration values shared by CLI workflows."""

    max_workers: int = 1
    scan_workers: int = 1
    exploitability_workers: int = 1
    fail_fast: bool = False


@dataclass(frozen=True)
class ThreadPoolTaskResult:
    """Result of one task submitted to the thread pool."""

    task_id: str
    status: str
    payload: Optional[Any] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None


class RepoPathLockManager:
    """Maintain a stable lock object per absolute repository path."""

    def __init__(self) -> None:
        self._manager_lock = Lock()
        self._locks: Dict[str, Lock] = {}

    def get_lock(self, repo_path: Path) -> Lock:
        """Return the lock tied to ``repo_path`` (resolved absolute string key)."""
        resolved = str(Path(repo_path).resolve())
        with self._manager_lock:
            lock = self._locks.get(resolved)
            if lock is None:
                lock = Lock()
                self._locks[resolved] = lock
            return lock



def _derive_task_id(task: Any, index: int) -> str:
    if isinstance(task, dict):
        task_id = task.get("task_id")
        if isinstance(task_id, str) and task_id:
            return task_id
        if isinstance(task_id, int):
            return str(task_id)
    candidate = getattr(task, "task_id", None)
    if isinstance(candidate, str) and candidate:
        return candidate
    if isinstance(candidate, int):
        return str(candidate)
    return str(index)


def run_thread_pool_tasks(
    tasks: Sequence[Any],
    worker_fn: Callable[[Any], Any],
    *,
    max_workers: int,
    fail_fast: bool = False,
) -> List[ThreadPoolTaskResult]:
    """Run worker tasks in a thread pool and return structured task results.

    Worker exceptions are captured as ``ThreadPoolTaskResult`` entries instead of
    bubbling up directly.
    """
    if max_workers <= 0:
        max_workers = 1
    if not tasks:
        return []

    results: List[ThreadPoolTaskResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for index, task in enumerate(tasks):
            task_id = _derive_task_id(task, index)
            future = executor.submit(worker_fn, task)
            futures[future] = task_id

        for future in as_completed(futures):
            task_id = futures[future]
            try:
                payload = future.result()
                results.append(
                    ThreadPoolTaskResult(
                        task_id=task_id,
                        status="success",
                        payload=payload,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    ThreadPoolTaskResult(
                        task_id=task_id,
                        status="error",
                        payload=None,
                        error_type=type(exc).__name__,
                        error_message=str(exc),
                    )
                )
                if fail_fast:
                    for remaining in futures:
                        if not remaining.done():
                            remaining.cancel()
                    break

    return results
