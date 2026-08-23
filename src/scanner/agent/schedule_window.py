"""Immutable host-side paging contract for frozen file schedules."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from profiler.fingerprint import stable_data_hash


FROZEN_SCHEDULE_CONTRACT = (
    "exact_frozen_global_contiguous_first_presentation_and_pending_"
    "structured_enumeration_eligibility_order"
)
FROZEN_SCHEDULE_PAGE_ALGORITHM = (
    "host-private-ledger-contiguous-pending-only-page-atomic-v2"
)
FROZEN_SCHEDULE_PAGE_SIZE = 1024


def _normalize_file_order(file_order: Sequence[str]) -> List[str]:
    files = [str(path) for path in file_order]
    if not files:
        raise ValueError("frozen schedule must contain at least one file")
    if any(not path.strip() for path in files) or len(files) != len(set(files)):
        raise ValueError("frozen schedule contains an empty or duplicate path")
    return files


def schedule_contract_metadata(
    file_order: Sequence[str],
    provenance: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Return the path-free, model-visible schedule contract."""
    files = _normalize_file_order(file_order)
    source = dict(provenance or {})
    declared_count = source.get("file_count", len(files))
    if isinstance(declared_count, bool) or int(declared_count) != len(files):
        raise ValueError("frozen schedule file_count does not match its file order")
    declared_page_size = source.get("page_size", FROZEN_SCHEDULE_PAGE_SIZE)
    if (
        isinstance(declared_page_size, bool)
        or int(declared_page_size) != FROZEN_SCHEDULE_PAGE_SIZE
    ):
        raise ValueError("frozen schedule page_size does not match the host contract")
    declared_page_algorithm = source.get(
        "page_algorithm", FROZEN_SCHEDULE_PAGE_ALGORITHM
    )
    if declared_page_algorithm != FROZEN_SCHEDULE_PAGE_ALGORITHM:
        raise ValueError("frozen schedule page_algorithm does not match the host contract")
    computed_universe_sha256 = stable_data_hash(sorted(files))
    computed_order_sha256 = stable_data_hash(files)
    declared_universe_sha256 = str(source.get("universe_sha256", "") or "")
    declared_order_sha256 = str(source.get("order_sha256", "") or "")
    if declared_universe_sha256 and declared_universe_sha256 != computed_universe_sha256:
        raise ValueError("frozen schedule universe_sha256 does not match its files")
    if declared_order_sha256 and declared_order_sha256 != computed_order_sha256:
        raise ValueError("frozen schedule order_sha256 does not match its file order")
    return {
        "contract": FROZEN_SCHEDULE_CONTRACT,
        "file_count": len(files),
        "algorithm": str(source.get("algorithm", "") or ""),
        "replicate": str(source.get("replicate", "") or ""),
        "artifact_sha256": str(source.get("artifact_sha256", "") or ""),
        "universe_sha256": computed_universe_sha256,
        "order_sha256": computed_order_sha256,
        "page_algorithm": FROZEN_SCHEDULE_PAGE_ALGORITHM,
        "page_size": FROZEN_SCHEDULE_PAGE_SIZE,
    }


def build_schedule_page(
    file_order: Sequence[str],
    *,
    cursor: int,
    completed_files: Sequence[str] = (),
) -> Dict[str, Any]:
    """Build one exact contiguous page from a host-owned cursor."""
    files = _normalize_file_order(file_order)
    if isinstance(cursor, bool) or not isinstance(cursor, int):
        raise ValueError("frozen schedule cursor must be an integer")
    if cursor < 0 or cursor > len(files):
        raise ValueError("frozen schedule cursor is out of range")
    if cursor != len(files) and cursor % FROZEN_SCHEDULE_PAGE_SIZE != 0:
        raise ValueError("frozen schedule cursor must be page aligned")
    page_files: List[str] = files[cursor : cursor + FROZEN_SCHEDULE_PAGE_SIZE]
    completed_set = {str(path) for path in completed_files}
    if not completed_set.issubset(set(files)):
        raise ValueError("frozen schedule ledger contains an off-schedule completion")
    end_cursor = cursor + len(page_files)
    if any(path not in completed_set for path in files[:cursor]):
        raise ValueError("frozen schedule cursor is ahead of an incomplete prior page")
    if any(path in completed_set for path in files[end_cursor:]):
        raise ValueError("frozen schedule ledger contains a future-page completion")
    completed_offsets = [
        offset
        for offset, path in enumerate(page_files)
        if path in completed_set
    ]
    active_pending_files = [path for path in page_files if path not in completed_set]
    return {
        "schema_version": 1,
        "contract": FROZEN_SCHEDULE_CONTRACT,
        "order_sha256": stable_data_hash(files),
        "universe_sha256": stable_data_hash(sorted(files)),
        "total_file_count": len(files),
        "cursor_index": cursor,
        "window_end_index_exclusive": end_cursor,
        "window_capacity": FROZEN_SCHEDULE_PAGE_SIZE,
        "window_file_count": len(page_files),
        "completed_window_offsets": completed_offsets,
        "active_pending_file_count": len(active_pending_files),
        "has_more": end_cursor < len(files),
        "schedule_complete": cursor == len(files),
        # The exact page boundary stays host-private. Model-visible structured
        # repository paths are always the current pending-only allowlist.
        "files": active_pending_files,
    }


def validate_schedule_page(
    file_order: Sequence[str],
    page: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    """Validate and copy one host-injected page against the immutable full order."""
    if not isinstance(page, Mapping):
        raise ValueError("candidate-priority ablation requires a host-injected page")
    raw_files = page.get("files")
    if not isinstance(raw_files, list):
        raise ValueError("host-injected schedule page files must be a list")
    page_files = [str(path) for path in raw_files]
    expected_keys = {
        "schema_version",
        "contract",
        "order_sha256",
        "universe_sha256",
        "total_file_count",
        "cursor_index",
        "window_end_index_exclusive",
        "window_capacity",
        "window_file_count",
        "completed_window_offsets",
        "active_pending_file_count",
        "has_more",
        "schedule_complete",
        "files",
    }
    if set(page) != expected_keys:
        raise ValueError("host-injected schedule page must use the exact neutral key set")
    cursor = page.get("cursor_index")
    if isinstance(cursor, bool) or not isinstance(cursor, int):
        raise ValueError("host-injected schedule page cursor must be an integer")
    completed_offsets = page.get("completed_window_offsets")
    normalized_order = _normalize_file_order(file_order)
    full_page_files = normalized_order[cursor : cursor + FROZEN_SCHEDULE_PAGE_SIZE]
    if (
        not isinstance(completed_offsets, list)
        or any(isinstance(value, bool) or not isinstance(value, int) for value in completed_offsets)
        or completed_offsets != sorted(set(completed_offsets))
        or any(
            value < 0 or value >= len(full_page_files)
            for value in completed_offsets
        )
    ):
        raise ValueError("host-injected schedule page completion offsets are invalid")
    completed_files = [
        *normalized_order[:cursor],
        *(full_page_files[offset] for offset in completed_offsets),
    ]
    expected = build_schedule_page(
        file_order,
        cursor=cursor,
        completed_files=completed_files,
    )
    expected_files = expected["files"]
    if page_files != expected_files:
        raise ValueError("host-injected schedule page is not the exact frozen slice")
    normalized = {**dict(page), "files": page_files}
    if normalized != expected:
        raise ValueError("host-injected schedule page metadata mismatch")
    return normalized
