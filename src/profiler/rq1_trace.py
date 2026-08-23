"""RQ1 内部实验的最小画像追踪器。

设置 ``RQ1_PROFILE_TRACE_DIR`` 和 ``RQ1_PROFILE_TRACE_ID`` 后启用。每次真实
LLM 调用、阶段解析结果和最终画像都会写成独立的 canonical JSON。默认关闭，
不改变普通画像流程。
"""

from __future__ import annotations

import atexit
import contextlib
import contextvars
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping


SCHEMA_VERSION = "rq1-internal-profile-trace-v1"
PARSER_RULE_IDS = {"parse-llm-json-v1", "agent-finalize-tool-v1", "derived-no-llm-v1"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|bearer|credential|password|secret|"
    r"access[_-]?token|refresh[_-]?token|token)(?:$|[_-])",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_AUTHORIZATION_CREDENTIAL = re.compile(
    r"(?im)(?P<prefix>\b(?:[A-Za-z0-9.-]+[_-])*(?:proxy[_-])?"
    r"authorization\s*(?::|=)\s*"
    r"(?:basic|digest|token)\s+)(?!\[REDACTED\])[^\r\n]+"
)
_QUOTED_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<prefix>
        ["']?(?:[A-Za-z0-9.-]+[_-])*
        (?:api[_-]?key|authorization|credential|password|secret|
           access[_-]?token|refresh[_-]?token|auth[_-]?token|token)
        (?:[_-][A-Za-z0-9.-]+)*["']?\s*[:=]\s*
    )
    (?P<quote>["'])(?P<value>.*?)(?P=quote)
    """
)
_UNQUOTED_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<prefix>
        (?:[A-Za-z0-9.-]+[_-])*
        (?:api[_-]?key|authorization|credential|password|secret|
           access[_-]?token|refresh[_-]?token|auth[_-]?token|token)
        (?:[_-][A-Za-z0-9.-]+)*\s*[:=]\s*
    )
    (?P<value>[^\s,;}\]"']+)
    """
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_URL_CREDENTIAL = re.compile(
    r"(?i)(?P<scheme>\b[a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@"
)
_TRACE_ROOT = re.compile(
    r"^results/rq1-experiment/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/trace$"
)
_REVISION_ROOT = Path(__file__).resolve(strict=True).parents[4]
_CURRENT_STAGE: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("rq1_profile_trace_stage", default=None)
)
_CURRENT_CALL: contextvars.ContextVar[dict[str, Any] | None] = (
    contextvars.ContextVar("rq1_profile_trace_call", default=None)
)
_LOCK = threading.RLock()
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_RENAME_NOREPLACE = 1
try:
    _RENAMEAT2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    _RENAMEAT2 = None
else:
    _RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int


@dataclass
class _TraceRun:
    logical_root: Path
    run_id: str
    directory_fds: tuple[int, ...]
    relations: tuple[tuple[int, str, int], ...]
    trace_fd: int
    run_fd: int
    sequence: int = 0
    poisoned: bool = False


_RUNS: dict[tuple[str, str], _TraceRun] = {}


def utc_now() -> str:
    """返回 UTC RFC3339 时间。"""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _jsonable(model_dump(mode="json"))
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _jsonable(to_dict())
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return repr(value)


def _redact(value: Any, *, key: str = "") -> Any:
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {name: _redact(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        rendered = _BEARER.sub("Bearer [REDACTED]", value)
        rendered = _AUTHORIZATION_CREDENTIAL.sub(
            lambda match: f"{match.group('prefix')}[REDACTED]",
            rendered,
        )
        rendered = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", rendered)
        rendered = _URL_CREDENTIAL.sub(
            lambda match: f"{match.group('scheme')}[REDACTED]@",
            rendered,
        )
        rendered = _QUOTED_SECRET_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group('prefix')}{match.group('quote')}"
                f"[REDACTED]{match.group('quote')}"
            ),
            rendered,
        )
        rendered = _UNQUOTED_SECRET_ASSIGNMENT.sub(
            lambda match: f"{match.group('prefix')}[REDACTED]",
            rendered,
        )
        for name, secret in os.environ.items():
            if secret and _SECRET_KEY.search(name):
                rendered = rendered.replace(secret, "[REDACTED]")
        return rendered
    return value


def _trace_settings() -> tuple[Path, str] | None:
    raw_root = os.environ.get("RQ1_PROFILE_TRACE_DIR")
    if not raw_root:
        return None
    trace_id = os.environ.get("RQ1_PROFILE_TRACE_ID", "")
    if not _SAFE_ID.fullmatch(trace_id):
        raise RuntimeError(
            "启用 RQ1 trace 时必须提供安全且非空的 RQ1_PROFILE_TRACE_ID"
        )
    if not _TRACE_ROOT.fullmatch(raw_root) or "\\" in raw_root:
        raise RuntimeError("RQ1_PROFILE_TRACE_DIR 必须是冻结的 revision 相对路径")
    relative = Path(raw_root)
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise RuntimeError("RQ1_PROFILE_TRACE_DIR 含不安全路径分量")
    return _REVISION_ROOT.joinpath(*relative.parts), trace_id


def trace_enabled() -> bool:
    """返回当前进程是否启用 RQ1 trace。"""

    return bool(os.environ.get("RQ1_PROFILE_TRACE_DIR"))


def profile_cache_allowed(force_regenerate: bool) -> bool:
    """RQ1 trace 启用时禁用画像缓存，保证本次调用有完整 trace。"""

    return not force_regenerate and not trace_enabled()


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _open_bound_child(
    parent_fd: int,
    name: str,
    *,
    create: bool,
    exclusive: bool,
) -> int:
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError as exc:
            if exclusive:
                raise RuntimeError("RQ1 trace_id 已存在，拒绝复用") from exc
        except OSError as exc:
            raise RuntimeError(f"无法创建 RQ1 trace 目录分量: {name}") from exc
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        bound = os.fstat(descriptor)
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise RuntimeError(f"RQ1 trace 路径不是无链接物理目录: {name}") from exc
    if (
        not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(bound.st_mode)
        or not _same_inode(named, bound)
    ):
        os.close(descriptor)
        raise RuntimeError(f"RQ1 trace 目录绑定失败: {name}")
    return descriptor


def _create_trace_run(root: Path, run_id: str) -> _TraceRun:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("当前平台缺少 RQ1 trace 所需的安全目录打开能力")
    try:
        relative = root.relative_to(_REVISION_ROOT)
    except ValueError as exc:
        raise RuntimeError("RQ1 trace 根目录逃出 revision") from exc
    descriptors: list[int] = []
    relations: list[tuple[int, str, int]] = []
    try:
        revision_fd = os.open(_REVISION_ROOT, _DIR_FLAGS)
        descriptors.append(revision_fd)
        current_fd = revision_fd
        for part in relative.parts:
            child_fd = _open_bound_child(
                current_fd,
                part,
                create=True,
                exclusive=False,
            )
            descriptors.append(child_fd)
            relations.append((current_fd, part, child_fd))
            current_fd = child_fd
        trace_fd = current_fd
        run_fd = _open_bound_child(
            trace_fd,
            run_id,
            create=True,
            exclusive=True,
        )
        descriptors.append(run_fd)
        relations.append((trace_fd, run_id, run_fd))
        return _TraceRun(
            logical_root=root,
            run_id=run_id,
            directory_fds=tuple(descriptors),
            relations=tuple(relations),
            trace_fd=trace_fd,
            run_fd=run_fd,
        )
    except Exception:
        for descriptor in reversed(descriptors):
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise


def _verify_trace_run(run: _TraceRun) -> None:
    revision_named = os.stat(_REVISION_ROOT, follow_symlinks=False)
    revision_bound = os.fstat(run.directory_fds[0])
    if (
        not stat.S_ISDIR(revision_named.st_mode)
        or not _same_inode(revision_named, revision_bound)
    ):
        raise RuntimeError("RQ1 revision 根目录绑定已失效")
    for parent_fd, name, child_fd in run.relations:
        try:
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            bound = os.fstat(child_fd)
        except OSError as exc:
            raise RuntimeError("RQ1 trace 目录绑定已失效") from exc
        if (
            not stat.S_ISDIR(named.st_mode)
            or not stat.S_ISDIR(bound.st_mode)
            or not _same_inode(named, bound)
        ):
            raise RuntimeError("RQ1 trace 目录绑定已失效")


def _trace_run(root: Path, run_id: str) -> _TraceRun:
    key = (str(root), run_id)
    run = _RUNS.get(key)
    if run is None:
        run = _create_trace_run(root, run_id)
        _RUNS[key] = run
    _verify_trace_run(run)
    if run.poisoned:
        raise RuntimeError("RQ1 trace 写入已失败，拒绝继续使用该 trace_id")
    return run


def _next_sequence(root: Path, run_id: str) -> int:
    with _LOCK:
        run = _trace_run(root, run_id)
        run.sequence += 1
        return run.sequence


def _rename_noreplace(directory_fd: int, source: str, target: str) -> None:
    if _RENAMEAT2 is None:
        raise RuntimeError("当前平台缺少 renameat2，无法安全提交 RQ1 trace 事件")
    result = _RENAMEAT2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(target),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise RuntimeError("RQ1 trace 事件文件已存在，拒绝覆盖")
    raise OSError(error, os.strerror(error), target)


def _close_trace_runs() -> None:
    with _LOCK:
        runs = tuple(_RUNS.values())
        _RUNS.clear()
    for run in runs:
        for descriptor in reversed(run.directory_fds):
            with contextlib.suppress(OSError):
                os.close(descriptor)


atexit.register(_close_trace_runs)


def _safe_component(value: str) -> str:
    rendered = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return rendered[:80] or "event"


def _write_event(event: Mapping[str, Any]) -> Path | None:
    settings = _trace_settings()
    if settings is None:
        return None
    root, run_id = settings
    with _LOCK:
        run = _trace_run(root, run_id)
        sequence = run.sequence + 1
        payload = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "sequence": sequence,
            **_redact(_jsonable(dict(event))),
        }
        payload["payload_sha256"] = hashlib.sha256(
            _canonical_bytes(payload)
        ).hexdigest()
        raw = _canonical_bytes(payload)
        event_type = _safe_component(str(payload.get("event_type", "event")))
        stage = _safe_component(str(payload.get("stage", "run")))
        filename = f"{sequence:06d}-{event_type}-{stage}.json"
        temporary = f".tmp-{sequence:06d}-{uuid.uuid4().hex}"
        if _next_sequence(root, run_id) != sequence:
            raise RuntimeError("RQ1 trace 事件序号竞争")
        descriptor: int | None = None
        published = False
        try:
            descriptor = os.open(temporary, _FILE_FLAGS, 0o600, dir_fd=run.run_fd)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("RQ1 trace 事件写入未前进")
                offset += written
            os.fsync(descriptor)
            temporary_info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(temporary_info.st_mode)
                or temporary_info.st_nlink != 1
            ):
                raise RuntimeError("RQ1 trace 临时事件不是单链接普通文件")
            _rename_noreplace(run.run_fd, temporary, filename)
            published = True
            final_info = os.stat(
                filename,
                dir_fd=run.run_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(final_info.st_mode)
                or final_info.st_nlink != 1
                or not _same_inode(temporary_info, final_info)
            ):
                raise RuntimeError("RQ1 trace 最终事件绑定失败")
            os.fsync(run.run_fd)
            _verify_trace_run(run)
        except Exception:
            run.poisoned = True
            if not published:
                with contextlib.suppress(OSError):
                    os.unlink(temporary, dir_fd=run.run_fd)
                    os.fsync(run.run_fd)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return root / run_id / filename


def model_metadata(client: Any) -> dict[str, Any]:
    """只提取模型身份。"""

    config = getattr(client, "config", None)
    return {
        "provider": str(getattr(config, "provider", "") or ""),
        "model": str(getattr(config, "model", "") or ""),
    }


def policy_metadata(client: Any) -> dict[str, Any]:
    """记录不含密钥的完整调用策略。"""

    config = getattr(client, "config", None)
    return {
        "endpoint": {
            "base_url": str(getattr(config, "base_url", "") or "").rstrip("/"),
            "operation": "chat.completions.create",
        },
        "decoding": {
            "temperature": getattr(config, "temperature", None),
            "top_p": getattr(config, "top_p", None),
            "max_tokens": getattr(config, "max_tokens", None),
            "context_limit": getattr(config, "context_limit", None),
            "timeout_seconds": getattr(config, "timeout", None),
            "enable_thinking": getattr(config, "enable_thinking", None),
            "reasoning_effort": getattr(config, "reasoning_effort", None),
            "service_tier": getattr(config, "service_tier", None),
            "enforce_exact_decoding": bool(
                getattr(config, "enforce_exact_decoding", False)
            ),
        },
        "retry_policy": {
            "max_provider_invocations": getattr(config, "max_retries", None),
            "sdk_max_retries": getattr(client, "sdk_max_retries", None),
            "initial_delay_seconds": getattr(config, "initial_delay", None),
            "max_delay_seconds": getattr(config, "max_delay", None),
            "backoff_factor": getattr(config, "backoff_factor", None),
            "jitter_ratio": 0.1,
        },
        "fallback_policy": {
            "enabled": bool(
                getattr(config, "fallback_on_retry_exhausted", False)
            ),
            "provider": getattr(config, "fallback_provider", None),
        },
    }


@contextlib.contextmanager
def trace_stage(
    kind: str,
    identity: Mapping[str, Any],
    stage: str,
) -> Iterator[None]:
    """给本上下文中的底层 LLM 调用附加画像阶段。"""

    token = _CURRENT_STAGE.set(
        {
            "kind": kind,
            "identity": _jsonable(identity),
            "stage": stage,
            "call_sequences": [],
            "call_statuses": [],
        }
    )
    try:
        yield
    finally:
        _CURRENT_STAGE.reset(token)


def install_client_trace(client: Any) -> Any:
    """记录每个逻辑调用及其全部 provider invocation。"""

    if client is None or not trace_enabled():
        return client
    if getattr(client, "_rq1_trace_installed", False):
        return client
    original_chat = getattr(client, "chat", None)
    try:
        completions = client.client.chat.completions
        original_create = completions.create
    except AttributeError as exc:
        raise RuntimeError(
            "RQ1 trace 需要可包装的 client.chat.completions.create"
        ) from exc
    if not callable(original_chat) or not callable(original_create):
        raise RuntimeError("RQ1 trace 的 chat/create 不可调用")
    if (
        getattr(client, "sdk_max_retries", None) != 0
        or getattr(client.client, "max_retries", None) != 0
    ):
        raise RuntimeError("RQ1 trace 要求显式禁用 SDK 内部重试")

    def traced_create(*args: Any, **kwargs: Any) -> Any:
        call = _CURRENT_CALL.get()
        if call is None:
            raise RuntimeError("provider invocation 未绑定高层 RQ1 call")
        attempt_index = len(call["provider_invocation_sequences"]) + 1
        started_at = utc_now()
        try:
            response = original_create(*args, **kwargs)
        except Exception as exc:
            event_path = _write_event(
                {
                    "event_type": "provider_invocation",
                    "kind": call["kind"],
                    "identity": call["identity"],
                    "stage": call["stage"],
                    "call_id": call["call_id"],
                    "attempt_index": attempt_index,
                    "capture_scope": (
                        "openai_chat_completions_create_sdk_retries_disabled"
                    ),
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "status": "failed",
                    "request": {"args": args, "kwargs": kwargs},
                    "response": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            if event_path is not None:
                call["provider_invocation_sequences"].append(
                    int(event_path.name.split("-", 1)[0])
                )
                call["provider_invocation_statuses"].append("failed")
            raise
        event_path = _write_event(
            {
                "event_type": "provider_invocation",
                "kind": call["kind"],
                "identity": call["identity"],
                "stage": call["stage"],
                "call_id": call["call_id"],
                "attempt_index": attempt_index,
                "capture_scope": (
                    "openai_chat_completions_create_sdk_retries_disabled"
                ),
                "started_at": started_at,
                "completed_at": utc_now(),
                "status": "completed",
                "request": {"args": args, "kwargs": kwargs},
                "response": response,
                "error": None,
            }
        )
        if event_path is not None:
            call["provider_invocation_sequences"].append(
                int(event_path.name.split("-", 1)[0])
            )
            call["provider_invocation_statuses"].append("completed")
        return response

    def traced_chat(*args: Any, **kwargs: Any) -> Any:
        stage_context = _CURRENT_STAGE.get()
        if stage_context is None:
            raise RuntimeError("RQ1 trace 拒绝未绑定画像阶段的 LLM 调用")
        call = {
            "kind": stage_context["kind"],
            "identity": stage_context["identity"],
            "stage": stage_context["stage"],
            "call_id": uuid.uuid4().hex,
            "provider_invocation_sequences": [],
            "provider_invocation_statuses": [],
        }
        token = _CURRENT_CALL.set(call)
        started_at = utc_now()
        request = {"args": args, "kwargs": kwargs}
        try:
            try:
                response = original_chat(*args, **kwargs)
                if not call["provider_invocation_sequences"]:
                    raise RuntimeError("RQ1 trace 未捕获 provider invocation")
                if call["provider_invocation_statuses"][-1] != "completed":
                    raise RuntimeError(
                        "RQ1 trace 最后一次 provider invocation 未完成"
                    )
            except Exception as exc:
                event_path = _write_event(
                    {
                        "event_type": "llm_call",
                        "kind": call["kind"],
                        "identity": call["identity"],
                        "stage": call["stage"],
                        "call_id": call["call_id"],
                        "provider_invocation_sequences": call[
                            "provider_invocation_sequences"
                        ],
                        "accepted_provider_sequence": None,
                        "started_at": started_at,
                        "completed_at": utc_now(),
                        "status": "failed",
                        "model": model_metadata(client),
                        "policy": policy_metadata(client),
                        "request": request,
                        "response": None,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                if event_path is not None:
                    stage_context["call_sequences"].append(
                        int(event_path.name.split("-", 1)[0])
                    )
                    stage_context["call_statuses"].append("failed")
                raise
            event_path = _write_event(
                {
                    "event_type": "llm_call",
                    "kind": call["kind"],
                    "identity": call["identity"],
                    "stage": call["stage"],
                    "call_id": call["call_id"],
                    "provider_invocation_sequences": call[
                        "provider_invocation_sequences"
                    ],
                    "accepted_provider_sequence": call[
                        "provider_invocation_sequences"
                    ][-1],
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "status": "completed",
                    "model": model_metadata(client),
                    "policy": policy_metadata(client),
                    "request": request,
                    "response": response,
                    "error": None,
                }
            )
            if event_path is not None:
                stage_context["call_sequences"].append(
                    int(event_path.name.split("-", 1)[0])
                )
                stage_context["call_statuses"].append("completed")
            return response
        finally:
            _CURRENT_CALL.reset(token)

    completions.create = traced_create
    client.chat = traced_chat
    client._rq1_trace_installed = True
    return client


def record_stage_result(
    *,
    kind: str,
    identity: Mapping[str, Any],
    stage: str,
    parser_rule_id: str,
    result: Any,
    usage: Any = None,
    status: str = "completed",
    error: str | None = None,
) -> Path | None:
    """记录 profiler 实际采用的阶段结果。"""
    if parser_rule_id not in PARSER_RULE_IDS:
        raise ValueError(f"未知 RQ1 parser_rule_id: {parser_rule_id}")

    context = _CURRENT_STAGE.get()
    call_sequences: list[int] = []
    call_statuses: list[str] = []
    if (
        context is not None
        and context["kind"] == kind
        and context["identity"] == _jsonable(identity)
        and context["stage"] == stage
    ):
        call_sequences = list(context["call_sequences"])
        call_statuses = list(context["call_statuses"])
    accepted_call_sequence = (
        call_sequences[-1]
        if (
            status == "completed"
            and call_sequences
            and call_statuses[-1] == "completed"
        )
        else None
    )
    return _write_event(
        {
            "event_type": "stage_result",
            "kind": kind,
            "identity": identity,
            "stage": stage,
            "completed_at": utc_now(),
            "status": status,
            "call_sequences": call_sequences,
            "accepted_call_sequence": accepted_call_sequence,
            "parser_rule_id": parser_rule_id,
            "result": result,
            "usage": usage,
            "error": error,
        }
    )


def record_final_profile(
    *, kind: str, identity: Mapping[str, Any], profile: Any
) -> Path | None:
    """记录最终写出的画像语义内容。"""

    value = profile.to_dict() if callable(getattr(profile, "to_dict", None)) else profile
    return _write_event(
        {
            "event_type": "final_profile",
            "kind": kind,
            "identity": identity,
            "stage": "final_profile",
            "completed_at": utc_now(),
            "status": "completed",
            "profile": value,
        }
    )


def verify_trace_directory(path: Path, *, expected_run_id: str | None = None) -> dict[str, Any]:
    """离线验证 trace 哈希、顺序、阶段闭包和密钥脱敏。"""

    root = path.resolve(strict=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("trace path 必须是物理目录")
    documents: list[dict[str, Any]] = []
    for item in sorted(root.iterdir(), key=lambda value: value.name.encode("utf-8")):
        info = os.lstat(item)
        if not stat.S_ISREG(info.st_mode) or item.is_symlink():
            raise ValueError(f"trace 目录含非普通文件: {item.name}")
        document = json.loads(item.read_text(encoding="utf-8"))
        declared = document.pop("payload_sha256", None)
        actual = hashlib.sha256(_canonical_bytes(document)).hexdigest()
        document["payload_sha256"] = declared
        if declared != actual:
            raise ValueError(f"trace 哈希不匹配: {item.name}")
        if expected_run_id is not None and document.get("run_id") != expected_run_id:
            raise ValueError(f"trace run_id 不匹配: {item.name}")
        if _redact(document) != document:
            raise ValueError(f"trace 含疑似密钥: {item.name}")
        documents.append(document)
    if not documents:
        raise ValueError("trace 目录为空")
    sequences = [int(item["sequence"]) for item in documents]
    if sequences != list(range(1, len(documents) + 1)):
        raise ValueError("trace sequence 不连续")
    successful_calls = {
        int(item["sequence"]): item
        for item in documents
        if item.get("event_type") == "llm_call" and item.get("status") == "completed"
    }
    for item in documents:
        if item.get("event_type") != "stage_result":
            continue
        expected_parser = (
            "derived-no-llm-v1"
            if item.get("status") == "derived"
            else "agent-finalize-tool-v1"
            if item.get("stage") == "module_analysis"
            else "parse-llm-json-v1"
        )
        if item.get("parser_rule_id") != expected_parser:
            raise ValueError(f"阶段 parser rule 不匹配: {item.get('stage')}")
        if item.get("status") != "completed":
            continue
        accepted = item.get("accepted_call_sequence")
        call = successful_calls.get(accepted)
        if accepted not in item.get("call_sequences", []) or call is None:
            raise ValueError(f"阶段结果缺少成功 LLM 调用: {item.get('stage')}")
        if any(call.get(key) != item.get(key) for key in ("kind", "identity", "stage")):
            raise ValueError(f"阶段结果绑定了其他阶段的 LLM 调用: {item.get('stage')}")
    finals = [item for item in documents if item.get("event_type") == "final_profile"]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": documents[0]["run_id"],
        "events": len(documents),
        "llm_calls": sum(item.get("event_type") == "llm_call" for item in documents),
        "stage_results": sum(
            item.get("event_type") == "stage_result" for item in documents
        ),
        "final_profiles": len(finals),
    }


__all__ = [
    "SCHEMA_VERSION",
    "PARSER_RULE_IDS",
    "install_client_trace",
    "model_metadata",
    "policy_metadata",
    "profile_cache_allowed",
    "record_final_profile",
    "record_stage_result",
    "trace_enabled",
    "trace_stage",
    "utc_now",
    "verify_trace_directory",
]
