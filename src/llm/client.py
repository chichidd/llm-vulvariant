import copy
import inspect
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set
import os
import time
import yaml
import threading
from dataclasses import dataclass
from pathlib import Path
from utils.claude_cli import aggregate_usage_summaries
from utils.llm_usage import (
    _first_present,
    _usage_get,
    build_empty_llm_usage_summary,
    summarize_chat_completion_usage,
)
from utils.number_utils import to_int
from utils.logger import get_logger

logger = get_logger(__name__)
# Sentinel that distinguishes "argument omitted" from "argument explicitly set to the default value".
_UNSET = object()


def capture_llm_usage_snapshot(llm_client: Any) -> Optional[int]:
    if llm_client is None:
        return None
    snapshot_fn = getattr(llm_client, "usage_history_snapshot", None)
    if callable(snapshot_fn):
        return snapshot_fn()
    return None


def aggregate_llm_usage_since(llm_client: Any, snapshot: Optional[int]) -> Dict[str, Any]:
    if llm_client is None or snapshot is None:
        summary = aggregate_usage_summaries([])
        summary["source"] = "llm_client"
        summary["provider"] = getattr(getattr(llm_client, "config", None), "provider", None)
        return summary

    aggregate_fn = getattr(llm_client, "aggregate_usage_since", None)
    if callable(aggregate_fn):
        return aggregate_fn(snapshot)

    summary = aggregate_usage_summaries([])
    summary["source"] = "llm_client"
    summary["provider"] = getattr(getattr(llm_client, "config", None), "provider", None)
    return summary


def safe_chat_call(llm_client: Any, messages: List[Dict[str, str]], **kwargs) -> Any:
    """Call ``chat`` with optional kwargs, falling back for lightweight test doubles.

    Some tests use simple dummy clients with ``chat(messages)`` signatures. This helper
    keeps runtime behavior (passing kwargs like ``temperature``) while preserving
    compatibility with those clients.
    """
    chat_fn = getattr(llm_client, "chat")
    if not kwargs:
        return chat_fn(messages)

    try:
        signature = inspect.signature(chat_fn)
    except (TypeError, ValueError):
        signature = None

    if signature is not None:
        accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
        if not accepts_kwargs:
            accepted_keyword_names = {
                param.name
                for param in signature.parameters.values()
                if param.kind in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            }
            if not set(kwargs).issubset(accepted_keyword_names):
                return chat_fn(messages)

    return chat_fn(messages, **kwargs)


def _default_llm_config() -> Dict[str, Any]:
    """Return the built-in fallback LLM configuration."""
    return {
        'llm': {
            'default': {
                'temperature': 0.1,
                'top_p': 0.9,
                'max_tokens': 0,
                'timeout': 120,
                'enable_thinking': True,
                'max_retries': 10,
                'initial_delay': 1.0,
                'max_delay': 60.0,
                'backoff_factor': 2.0,
            },
            'providers': {}
        }
    }


def load_llm_config_from_yaml(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load LLM configuration from a YAML file.

    Args:
        config_path: Path to the config file; uses a default path if not provided.

    Returns:
        A dict containing LLM configuration.
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent.parent / "config" / "llm_config.yaml"
    config_path = Path(config_path)

    if not config_path.exists():
        return _default_llm_config()

    try:
        raw_text = config_path.read_text(encoding='utf-8')
    except Exception as exc:
        raise RuntimeError(f"Failed to read LLM config: {config_path}: {exc}") from exc

    if not raw_text.strip():
        return _default_llm_config()

    try:
        config = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse LLM config: {config_path}: {exc}") from exc
    if config is None:
        return _default_llm_config()
    if isinstance(config, dict):
        return config
    raise RuntimeError(f"Invalid LLM config at {config_path}: top-level YAML must be a mapping")


@dataclass(init=False)
class LLMConfig:
    """LLM configuration."""
    provider: str = ""  # openai, deepseek, lab
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    fallback_provider: Optional[str] = None
    fallback_on_retry_exhausted: Optional[bool] = None
    temperature: float = 1.0
    top_p: float = 0.9
    max_tokens: int = 0
    timeout: int = 120
    context_limit: int = 0

    # Retry settings
    max_retries: int = 10  # Maximum retries
    initial_delay: float = 1.0  # Initial delay (seconds)
    max_delay: float = 60.0  # Maximum delay (seconds)
    backoff_factor: float = 2.0  # Exponential backoff factor
    

    enable_thinking: Optional[bool] = None  # DeepSeek thinking parameter

    def __init__(
        self,
        provider: str = "",
        model: str = "",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        fallback_provider: Any = _UNSET,
        fallback_on_retry_exhausted: Any = _UNSET,
        temperature: Any = _UNSET,
        top_p: Any = _UNSET,
        max_tokens: Any = _UNSET,
        timeout: Any = _UNSET,
        context_limit: Any = _UNSET,
        max_retries: Any = _UNSET,
        initial_delay: Any = _UNSET,
        max_delay: Any = _UNSET,
        backoff_factor: Any = _UNSET,
        enable_thinking: Any = _UNSET,
    ) -> None:
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.fallback_provider = None if fallback_provider is _UNSET else fallback_provider
        self.fallback_on_retry_exhausted = None if fallback_on_retry_exhausted is _UNSET else fallback_on_retry_exhausted
        self.temperature = 1.0 if temperature is _UNSET else temperature
        self.top_p = 0.9 if top_p is _UNSET else top_p
        self.max_tokens = 0 if max_tokens is _UNSET else max_tokens
        self.timeout = 120 if timeout is _UNSET else timeout
        self.context_limit = 0 if context_limit is _UNSET else context_limit
        self.max_retries = 10 if max_retries is _UNSET else max_retries
        self.initial_delay = 1.0 if initial_delay is _UNSET else initial_delay
        self.max_delay = 60.0 if max_delay is _UNSET else max_delay
        self.backoff_factor = 2.0 if backoff_factor is _UNSET else backoff_factor
        self.enable_thinking = None if enable_thinking is _UNSET else enable_thinking
        self._explicit_config_fields: Set[str] = {
            field_name
            for field_name, value in (
                ("temperature", temperature),
                ("top_p", top_p),
                ("max_tokens", max_tokens),
                ("timeout", timeout),
                ("context_limit", context_limit),
                ("fallback_provider", fallback_provider),
                ("fallback_on_retry_exhausted", fallback_on_retry_exhausted),
                ("max_retries", max_retries),
                ("initial_delay", initial_delay),
                ("max_delay", max_delay),
                ("backoff_factor", backoff_factor),
                ("enable_thinking", enable_thinking),
            )
            if value is not _UNSET
        }
        self.__post_init__()

    def __post_init__(self) -> None:
        """Auto-populate api_key/base_url based on provider, preferring YAML config."""
        explicit_fields = getattr(self, "_explicit_config_fields", set())
        # First try to load from YAML.
        yaml_config = load_llm_config_from_yaml()
        llm_config = yaml_config.get('llm', {})
        providers_config = llm_config.get('providers', {})
        default_config = llm_config.get('default', {})

        # If not explicitly set, use YAML defaults.
        if "temperature" not in explicit_fields and self.temperature == 1.0 and 'temperature' in default_config:
            self.temperature = default_config['temperature']
        if "top_p" not in explicit_fields and self.top_p == 0.9 and 'top_p' in default_config:
            self.top_p = default_config['top_p']
        if "timeout" not in explicit_fields and self.timeout == 120 and 'timeout' in default_config:
            self.timeout = default_config['timeout']
        if "max_retries" not in explicit_fields and self.max_retries == 10 and 'max_retries' in default_config:
            self.max_retries = default_config['max_retries']
        if "initial_delay" not in explicit_fields and self.initial_delay == 1.0 and 'initial_delay' in default_config:
            self.initial_delay = default_config['initial_delay']
        if "max_delay" not in explicit_fields and self.max_delay == 60.0 and 'max_delay' in default_config:
            self.max_delay = default_config['max_delay']
        if "backoff_factor" not in explicit_fields and self.backoff_factor == 2.0 and 'backoff_factor' in default_config:
            self.backoff_factor = default_config['backoff_factor']
        if "enable_thinking" not in explicit_fields and self.enable_thinking is None and 'enable_thinking' in default_config:
            self.enable_thinking = default_config['enable_thinking']

        # Load provider-specific config.
        if self.provider and self.provider in providers_config:
            provider_config = providers_config[self.provider]

            # Keep explicit credentials/model overrides from the caller.
            if not self.api_key and 'api_key_env' in provider_config:
                self.api_key = os.getenv(provider_config['api_key_env'])

            # Set other fields.
            if not self.base_url and 'base_url' in provider_config:
                self.base_url = provider_config['base_url']
            if not self.model and 'model' in provider_config:
                self.model = provider_config['model']
            if "fallback_provider" not in explicit_fields and not self.fallback_provider and 'fallback_provider' in provider_config:
                self.fallback_provider = provider_config['fallback_provider']
            if (
                "fallback_on_retry_exhausted" not in explicit_fields
                and self.fallback_on_retry_exhausted is None
                and 'fallback_on_retry_exhausted' in provider_config
            ):
                self.fallback_on_retry_exhausted = provider_config['fallback_on_retry_exhausted']
            if "max_tokens" not in explicit_fields and self.max_tokens == 0 and 'max_tokens' in provider_config:
                self.max_tokens = provider_config['max_tokens']
            if "context_limit" not in explicit_fields and self.context_limit == 0 and 'context_limit' in provider_config:
                self.context_limit = provider_config['context_limit']

        if self.fallback_on_retry_exhausted is None:
            self.fallback_on_retry_exhausted = False
        else:
            self.fallback_on_retry_exhausted = bool(self.fallback_on_retry_exhausted)

        # Backward compatibility: if YAML is missing fields, fill provider defaults.
        if self.provider == "deepseek":
            if not self.api_key:
                self.api_key = os.getenv("DEEPSEEK_API_KEY")
            if not self.base_url:
                self.base_url = "https://api.deepseek.com/v1"
            if not self.model:
                self.model = "deepseek-chat"
            if "max_tokens" not in explicit_fields and self.max_tokens == 0:
                self.max_tokens = 65536
            if "context_limit" not in explicit_fields and self.context_limit == 0:
                self.context_limit = 131072
        elif self.provider == "openai":
            if not self.api_key:
                self.api_key = os.getenv("NY_API_KEY")
            if not self.base_url:
                self.base_url = "https://ai.nengyongai.cn/v1"
            if not self.model:
                self.model = "gpt-5.1"
            if "max_tokens" not in explicit_fields and self.max_tokens == 0:
                self.max_tokens = 65536
            if "context_limit" not in explicit_fields and self.context_limit == 0:
                self.context_limit = 65536

        if self.enable_thinking is None:
            self.enable_thinking = True


class LLMRetryExhaustedError(Exception):
    """Raised when LLM retries are exhausted."""
    def __init__(self, message: str, last_error: Exception = None):
        super().__init__(message)
        self.last_error = last_error


class BaseLLMClient(ABC):
    """Base class for LLM clients."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self.context_limit = max(0, to_int(getattr(config, "context_limit", 0)))
        self._last_usage_summary = build_empty_llm_usage_summary(
            requested_model=config.model,
            provider=config.provider,
        )
        self._usage_history: List[Dict[str, Any]] = []
        self._usage_lock = threading.RLock()
        # Load retry settings from config
        # Always allow at least one real request, even when config sets 0 retries.
        self.max_retries = max(1, to_int(config.max_retries))
        self.config.max_retries = self.max_retries
        self.initial_delay = config.initial_delay
        self.max_delay = config.max_delay
        self.backoff_factor = config.backoff_factor
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                base_url=config.base_url
            )
        except ImportError:
            raise ImportError("Please install openai: pip install openai")

    def _normalize_usage_summary(self, usage_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return usage_summary or build_empty_llm_usage_summary(
            requested_model=self.config.model,
            provider=self.config.provider,
        )

    def _ensure_usage_lock(self) -> threading.RLock:
        """Return the usage lock, creating it lazily for test doubles."""
        lock = getattr(self, "_usage_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._usage_lock = lock
        return lock

    def _record_usage_summary(self, usage_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        summary = self._normalize_usage_summary(usage_summary)
        with self._ensure_usage_lock():
            self._last_usage_summary = copy.deepcopy(summary)
            self._usage_history.append(copy.deepcopy(summary))
            return copy.deepcopy(summary)

    def _set_last_usage_summary(self, usage_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        summary = self._normalize_usage_summary(usage_summary)
        with self._ensure_usage_lock():
            self._last_usage_summary = copy.deepcopy(summary)
            return copy.deepcopy(summary)

    def get_last_usage_summary(self) -> Dict[str, Any]:
        with self._ensure_usage_lock():
            return copy.deepcopy(self._last_usage_summary)

    def get_last_request_input_tokens(self) -> int:
        summary = self.get_last_usage_summary()
        selected_usage = summary.get("selected_model_usage") if isinstance(summary, dict) else None
        top_level_usage = summary.get("top_level_usage") if isinstance(summary, dict) else None
        return to_int(
            _first_present(
                _usage_get(selected_usage, "input_tokens"),
                _usage_get(top_level_usage, "input_tokens"),
            )
        )

    def get_last_request_output_tokens(self) -> int:
        summary = self.get_last_usage_summary()
        selected_usage = summary.get("selected_model_usage") if isinstance(summary, dict) else None
        top_level_usage = summary.get("top_level_usage") if isinstance(summary, dict) else None
        return to_int(
            _first_present(
                _usage_get(selected_usage, "output_tokens"),
                _usage_get(top_level_usage, "output_tokens"),
            )
        )

    def get_last_request_context_limit(self) -> int:
        summary = self.get_last_usage_summary()
        selected_usage = summary.get("selected_model_usage") if isinstance(summary, dict) else None
        reported_context_window = to_int(_usage_get(selected_usage, "context_window"))
        if reported_context_window > 0:
            return reported_context_window
        return max(0, to_int(getattr(self, "context_limit", 0)))

    def usage_history_snapshot(self) -> int:
        with self._ensure_usage_lock():
            return len(self._usage_history)

    def get_usage_history_since(self, snapshot: int) -> List[Dict[str, Any]]:
        start = max(0, int(snapshot))
        with self._ensure_usage_lock():
            return [copy.deepcopy(item) for item in self._usage_history[start:]]

    def aggregate_usage_since(self, snapshot: int) -> Dict[str, Any]:
        with self._ensure_usage_lock():
            summary = aggregate_usage_summaries(
                self.get_usage_history_since(snapshot),
                selected_model=self.config.model,
            )
        summary["source"] = "llm_client"
        summary["provider"] = self.config.provider
        return summary
    
    
    def _should_retry(self, exception: Exception) -> bool:
        """
        Decide whether an exception should trigger a retry.

        Args:
            exception: The caught exception.

        Returns:
            True if the call should be retried.
        """
        # Import OpenAI exceptions if available
        try:
            from openai import (
                APIConnectionError,
                RateLimitError,
                APITimeoutError,
                InternalServerError,
                APIStatusError,
            )
            # These errors should be retried
            retriable_exceptions = (
                APIConnectionError,  # Connection error
                RateLimitError,  # Rate limit
                APITimeoutError,  # Timeout
                InternalServerError,  # Internal server error (5xx)
            )
            if isinstance(exception, retriable_exceptions):
                return True
            # For APIStatusError, check status code
            if isinstance(exception, APIStatusError):
                # Retry on 5xx and 429 (rate limit)
                if exception.status_code >= 500 or exception.status_code == 429:
                    return True
        except ImportError:
            pass
        
        # Generic network errors
        import socket
        if isinstance(exception, (ConnectionError, TimeoutError, socket.timeout)):
            return True
        
        status_code = getattr(exception, "status_code", None)
        if isinstance(status_code, int) and (status_code >= 500 or status_code == 429):
            return True
        exception_name = type(exception).__name__
        if status_code is None and exception_name in {"APIConnectionError", "APITimeoutError"}:
            return True

        # Preserve parser/validation failures as non-retriable even when their
        # messages include retry-like words such as "timeout".
        if isinstance(exception, (TypeError, ValueError)):
            return False

        error_msg = str(exception).lower()
        retriable_keywords = [
            'rate limit', 'rate_limit', 'ratelimit',
            'timeout', 'timed out',
            'connection', 'network',
            'server error', 'internal error',
            'service unavailable', 'bad gateway',
            'overloaded', 'capacity',
        ]
        if any(keyword in error_msg for keyword in retriable_keywords):
            return True

        return False
    
    def _calculate_delay(self, attempt: int) -> float:
        """
        Compute retry delay using exponential backoff.

        Args:
            attempt: Current retry attempt (0-based).

        Returns:
            Delay in seconds.
        """
        delay = self.initial_delay * (self.backoff_factor ** attempt)
        # Add jitter (±10%)
        import random
        jitter = delay * 0.1 * (2 * random.random() - 1)
        delay = delay + jitter
        return min(delay, self.max_delay)

    def _get_normalized_fallback_provider(self) -> str:
        return str(self.config.fallback_provider or "").strip().lower()

    def _should_use_provider_fallback(self, exception: Exception) -> bool:
        return (
            self.config.provider == "lab"
            and bool(self.config.fallback_on_retry_exhausted)
            and self._get_normalized_fallback_provider() == "deepseek"
            and self._should_retry(exception)
        )

    def _execute_with_provider_fallback(
        self,
        request_name: str,
        *args: Any,
        exhausted_retries: int,
        final_exception: Exception,
        **kwargs: Any,
    ) -> Any:
        fallback_provider = self._get_normalized_fallback_provider()
        logger.warning(
            "LLM provider fallback starting: %s -> %s for %s after retry exhaustion "
            "(retries=%s, final_error=%s).",
            self.config.provider,
            fallback_provider,
            request_name,
            exhausted_retries,
            type(final_exception).__name__,
        )
        try:
            fallback_config = LLMConfig(
                provider=fallback_provider,
                temperature=self.config.temperature,
                top_p=self.config.top_p,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout,
                max_retries=self.max_retries,
                initial_delay=self.initial_delay,
                max_delay=self.max_delay,
                backoff_factor=self.backoff_factor,
                enable_thinking=self.config.enable_thinking,
                fallback_on_retry_exhausted=False,
            )
            fallback_client = create_llm_client(fallback_config)
            fallback_request = getattr(fallback_client, request_name, None)
            if not callable(fallback_request):
                raise AttributeError(
                    f"Fallback provider '{fallback_config.provider}' does not support request '{request_name}'"
                )
            usage_history_snapshot = capture_llm_usage_snapshot(fallback_client)
            result = fallback_request(*args, **kwargs)
            fallback_usage_history: List[Dict[str, Any]] = []
            get_usage_history_since = getattr(fallback_client, "get_usage_history_since", None)
            if usage_history_snapshot is not None and callable(get_usage_history_since):
                fallback_usage_history = get_usage_history_since(usage_history_snapshot)

            fallback_metadata = {
                "fallback_used": True,
                "fallback_from_provider": self.config.provider,
                "fallback_to_provider": fallback_config.provider,
            }
            if fallback_usage_history:
                for usage_summary in fallback_usage_history:
                    if not isinstance(usage_summary, dict):
                        continue
                    usage_summary = copy.deepcopy(usage_summary)
                    if not usage_summary.get("is_error"):
                        usage_summary.update(fallback_metadata)
                    self._record_usage_summary(usage_summary)
            else:
                fallback_summary = None
                get_last_usage_summary = getattr(fallback_client, "get_last_usage_summary", None)
                if callable(get_last_usage_summary):
                    fallback_summary = get_last_usage_summary()
                if not fallback_summary:
                    fallback_summary = build_empty_llm_usage_summary(
                        requested_model=fallback_config.model,
                        provider=fallback_config.provider,
                    )
                fallback_summary["is_error"] = False
                fallback_summary.update(fallback_metadata)
                self._record_usage_summary(fallback_summary)
            logger.info(
                "LLM provider fallback succeeded: %s -> %s for %s.",
                self.config.provider,
                fallback_config.provider,
                request_name,
            )
            return result
        except Exception as exc:
            logger.error(
                "LLM provider fallback failed: %s -> %s for %s: %s: %s",
                self.config.provider,
                fallback_provider,
                request_name,
                type(exc).__name__,
                exc,
            )
            raise
    
    def _execute_with_retry(self, func, *args, **kwargs) -> Any:
        """
        Execute a function with retry logic.

        Args:
            func: Function to execute.
            *args: Positional args.
            **kwargs: Keyword args.

        Returns:
            Function result.

        Raises:
            LLMRetryExhaustedError: When retries are exhausted.
        """
        func_name = getattr(func, "__name__", "")
        request_name = None
        if func_name == "_make_chat_request":
            request_name = "chat"
        elif func_name in {"_make_complete_request", "_make_completion_request"}:
            request_name = "complete"

        last_exception = None

        for attempt in range(self.max_retries):
            with self._ensure_usage_lock():
                usage_history_start = len(self._usage_history)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                with self._ensure_usage_lock():
                    usage_history_len = len(self._usage_history)
                if usage_history_len == usage_history_start:
                    error_summary = build_empty_llm_usage_summary(
                        requested_model=self.config.model,
                        provider=self.config.provider,
                        is_error=True,
                    )
                else:
                    error_summary = self.get_last_usage_summary()
                    error_summary["is_error"] = True
                self._set_last_usage_summary(error_summary)
                
                # Decide whether to retry
                if not self._should_retry(e):
                    logger.error(f"!!!!\n\n\nNon-retriable error occurred: {type(e).__name__}: {e}\n\n\n!!!!\n\n\n")
                    raise
                
                # Check whether we have remaining retries
                if attempt < self.max_retries - 1:
                    delay = self._calculate_delay(attempt)
                    logger.warning(
                        f"LLM API error (attempt {attempt + 1}/{self.max_retries}): "
                        f"{type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        f"LLM API error (attempt {attempt + 1}/{self.max_retries}): "
                        f"{type(e).__name__}: {e}. No more retries."
                    )
                    if request_name and self._should_use_provider_fallback(e):
                        return self._execute_with_provider_fallback(
                            request_name,
                            *args,
                            exhausted_retries=self.max_retries,
                            final_exception=e,
                            **kwargs,
                        )
        
        raise LLMRetryExhaustedError(
            f"Failed after {self.max_retries} attempts. Last error: {last_exception}",
            last_error=last_exception
        )
    
    @abstractmethod
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> str:
        """Send a chat request.

        Args:
            messages: List of messages.
            tools: Optional tool definitions (OpenAI format).
            **kwargs: Other parameters.

        Returns:
            Response content string (or a dict containing tool_calls).
        """
        raise NotImplementedError("Subclasses must implement chat method")
    
    @abstractmethod
    def complete(self, prompt: str, **kwargs) -> str:
        """Send a completion request."""
        raise NotImplementedError("Subclasses must implement complete method")
    


class OpenAIClient(BaseLLMClient):
    """OpenAI client with automatic retries and tool calling support."""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        
    def _make_chat_request(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """Execute the underlying chat request (internal helper)."""
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "timeout": kwargs.get("timeout", self.config.timeout),
            "stream": False,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        response_format = kwargs.get("response_format")
        if response_format is not None:
            request_params["response_format"] = response_format
        
        # Add tools parameters
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        response = self.client.chat.completions.create(**request_params)
        self._record_usage_summary(
            summarize_chat_completion_usage(
                response,
                requested_model=self.config.model,
                provider=self.config.provider,
            )
        )
        return response.choices[0].message
    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """Send a chat request (with retry logic)."""
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)




class DeepSeekClient(BaseLLMClient):
    """DeepSeek client supporting tool calling and thinking mode."""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if self.context_limit <= 0:
            self.context_limit = 131072

    def _process_extra_body(self, kwargs) -> Dict[str, Any]:
        if self.config.enable_thinking:

            if self.config.provider == "deepseek":
                return {"thinking": {"type": "enabled"}}
            
        return {}

    def _make_chat_request(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """Execute the underlying chat request (internal helper).

        Args:
            messages: List of messages.
            tools: Optional tool definitions.
            **kwargs: Other parameters.
                - tool_choice: Tool selection strategy: "none"/"auto"/"required"

        """
        # Add a system message if missing
        if not any(m.get("role") == "system" for m in messages):
            messages = [
                {"role": "system", "content": "You are a helpful AI assistant specialized in code security analysis."},
                *messages
            ]
        
        
        
        # Build base request parameters
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "timeout": kwargs.get("timeout", self.config.timeout),
            "stream": False,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        response_format = kwargs.get("response_format")
        if response_format is not None:
            request_params["response_format"] = response_format
        
        request_params["extra_body"] = self._process_extra_body(kwargs)

        # Add tools parameters
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        # Send request
        response = self.client.chat.completions.create(**request_params)
        self._record_usage_summary(
            summarize_chat_completion_usage(
                response,
                requested_model=self.config.model,
                provider=self.config.provider,
            )
        )

        return response.choices[0].message

    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """Send a chat request (with retry logic).

        Args:
            messages: List of messages.
            tools: Optional tool definitions.
            **kwargs: Other parameters.
                - tool_choice: Tool choice: "none"/"auto"/"required" (when tools are provided)
                - separate_reasoning: bool, whether to return separate reasoning and content when there are no tool_calls

        Returns:
            Different formats depending on response type:
            - With tool_calls: {"content": str, "tool_calls": [...], "reasoning": str (if thinking enabled)}
            - No tool_calls and separate_reasoning=True: {"reasoning": str, "content": str}
            - Otherwise: str (merged content)
        """
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        """Send a completion request (translated into chat format)."""
        return self.chat([{"role": "user", "content": prompt}], **kwargs)
    



def create_llm_client(config: LLMConfig) -> BaseLLMClient:
    """Create an LLM client."""
    providers = {
        "openai": OpenAIClient,
        "deepseek": DeepSeekClient,
        "lab": OpenAIClient,
    }
    
    client_class = providers.get(config.provider)
    if not client_class:
        raise ValueError(f"Unknown LLM provider: {config.provider}. Available: {list(providers.keys())}")
    
    return client_class(config)
