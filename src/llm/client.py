import copy
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
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
    if not kwargs:
        return llm_client.chat(messages)
    try:
        return llm_client.chat(messages, **kwargs)
    except TypeError as exc:
        if "unexpected keyword argument" in str(exc):
            return llm_client.chat(messages)
        raise


def load_llm_config_from_yaml(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load LLM configuration from a YAML file.

    Args:
        config_path: Path to the config file; uses a default path if not provided.

    Returns:
        A dict containing LLM configuration.
    """
    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "llm_config.yaml"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if isinstance(config, dict):
                return config
    except Exception as e:
        import logging
        logging.debug(f"Failed to load LLM config: {e}")
    
    # Defaults
    return {
        'llm': {
            'default': {
                'temperature': 1.0,
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


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: str = ""  # openai, deepseek
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
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
    

    enable_thinking: bool = True  # DeepSeek thinking parameter
    
    def __post_init__(self):
        """Auto-populate api_key/base_url based on provider, preferring YAML config."""
        # First try to load from YAML
        yaml_config = load_llm_config_from_yaml()
        llm_config = yaml_config.get('llm', {})
        providers_config = llm_config.get('providers', {})
        default_config = llm_config.get('default', {})
        
        # If not explicitly set, use defaults
        if self.temperature == 1.0 and 'temperature' in default_config:
            self.temperature = default_config['temperature']
        if self.top_p == 0.9 and 'top_p' in default_config:
            self.top_p = default_config['top_p']
        if self.timeout == 120 and 'timeout' in default_config:
            self.timeout = default_config['timeout']
        if self.max_retries == 10 and 'max_retries' in default_config:
            self.max_retries = default_config['max_retries']
        if self.initial_delay == 1.0 and 'initial_delay' in default_config:
            self.initial_delay = default_config['initial_delay']
        if self.max_delay == 60.0 and 'max_delay' in default_config:
            self.max_delay = default_config['max_delay']
        if self.backoff_factor == 2.0 and 'backoff_factor' in default_config:
            self.backoff_factor = default_config['backoff_factor']
        if 'enable_thinking' in default_config:
            self.enable_thinking = default_config['enable_thinking']
        
        # Load provider-specific config
        if self.provider and self.provider in providers_config:
            provider_config = providers_config[self.provider]
            
            # Keep explicit credentials/model overrides from the caller.
            if not self.api_key and 'api_key_env' in provider_config:
                self.api_key = os.getenv(provider_config['api_key_env'])
            
            # Set other fields
            if not self.base_url and 'base_url' in provider_config:
                self.base_url = provider_config['base_url']
            if not self.model and 'model' in provider_config:
                self.model = provider_config['model']
            if self.max_tokens == 0 and 'max_tokens' in provider_config:
                self.max_tokens = provider_config['max_tokens']
            if self.context_limit == 0 and 'context_limit' in provider_config:
                self.context_limit = provider_config['context_limit']
        
        # Backward compatibility: if YAML has no config, use hardcoded defaults
        if self.provider and not self.base_url:
            if self.provider == "deepseek":
                # DeepSeek API
                if not self.api_key:
                    self.api_key = os.getenv("DEEPSEEK_API_KEY")
                self.base_url = "https://api.deepseek.com/v1"
                if not self.model:
                    self.model = "deepseek-chat"
                if self.max_tokens == 0:
                    self.max_tokens = 65536
                if self.context_limit == 0:
                    self.context_limit = 131072
            elif self.provider == "openai":
                if not self.api_key:
                    self.api_key = os.getenv("NY_API_KEY")
                self.base_url = "https://ai.nengyongai.cn/v1"
                if not self.model:
                    self.model = "gpt-5.1"
                if self.max_tokens == 0:
                    self.max_tokens = 65536
                if self.context_limit == 0:
                    self.context_limit = 65536
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

    def _record_usage_summary(self, usage_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        summary = self._normalize_usage_summary(usage_summary)
        with self._usage_lock:
            self._last_usage_summary = copy.deepcopy(summary)
            self._usage_history.append(copy.deepcopy(summary))
            return copy.deepcopy(summary)

    def _set_last_usage_summary(self, usage_summary: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        summary = self._normalize_usage_summary(usage_summary)
        with self._usage_lock:
            self._last_usage_summary = copy.deepcopy(summary)
            return copy.deepcopy(summary)

    def get_last_usage_summary(self) -> Dict[str, Any]:
        with self._usage_lock:
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
        with self._usage_lock:
            return len(self._usage_history)

    def get_usage_history_since(self, snapshot: int) -> List[Dict[str, Any]]:
        start = max(0, int(snapshot))
        with self._usage_lock:
            return [copy.deepcopy(item) for item in self._usage_history[start:]]

    def aggregate_usage_since(self, snapshot: int) -> Dict[str, Any]:
        with self._usage_lock:
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
        
        # Check keywords in the error message
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
        last_exception = None
        
        for attempt in range(self.max_retries):
            with self._usage_lock:
                usage_history_start = len(self._usage_history)
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                with self._usage_lock:
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
    }
    
    client_class = providers.get(config.provider)
    if not client_class:
        raise ValueError(f"Unknown LLM provider: {config.provider}. Available: {list(providers.keys())}")
    
    return client_class(config)
