
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import os
import time
import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from utils.logger import get_logger

from utils import DSTokenizerCompute

logger = get_logger(__name__)


# Logging
logger = logging.getLogger(__name__)


# DS_THINK_TOKENS = ('<think>', '</think>')


# def concat_ds_think_content(reasoning: str, output: str) -> str:
#     """Combine DeepSeek reasoning content and the final output content."""
#     think_start, think_end = DS_THINK_TOKENS
#     # Handle output=None (e.g., tool_calls present but no content)
#     output = output or ''
#     # Handle reasoning=None
#     reasoning = reasoning or ''
#     return ''.join([think_start, reasoning, think_end, output])


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
    provider: str = ""  # openai, anthropic, lab, deepseek, mock
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 1.0
    top_p: float = 0.9
    max_tokens: int = 0
    timeout: int = 120

    # Retry settings
    max_retries: int = 10  # Maximum retries
    initial_delay: float = 1.0  # Initial delay (seconds)
    max_delay: float = 60.0  # Maximum delay (seconds)
    backoff_factor: float = 2.0  # Exponential backoff factor
    

    enable_thinking: bool = True  # DeepSeek/LAB thinking parameter
    
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
            
            # Set API key
            if 'api_key_env' in provider_config:
                self.api_key = os.getenv(provider_config['api_key_env'])
            
            # Set other fields
            if not self.base_url and 'base_url' in provider_config:
                self.base_url = provider_config['base_url']
            if not self.model and 'model' in provider_config:
                self.model = provider_config['model']
            if self.max_tokens == 0 and 'max_tokens' in provider_config:
                self.max_tokens = provider_config['max_tokens']
        
        # Backward compatibility: if YAML has no config, use hardcoded defaults
        if self.provider and not self.base_url:
            if self.provider == "lab":
                # LAB LLM API
                self.api_key = os.getenv("LAB_LLM_API_KEY")
                self.base_url = "https://hkucvm.dynv6.net/v1"
                self.model = "DeepSeek-V3.2"
            elif self.provider == "deepseek":
                # DeepSeek API
                self.api_key = os.getenv("DEEPSEEK_API_KEY")
                self.base_url = "https://api.deepseek.com/v1"
                self.model = "deepseek-chat"
                self.max_tokens = 65536
            elif self.provider == "openai":
                self.api_key = os.getenv("NY_API_KEY")
                self.base_url = "https://ai.nengyongai.cn/v1"
                self.model = "gpt-5.1"
                self.max_tokens = 65536




# class LLMAPIError(Exception):
#     """LLM API call error."""
#     def __init__(self, message: str, status_code: int = None, response: Any = None):
#         super().__init__(message)
#         self.status_code = status_code
#         self.response = response


class LLMRetryExhaustedError(Exception):
    """Raised when LLM retries are exhausted."""
    def __init__(self, message: str, last_error: Exception = None):
        super().__init__(message)
        self.last_error = last_error


class BaseLLMClient(ABC):
    """Base class for LLM clients."""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        # Load retry settings from config
        self.max_retries = config.max_retries
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
                APIError,
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
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
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
            "top_p": kwargs.get("top_p", self.config.top_p),
            "timeout": kwargs.get("timeout", self.config.timeout),
            "stream": False,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        
        # Add tools parameters
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        response = self.client.chat.completions.create(**request_params)
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
        self.token_compute = DSTokenizerCompute()
        self.context_limit = 131072  # DeepSeek context limit

    def _process_extra_body(self, kwargs) -> Dict[str, Any]:
        if not self.config.enable_thinking:
            return {}

        if self.config.provider == "deepseek":
            return {"thinking": {"type": "enabled"}}
        elif self.config.provider == "lab":
            return {
                "seperate_reasoning": kwargs.get("separate_reasoning", True),
                "chat_template_kwargs": {"thinking": self.config.enable_thinking}
            }
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
        
        request_params["extra_body"] = self._process_extra_body(kwargs)

        # Add tools parameters
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        # Send request
        response = self.client.chat.completions.create(**request_params)

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
    

class MockLLMClient(BaseLLMClient):
    """Mock LLM client for tests."""
    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> str:
        if tools is not None:
            return '{"content": "mock response", "tool_calls": [{"id": "mock_1", "type": "function", "function": {"name": "mock_tool", "arguments": "{}"}}]}'
        return '{"status": "mock_response", "message": "This is a mock response for testing"}'
    
    def complete(self, prompt: str, **kwargs) -> str:
        """Send a completion request (mock implementation)."""
        return '{"status": "mock_completion", "prompt": "' + prompt[:50] + '..."}'
    


def create_llm_client(config: LLMConfig) -> BaseLLMClient:
    """Create an LLM client."""
    providers = {
        "openai": OpenAIClient,
        "lab": DeepSeekClient,
        "deepseek": DeepSeekClient,
        "mock": MockLLMClient,
    }
    
    client_class = providers.get(config.provider)
    if not client_class:
        raise ValueError(f"Unknown LLM provider: {config.provider}. Available: {list(providers.keys())}")
    
    return client_class(config)
