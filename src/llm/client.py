
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import os
import time
import logging
import yaml
from dataclasses import dataclass
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


# 设置日志
logger = logging.getLogger(__name__)


DS_THINK_TOKENS = ('<think>', '</think>')


def concat_ds_think_content(reasoning: str, output: str) -> str:
    """将DeepSeek的reasoning内容和输出内容合并"""
    think_start, think_end = DS_THINK_TOKENS
    # 处理 output 为 None 的情况（例如只有 tool_calls 没有 content）
    output = output or ''
    # 处理 reasoning 为 None 的情况
    reasoning = reasoning or ''
    return ''.join([think_start, reasoning, think_end, output])


def load_llm_config_from_yaml(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    从配置文件加载 LLM 配置
    
    Args:
        config_path: 配置文件路径，如果未提供则使用默认路径
        
    Returns:
        包含 LLM 配置的字典
    """
    try:
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "config" / "llm_config.yaml"
        
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            return config
    except Exception as e:
        pass
    
    # 默认值
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
    """LLM配置"""
    provider: str = ""  # openai, anthropic, lab, deepseek, mock
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 1.0
    top_p: float = 0.9
    max_tokens: int = 0
    timeout: int = 120

    # 重试配置
    max_retries: int = 10  # 最大重试次数
    initial_delay: float = 1.0  # 初始延迟（秒）
    max_delay: float = 60.0  # 最大延迟（秒）
    backoff_factor: float = 2.0  # 指数退避因子
    

    enable_thinking: bool = True  # LAB LLM DS参数
    
    def __post_init__(self):
        """根据provider自动设置API key和base_url，优先从YAML加载"""
        # 首先尝试从 YAML 加载配置
        yaml_config = load_llm_config_from_yaml()
        llm_config = yaml_config.get('llm', {})
        providers_config = llm_config.get('providers', {})
        default_config = llm_config.get('default', {})
        
        # 如果没有明确设置，使用默认配置
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
        
        # 根据 provider 加载特定配置
        if self.provider and self.provider in providers_config:
            provider_config = providers_config[self.provider]
            
            # 设置 API key
            if 'api_key_env' in provider_config:
                self.api_key = os.getenv(provider_config['api_key_env'])
            
            # 设置其他配置
            if not self.base_url and 'base_url' in provider_config:
                self.base_url = provider_config['base_url']
            if not self.model and 'model' in provider_config:
                self.model = provider_config['model']
            if self.max_tokens == 0 and 'max_tokens' in provider_config:
                self.max_tokens = provider_config['max_tokens']
        
        # 向后兼容：如果 YAML 中没有配置，使用硬编码的默认值
        if self.provider and not self.base_url:
            if self.provider == "lab":
                # LAB LLM API
                self.api_key = os.getenv("HKU_LLM_API_KEY")
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




class LLMAPIError(Exception):
    """LLM API调用错误"""
    def __init__(self, message: str, status_code: int = None, response: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class LLMRetryExhaustedError(Exception):
    """LLM重试次数耗尽错误"""
    def __init__(self, message: str, last_error: Exception = None):
        super().__init__(message)
        self.last_error = last_error


class BaseLLMClient(ABC):
    """LLM客户端基类"""
    
    def __init__(self, config: LLMConfig):
        self.config = config
        # 从config读取重试配置
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
        判断是否应该重试
        
        Args:
            exception: 捕获的异常
            
        Returns:
            是否应该重试
        """
        # 导入OpenAI相关异常（如果可用）
        try:
            from openai import (
                APIError,
                APIConnectionError,
                RateLimitError,
                APITimeoutError,
                InternalServerError,
                APIStatusError,
            )
            # 这些错误应该重试
            retriable_exceptions = (
                APIConnectionError,  # 连接错误
                RateLimitError,  # 速率限制
                APITimeoutError,  # 超时
                InternalServerError,  # 服务器内部错误 (5xx)
            )
            if isinstance(exception, retriable_exceptions):
                return True
            # 对于APIStatusError，检查状态码
            if isinstance(exception, APIStatusError):
                # 5xx 错误和 429 (Rate Limit) 应该重试
                if exception.status_code >= 500 or exception.status_code == 429:
                    return True
        except ImportError:
            pass
        
        # 通用网络错误
        import socket
        if isinstance(exception, (ConnectionError, TimeoutError, socket.timeout)):
            return True
        
        # 检查异常消息中的关键词
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
        计算重试延迟时间（指数退避）
        
        Args:
            attempt: 当前重试次数（从0开始）
            
        Returns:
            延迟时间（秒）
        """
        delay = self.initial_delay * (self.backoff_factor ** attempt)
        # 添加随机抖动（±10%）
        import random
        jitter = delay * 0.1 * (2 * random.random() - 1)
        delay = delay + jitter
        return min(delay, self.max_delay)
    
    def _execute_with_retry(self, func, *args, **kwargs) -> Any:
        """
        带重试机制执行函数
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            **kwargs: 关键字参数
            
        Returns:
            函数执行结果
            
        Raises:
            LLMRetryExhaustedError: 重试次数耗尽
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                # 判断是否应该重试
                if not self._should_retry(e):
                    logger.error(f"!!!!\n\n\nNon-retriable error occurred: {type(e).__name__}: {e}\n\n\n!!!!\n\n\n")
                    raise
                
                # 检查是否还有重试次数
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
        """发送聊天请求
        
        Args:
            messages: 消息列表
            tools: 可选的工具定义列表（OpenAI format）
            **kwargs: 其他参数
            
        Returns:
            响应内容字符串（或包含tool_calls的字典）
        """
        pass
    
    @abstractmethod
    def complete(self, prompt: str, **kwargs) -> str:
        """发送补全请求"""
        pass
    


class OpenAIClient(BaseLLMClient):
    """OpenAI客户端 - 带自动重试机制，支持工具调用"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        
    def _make_chat_request(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """实际执行聊天请求（内部方法）"""
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        
        # 添加tools参数
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        response = self.client.chat.completions.create(**request_params)
        return response.choices[0].message
    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """发送聊天请求（带重试机制）"""
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)




class DeepSeekClient(BaseLLMClient):
    """DeepSeek客户端 - 支持工具调用和思考模式
    """
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
    
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
        """实际执行聊天请求（内部方法）
        
        Args:
            messages: 消息列表
            tools: 工具定义列表（可选）
            **kwargs: 其他参数
                - tool_choice: 工具选择策略 "none"/"auto"/"required"

        """
        # 添加系统消息如果不存在
        if not any(m.get("role") == "system" for m in messages):
            messages = [
                {"role": "system", "content": "You are a helpful AI assistant specialized in code security analysis."},
                *messages
            ]
        
        
        
        # 构建基础请求参数
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "timeout": kwargs.get("timeout", self.config.timeout),
            "stream": False,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
            
        }
        
        request_params["extra_body"] = self._process_extra_body(kwargs)

        # 添加tools参数
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        # 发送请求
        response = self.client.chat.completions.create(**request_params)

        return response.choices[0].message

    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """发送聊天请求（带重试机制）
        
        Args:
            messages: 消息列表
            tools: 工具定义列表（可选）
            **kwargs: 其他参数
                - tool_choice: 工具选择 "none"/"auto"/"required"（当提供tools时）
                - separate_reasoning: bool，是否返回分离的 reasoning 和 content（无 tool_calls 时）
                
        Returns:
            根据响应类型返回不同格式：
            - 有 tool_calls: {"content": str, "tool_calls": [...], "reasoning": str (if thinking enabled)}
            - 无 tool_calls 且 separate_reasoning=True: {"reasoning": str, "content": str}
            - 其他: str (合并后的内容)
        """
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        """发送补全请求（转换为聊天格式）"""
        return self.chat([{"role": "user", "content": prompt}], **kwargs)
    

class MockLLMClient(BaseLLMClient):
    """Mock LLM客户端，用于测试"""
    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> str:
        if tools is not None:
            return '{"content": "mock response", "tool_calls": [{"id": "mock_1", "type": "function", "function": {"name": "mock_tool", "arguments": "{}"}}]}'
        return '{"status": "mock_response", "message": "This is a mock response for testing"}'
    
    def complete(self, prompt: str, **kwargs) -> str:
        """发送补全请求（Mock实现）"""
        return '{"status": "mock_completion", "prompt": "' + prompt[:50] + '..."}'
    


def create_llm_client(config: LLMConfig) -> BaseLLMClient:
    """创建LLM客户端"""
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
