"""
LLM客户端封装
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import json
import re
import time
import logging

from .config import LLMConfig, DS_THINK_TOKENS

# 设置日志
logger = logging.getLogger(__name__)

def concat_ds_think_content(reasoning: str, output: str) -> str:
    """将DeepSeek的reasoning内容和输出内容合并"""
    think_start, think_end = DS_THINK_TOKENS
    # 处理 output 为 None 的情况（例如只有 tool_calls 没有 content）
    output = output or ''
    # 处理 reasoning 为 None 的情况
    reasoning = reasoning or ''
    return ''.join([think_start, reasoning, think_end, output])



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
    """OpenAI客户端 - 带自动重试机制"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                base_url=config.base_url
            )
        except ImportError:
            raise ImportError("Please install openai: pip install openai")
    
    def _make_chat_request(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """实际执行聊天请求（内部方法）"""
        response = self.client.chat.completions.create(
            model=self.config.model,
            messages=messages,
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
        )
        return response.choices[0].message.content
    
    def chat(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """发送聊天请求（带重试机制）"""
        return self._execute_with_retry(self._make_chat_request, messages, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)


class HKULLMClient(BaseLLMClient):
    """HKU LLM客户端 - DeepSeek-V3.2 - 带自动重试机制"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                base_url=config.base_url or "https://hkucvm.dynv6.net/v1"
            )
        except ImportError:
            raise ImportError("Please install openai: pip install openai")
    
    def _make_chat_request(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """实际执行聊天请求（内部方法）
        
        Args:
            messages: 消息列表
            tools: 工具定义列表（可选）
        """
        # 添加系统消息如果不存在
        if not any(m.get("role") == "system" for m in messages):
            messages = [
                {"role": "system", "content": "You are a helpful AI assistant specialized in code security analysis."},
                *messages
            ]
        
        
        # 构建请求参数
        request_params = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "timeout": kwargs.get("timeout", self.config.timeout),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
            "extra_body": {
                "seperate_tool_calls": True,
                "chat_template_kwargs": {"thinking": self.config.enable_thinking}
            }
        }
        

        # 添加tools参数
        if tools is not None:
            request_params["tools"] = tools
            request_params["tool_choice"] = kwargs.get("tool_choice", "auto")
        
        response = self.client.chat.completions.create(**request_params)
        
        return response.choices[0].message

    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Any:
        """发送聊天请求（带重试机制）
        
        Args:
            messages: 消息列表
            tools: 可选的工具定义列表
            **kwargs: 其他参数
                - tool_choice: "none", "auto", "required" (当提供tools时)
                - clear_reasoning: bool，是否清除历史消息中的 reasoning_content（新轮次开始时使用）
                - separate_reasoning: bool，是否返回分离的 reasoning 和 content（无 tool_calls 时）
                
        Returns:
            根据响应类型返回不同格式：
            - 有 tool_calls: {"content": str, "tool_calls": [...], "reasoning": str (if thinking enabled)}
            - 无 tool_calls 且 separate_reasoning=True: {"reasoning": str, "content": str}
            - 其他: str (合并后的内容)
            
        Note:
            在 Tool+Thinking 模式下的多轮对话（SGLang/HKU）：
            1. 在同一个问题的多个子轮次中，需要将 reasoning_content 传回 API
            2. 开始新问题时，可使用 clear_reasoning=True 清除历史 reasoning_content
            3. Assistant 消息应包含 content, tool_calls (如有), reasoning_content (如有)
            4. 使用 extra_body={"separate_reasoning": True} 分离推理内容
        """
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)

    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)


class DeepSeekClient(BaseLLMClient):
    """DeepSeek客户端 - 带自动重试机制
    
    支持功能：
    1. 思考模式（reasoner模型）
    2. Tool调用（tools参数）
    """
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=config.api_key,
                base_url=config.base_url or "https://api.deepseek.com/v1"
            )
            
        except ImportError:
            raise ImportError("Please install openai: pip install openai")
    
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
        }
        
        # 处理 thinking 模式（reasoner 模型或显式启用）
        if self.config.enable_thinking:
            request_params["top_p"] = kwargs.get("top_p", self.config.top_p)
            request_params["max_tokens"] = kwargs.get("max_tokens", self.config.max_tokens)
            # 使用 thinking 参数启用思考模式（适用于 tool calling）
            request_params["extra_body"] = {"thinking": {"type": "enabled"}}
        else:
            request_params["max_tokens"] = min(kwargs.get("max_tokens", self.config.max_tokens), 8192)
        

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
                - clear_reasoning: bool，是否清除历史消息中的 reasoning_content（新轮次开始时使用）
                - separate_reasoning: bool，是否返回分离的 reasoning 和 content（无 tool_calls 时）
                
        Returns:
            根据响应类型返回不同格式：
            - 有 tool_calls: {"content": str, "tool_calls": [...], "reasoning": str (if thinking enabled)}
            - 无 tool_calls 且 separate_reasoning=True: {"reasoning": str, "content": str}
            - 其他: str (合并后的内容)
            
        Note:
            在 Tool+Thinking 模式下的多轮对话：
            1. 在同一个问题的多个子轮次中，需要将 reasoning_content 传回 API
            2. 开始新问题时，应使用 clear_reasoning=True 清除历史 reasoning_content
            3. Assistant 消息应包含 content, tool_calls (如有), reasoning_content (如有)
        """
        return self._execute_with_retry(self._make_chat_request, messages, tools=tools, **kwargs)
    
    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)


class MockLLMClient(BaseLLMClient):
    """Mock LLM客户端，用于测试"""
    
    def chat(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> str:
        if tools is not None:
            return '{"content": "mock response", "tool_calls": [{"id": "mock_1", "type": "function", "function": {"name": "mock_tool", "arguments": "{}"}}]}'
        return '{"status": "mock_response", "message": "This is a mock response for testing"}'
    
    def complete(self, prompt: str, **kwargs) -> str:
        return self.chat([{"role": "user", "content": prompt}], **kwargs)


def create_llm_client(config: LLMConfig) -> BaseLLMClient:
    """创建LLM客户端"""
    providers = {
        "openai": OpenAIClient,
        "hku": HKULLMClient,
        "deepseek": DeepSeekClient,
        "mock": MockLLMClient,
    }
    
    client_class = providers.get(config.provider)
    if not client_class:
        raise ValueError(f"Unknown LLM provider: {config.provider}. Available: {list(providers.keys())}")
    
    return client_class(config)
