"""
核心配置模块
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import os
from pathlib import Path

# 获取仓库基础路径
PROJECT_ROOT = Path.home() / "vuln" 

DATA_BASE_PATH = PROJECT_ROOT / "data"
VULN_DATA_PATH = DATA_BASE_PATH / "vuln.json"
REPO_BASE_PATH = DATA_BASE_PATH / "repos"

CODEQL_DB_PATH = PROJECT_ROOT / "codeql_dbs"



@dataclass
class LLMConfig:
    """LLM配置"""
    provider: str = "hku"  # openai, anthropic, hku, deepseek, mock
    model: str = "Qwen3-Coder-480B-A35B-Instruct-FP8"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0
    top_p: float = 0.9
    max_tokens: int = 8192 * 8
    timeout: int = 120

    # 重试配置
    max_retries: int = 10  # 最大重试次数
    initial_delay: float = 1.0  # 初始延迟（秒）
    max_delay: float = 60.0  # 最大延迟（秒）
    backoff_factor: float = 2.0  # 指数退避因子
    
    # enable_thinking: bool = False  # Qwen3特有参数
    
    def __post_init__(self):
        """根据provider自动设置API key和base_url"""
        if self.provider == "hku":
            # HKU LLM API
            self.api_key = os.getenv("HKU_LLM_API_KEY")
            self.base_url = "https://hkucvm.dynv6.net/v1"
            self.model = "Qwen3-Coder-480B-A35B-Instruct-FP8"
        elif self.provider == "deepseek":
            # DeepSeek API
            self.api_key = os.getenv("DEEPSEEK_API_KEY")
            self.base_url = "https://api.deepseek.com/v1"
            self.model = "deepseek-reasoner"
            self.max_tokens = 65536
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY")


EXTENSION_MAPPING = {
                ".py": "Python",
                ".js": "JavaScript",
                ".ts": "TypeScript",
                ".java": "Java",
                ".go": "Go",
                ".rb": "Ruby",
                ".php": "PHP",
                ".rs": "Rust",
            }
@dataclass
class SoftwareProfilerConfig:
    """扫描器配置"""
    # 文件扫描配置
    file_extensions: List[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".rs"
    ])
    exclude_dirs: List[str] = field(default_factory=lambda: [
        "__pycache__", "node_modules", ".git", ".venv", "venv", "env",
        "build", "dist", ".eggs", "*.egg-info"
    ])

    # 分析配置
    max_module_analysis_iterations: int = 100

    
    

@dataclass
class VulnProfileConfig:
    """漏洞画像配置"""
    call_chain: List[Dict[str, Any]] = field(default_factory=list)
    categories: List[str] = field(default_factory=lambda: [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Remote Code Execution",
        "Command Injection",
        "Insecure Deserialization",
        "Path Traversal",
        "Buffer Overflow",
        "Authentication Bypass",
        "Privilege Escalation",
        "Information Disclosure",
    ])
    payload: str = ""  # 自定义payload
