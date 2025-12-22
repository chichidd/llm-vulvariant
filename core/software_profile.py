"""
软件画像数据模型

## 相似性与软件profile
Module's functionality can be hierachial?
Method:
1. find the similar module in the same software (how to define similar)
* functionality (vuln module: )

"""
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from core.llm_client import BaseLLMClient
from core.config import SoftwareProfilerConfig, EXTENSION_MAPPING
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json
from utils.llm_utils import parse_llm_json
from utils.git_utils import get_git_commit, checkout_commit, get_diff_stats, get_changed_files_with_status


@dataclass
class ModuleInfo:
    """模块信息 TODO, NOT USED FOR NOW, TO DELETE IF NO USE LATER"""
    name: str
    path: str
    description: str
    dependencies: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "dependencies": self.dependencies,
            "exports": self.exports,
            "entry_points": self.entry_points,
        }


@dataclass
class SoftwareProfile:
    """软件画像 - 完整的软件特征描述"""
    
    # 1.1 基本信息
    name: str
    version: Optional[str] = None # commit hash or version string
    description: str = ""
    target_application: List[str] = field(default_factory=list)  # 目标场景
    target_user: List[str] = field(default_factory=list)  # 目标人群

    # 1.2 架构信息

    repo_info: Dict[str, Any] = field(default_factory=dict)
    # 1.3 业务逻辑特征
    modules: List[str] = field(default_factory=list)


    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "basic_info": {
                "name": self.name,
                "version": self.version,
                "description": self.description,
                "target_application": self.target_application,
                "target_user": self.target_user,
            },
            "repo_info": self.repo_info,
            "modules": self.modules,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SoftwareProfile":
        """从字典创建"""
        basic = data.get("basic_info", {})
        repo_info = data.get("repo_info", {})
        modules = data.get("modules", [])

        return cls(
            name=basic.get("name", ""),
            version=basic.get("version"),
            description=basic.get("description", ""),
            target_application=basic.get("target_application", []),
            target_user=basic.get("target_user", []),

            repo_info=repo_info,

            modules=modules,
        )
    

class SoftwareProfiler:
    """
    软件画像生成器
    
    负责分析软件仓库并生成完整的软件画像，包括：
    1.1 应用名称、目标场景、目标人群、潜在部署情景
    1.2 应用软件架构、source和sink
    1.3 软件业务逻辑特征
    
    支持断点续传功能，可以保存中间结果并从上次中断处继续。
    """
    
    def __init__(self, config: SoftwareProfilerConfig = None, llm_client: BaseLLMClient = None, output_dir: str = None):
        """
        初始化软件画像生成器
        
        Args:
            config: 扫描器配置
            llm_client: LLM客户端
            output_dir: 输出目录路径，用于保存中间结果和最终画像
        """
        if config is None:
            config = SoftwareProfilerConfig()
        self.config = config
        self.llm_client = llm_client
        
        # 设置输出目录和存储管理器
        self.output_dir = Path(output_dir) if output_dir else None
        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            from .profile_storage import ProfileStorageManager
            self.storage_manager = ProfileStorageManager(str(self.output_dir), profile_type="software")
        else:
            self.storage_manager = None
    
    def _to_relative_path(self, file_path: str, repo_path: Path) -> str:
        """
        将绝对路径转换为相对于仓库根目录的相对路径
        
        Args:
            file_path: 文件的绝对路径
            repo_path: 仓库根目录路径
            
        Returns:
            相对路径字符串
        """
        try:
            return str(Path(file_path).relative_to(repo_path))
        except ValueError:
            # 如果路径不在仓库内，返回原路径
            return file_path

    
    def generate_profile(self, repo_path: str, force_full_analysis: bool = False, target_version: str = None) -> SoftwareProfile:
        """
        生成完整的软件画像
        
        支持断点续传和增量分析：
        - 如果是第一次分析，进行完整分析并设置为base_commit
        - 如果之前有base_commit，比较当前版本与base版本，进行增量分析
        
        Args:
            repo_path: 仓库路径
            force_full_analysis: 是否强制完整分析（忽略增量优化）
            target_version: 目标版本（commit hash）。如果指定，将checkout到该版本进行分析
            
        Returns:
            SoftwareProfile: 软件画像对象
        """
        repo_path = Path(repo_path)
        repo_name = repo_path.name

        print(f"[INFO] Starting profile generation for: {repo_name}")
        
        # 获取git commit hash作为版本号
        current_version = get_git_commit(str(repo_path))
        
        # 如果用户指定了目标版本，检查是否需要checkout
        if target_version:
            print(f"[INFO] Target version specified: {target_version[:8]}...")
            if current_version != target_version:
                print(f"[INFO] Current version ({current_version[:8] if current_version else 'unknown'}...) differs from target version.")
                print(f"[INFO] Checking out to target version {target_version[:8]}...")
                if not checkout_commit(str(repo_path), target_version):
                    raise RuntimeError(f"Failed to checkout to target version: {target_version}")
                print(f"[INFO] Successfully checked out to {target_version[:8]}...")
                version = target_version
            else:
                print(f"[INFO] Current version matches target version, no checkout needed.")
                version = current_version
        else:
            # 用户未指定版本，使用当前版本
            version = current_version
        if version:
            print(f"[INFO] Extracted git commit hash: {version[:8]}...")
        else:
            print(f"[WARN] Could not get git commit hash, using 'unknown' as version")
            version = "unknown"
        
        # 加载或创建 profile_info
        profile_info = self.storage_manager.load_profile_info(repo_name) if self.storage_manager else None
        is_first_run = (profile_info is None)
        
        if is_first_run:
            print(f"[INFO] First run detected. Will perform full analysis and set as base_commit.")
            profile_info = {
                "repo_name": repo_name,
                "base_commit": version,
                "first_analysis_date": datetime.now().isoformat(),
                "llm_config": {
                    "model": self.llm_client.config.model if self.llm_client else "none",
                    "temperature": self.llm_client.config.temperature if self.llm_client else 0.0,
                } if self.llm_client else {},
                "analysis_history": [
                    {
                        "version": version,
                        "date": datetime.now().isoformat(),
                        "type": "full_analysis"
                    }
                ]
            }
            if self.storage_manager:
                self.storage_manager.save_profile_info(profile_info, repo_name)
        else:
            base_commit = profile_info.get("base_commit")
            print(f"[INFO] Found existing profile_info. Base commit: {base_commit[:8] if base_commit else 'N/A'}...")
            
            # 检查当前版本是否与base_commit相同
            if version == base_commit:
                print(f"[INFO] Current version matches base_commit. Checking for cached results...")
            else:
                print(f"[INFO] Current version differs from base_commit.")
                if not force_full_analysis:
                    print(f"[INFO] Will perform incremental analysis using git diff.")
        
        # 尝试加载已完成的最终画像（针对当前版本）
        if self.storage_manager and not force_full_analysis:
            # 直接从最终结果文件加载
            path_parts = (repo_name, version) if version else (repo_name,)
            existing_profile_json = self.storage_manager.load_final_result("software_profile.json", *path_parts)
            if existing_profile_json:
                print(f"[INFO] Found completed profile for {repo_name} (version: {version[:8]}...), loading from cache...")
                existing_profile = json.loads(existing_profile_json)
                return SoftwareProfile.from_dict(existing_profile)
        
        # 决定是否使用增量分析
        use_incremental = (
            not is_first_run and 
            not force_full_analysis and 
            version != profile_info.get("base_commit") and
            version != "unknown" and
            profile_info.get("base_commit") != "unknown"
        )
        
        if use_incremental:
            print(f"[INFO] Performing incremental analysis...")
            profile = self._generate_profile_incremental(repo_path, repo_name, version, profile_info)
        else:
            print(f"[INFO] Performing full analysis...")
            profile = self._generate_profile_full(repo_path, repo_name, version)
        
        # 更新 profile_info 的分析历史
        if not is_first_run:
            if "analysis_history" not in profile_info:
                profile_info["analysis_history"] = []
            profile_info["analysis_history"].append({
                "version": version,
                "date": datetime.now().isoformat(),
                "type": "incremental_analysis" if use_incremental else "full_analysis"
            })
            if self.storage_manager:
                self.storage_manager.save_profile_info(profile_info, repo_name)
        
        print(f"[INFO] Profile generation completed for: {repo_name} (version: {version[:8]}...)")
        return profile
    
    def _generate_profile_full(self, repo_path: Path, repo_name: str, version: str) -> SoftwareProfile:
        """执行完整的profile分析"""
        # Step 1: 收集仓库信息（支持断点续传）
        print(f"[INFO] Step 1/3: Collecting repo info...")
        path_parts = (repo_name, version) if version else (repo_name,)
        repo_info = self.storage_manager.load_checkpoint("repo_info", *path_parts) if self.storage_manager else None
        if repo_info:
            print(f"[INFO] Loaded repo_info from checkpoint")
        else:
            repo_info = self._collect_repo_info(repo_path, repo_name, version)
            repo_info['commit_hash'] = version
            if self.storage_manager:
                self.storage_manager.save_checkpoint("repo_info", repo_info, *path_parts)

        # Step 2: 分析基本信息（支持断点续传）
        print(f"[INFO] Step 2/3: Analyzing basic info...")
        basic_info = self.storage_manager.load_checkpoint("basic_info", *path_parts) if self.storage_manager else None
        if basic_info:
            print(f"[INFO] Loaded basic_info from checkpoint")
        else:
            basic_info = self._analyze_basic_info(repo_path, repo_info, repo_name, version)
            if self.storage_manager:
                self.storage_manager.save_checkpoint("basic_info", basic_info, *path_parts)

        # Step 3: 分析模块（支持断点续传）
        print(f"[INFO] Step 3/3: Analyzing modules...")
        modules_result = self.storage_manager.load_checkpoint("modules", *path_parts) if self.storage_manager else None
        if modules_result:
            print(f"[INFO] Loaded modules from checkpoint")
        else:
            modules_result = self._analyze_modules(repo_info, repo_name, version, repo_path)
            if self.storage_manager:
                self.storage_manager.save_checkpoint("modules", modules_result, *path_parts)

        # 构建软件画像
        profile = SoftwareProfile(
            name=repo_name,
            version=version,
            description=basic_info.get("description", ""),
            target_application=basic_info.get("target_application", []),
            target_user=basic_info.get("target_user", []),
            repo_info=repo_info,
            modules=modules_result.get('modules', []) if modules_result else [],
        )
        
        # 保存最终画像
        if self.storage_manager:
            self.storage_manager.save_final_result("software_profile.json", profile.to_json(), *path_parts)
        
        return profile
    
    def _generate_profile_incremental(self, repo_path: Path, repo_name: str, version: str, profile_info: Dict) -> SoftwareProfile:
        """执行增量profile分析，复用base_commit的结果"""
        base_commit = profile_info.get("base_commit")
        
        print(f"[INFO] Analyzing changes from {base_commit[:8]}... to {version[:8]}...")
        
        # 获取变更的文件
        changed_files_with_status = get_changed_files_with_status(str(repo_path), base_commit, version)
        changed_files = [f for _, f in changed_files_with_status]
        
        print(f"[INFO] Found {len(changed_files)} changed files")
        
        # 获取diff统计
        diff_stats = get_diff_stats(str(repo_path), base_commit, version)
        if diff_stats:
            print(f"[INFO] Diff statistics:\n{diff_stats}")
        
        # 加载base版本的结果
        base_path_parts = (repo_name, base_commit) if base_commit else (repo_name,)
        base_repo_info = self.storage_manager.load_checkpoint("repo_info", *base_path_parts) if self.storage_manager else None
        base_file_summaries = base_repo_info.get('file_summaries', {}) if base_repo_info else {}
        
        # 收集当前版本的仓库信息
        print(f"[INFO] Step 1/3: Collecting repo info (incremental)...")
        repo_info = self._collect_repo_info(repo_path, repo_name, version)
        repo_info['commit_hash'] = version
        repo_info['base_commit'] = base_commit
        repo_info['changed_files'] = changed_files
        repo_info['diff_stats'] = diff_stats
        
        # 对于未变更的文件，复用base版本的摘要
        print(f"[INFO] Reusing summaries for unchanged files...")
        new_file_summaries = {}
        reused_count = 0
        new_analysis_count = 0
        
        all_files_set = set(repo_info['files'])
        # 将changed_files转换为相对路径进行比较
        changed_files_set = set(self._to_relative_path(str(repo_path / f), repo_path) for f in changed_files)
        
        for file_path in repo_info['files']:
            if file_path in changed_files_set:
                # 变更的文件需要重新分析
                new_analysis_count += 1
            elif file_path in base_file_summaries:
                # 未变更的文件复用旧结果
                new_file_summaries[file_path] = base_file_summaries[file_path]
                reused_count += 1
        
        print(f"[INFO] Reused {reused_count} file summaries, need to analyze {new_analysis_count} new/changed files")
        
        # 只分析变更的文件（使用并发版本）
        if new_analysis_count > 0:
            changed_file_paths = [f for f in repo_info['files'] if f in changed_files_set]
            changed_summaries = self._summarize_each_file_concurrent(changed_file_paths, repo_name=repo_name, version=version, repo_path=repo_path)
            new_file_summaries.update(changed_summaries)
        
        repo_info['file_summaries'] = new_file_summaries
        path_parts = (repo_name, version) if version else (repo_name,)
        if self.storage_manager:
            self.storage_manager.save_checkpoint("repo_info", repo_info, *path_parts)
        
        # Step 2: 分析基本信息
        print(f"[INFO] Step 2/3: Analyzing basic info...")
        basic_info = self._analyze_basic_info(repo_path, repo_info, repo_name, version)
        if self.storage_manager:
            self.storage_manager.save_checkpoint("basic_info", basic_info, *path_parts)

        # Step 3: 分析模块
        print(f"[INFO] Step 3/3: Analyzing modules...")
        modules_result = self._analyze_modules(repo_info, repo_name, version, repo_path)
        if self.storage_manager:
            self.storage_manager.save_checkpoint("modules", modules_result, *path_parts)

        # 构建软件画像
        profile = SoftwareProfile(
            name=repo_name,
            version=version,
            description=basic_info.get("description", ""),
            target_application=basic_info.get("target_application", []),
            target_user=basic_info.get("target_user", []),
            repo_info=repo_info,
            modules=modules_result.get('modules', []) if modules_result else [],
        )
        
        # 保存最终画像
        if self.storage_manager:
            self.storage_manager.save_final_result("software_profile.json", profile.to_json(), *path_parts)
        
        return profile
    
    def _collect_repo_info(self, repo_path: Path, repo_name: str = None, version: str = None) -> Dict[str, Any]:
        """
        收集仓库基本信息
        
        Args:
            repo_path: 仓库路径
            repo_name: 仓库名称（用于保存检查点）
            version: 版本号（commit hash）
        """
        if repo_name is None:
            repo_name = repo_path.name
            
        info = {
            "files": [],
            "languages": [],
            "readme_content": "",
            "config_files": [],
            "dependencies": [],
        }

        def _should_exclude(file_path: Path) -> bool:
            """检查是否应该排除该文件"""
            path_str = str(file_path)
            for exclude_pattern in self.config.exclude_dirs:
                if exclude_pattern in path_str:
                    return True
            return False
    

        # 收集文件列表
        languages = set()
        for ext in self.config.file_extensions:
            # print(f"DEBUG: Searching for *{ext} in {repo_path}", len(list(repo_path.rglob(f"*{ext}"))))
            for file_path in repo_path.rglob(f"*{ext}"):
                if not _should_exclude(file_path):
                    # 使用相对路径
                    relative_path = self._to_relative_path(str(file_path), repo_path)
                    info["files"].append(relative_path)
                    if ext in EXTENSION_MAPPING:
                        languages.add(EXTENSION_MAPPING[ext])
        info["languages"] = list(languages)

        # 读取README
        for readme_name in ["README.md", "README.rst", "README.txt", "README"]:
            readme_path = repo_path / readme_name
            if readme_path.exists():
                try:
                    info["readme_content"] = readme_path.read_text(encoding="utf-8")
                except Exception:
                    pass
                break
        
        # 读取包配置
        dependencies = set()
        for config_name in ["pyproject.toml", "setup.py", "setup.cfg", "package.json"]:
            config_path = repo_path / config_name
            if config_path.exists():
                try:
                    content = config_path.read_text(encoding="utf-8")
                    info["config_files"].append({
                        "name": config_name,
                        "content": content
                    })
                    if config_name == "pyproject.toml":
                        # 解析pyproject.toml中的依赖
                        dep_match = re.findall(r'"([a-zA-Z0-9_-]+)(?:[>=<].*?)?"', content)
                        dependencies.update(dep_match)

                    elif config_name == "setup.py":
                        # 解析setup.py中的依赖
                        dep_match = re.findall(r"['\"]([a-zA-Z0-9_-]+)(?:[>=<].*?)?['\"]", content)
                        dependencies.update(dep_match)
                        
                except Exception:
                    pass
        info["dependencies"] = list(dependencies)
        
        # 获取每个文件的摘要（支持断点续传，使用并发版本）
        info['file_summaries'] = self._summarize_each_file_concurrent(info['files'], repo_name=repo_name, version=version, repo_path=repo_path)

        return info

    
    def _analyze_basic_info(self, repo_path: Path, repo_info: Dict, repo_name: str = None, version: str = None) -> Dict[str, Any]:
        """
        1.1 分析基本信息
        包括：应用名称、目标场景、目标用户
        """

        def _format_config_files(config_files: List[Dict]) -> str:
            """格式化配置文件内容"""
            result = []
            for cf in config_files[:3]:
                result.append(f"--- {cf['name']} ---\n{cf['content'][:1000]}")
            return "\n".join(result)
    
        def _rule_based_basic_analysis(repo_path: Path, repo_info: Dict) -> Dict[str, Any]:
            """基于规则的基本分析（LLM不可用时的回退）"""
            readme = repo_info.get("readme_content", "").lower()
            
            # 检测目标场景
            scenarios = []
            scenario_keywords = {
                "data analysis": ["data analysis", "pandas", "numpy", "analytics"],
                "machine learning": ["machine learning", "ml", "deep learning", "neural"],
                "web development": ["web", "flask", "django", "fastapi", "api"],
                "automation": ["automation", "script", "bot"],
                "llm/ai": ["llm", "gpt", "language model", "ai", "openai", "langchain"],
            }
            for scenario, keywords in scenario_keywords.items():
                if any(kw in readme for kw in keywords):
                    scenarios.append(scenario)
            
            # 检测目标用户
            audiences = []
            audience_keywords = {
                "developers": ["developer", "programmer", "engineer"],
                "data scientists": ["data scientist", "researcher", "analyst"],
                "enterprise": ["enterprise", "business", "company"],
            }
            for audience, keywords in audience_keywords.items():
                if any(kw in readme for kw in keywords):
                    audiences.append(audience)
            
            return {
                "description": "",
                "purpose": "",
                "target_application": scenarios or ["general"],
                "target_user": audiences or ["developers"],
            }
        
        BASIC_INFO_PROMPT = """请仔细分析以下软件仓库，准确识别其应用领域、目标场景和用户群体。

# 仓库信息

**仓库名称**: {repo_name}

**README内容**:
```
{readme_content}
```

**配置文件**:
{config_files_formatted}

---

# 分析任务

## 1. 软件描述 (description)
- 用1-3句话概括软件的核心功能和价值
- 说明软件解决什么问题或提供什么服务
- 保持客观、准确，基于README和配置文件的内容

## 2. 目标应用场景 (target_application)
识别软件的**具体应用领域**，从以下分类中选择（可多选）：

**数据处理与分析**:
- "数据清洗与ETL" - 数据提取、转换、加载
- "数据分析与可视化" - 数据统计、图表生成
- "大数据处理" - 分布式计算、海量数据处理

**AI与机器学习**:
- "机器学习训练" - 模型训练、特征工程
- "深度学习" - 神经网络、计算机视觉、NLP
- "模型推理与部署" - 模型服务化、在线预测
- "LLM应用" - 大语言模型集成、提示工程

**Web与网络**:
- "Web后端服务" - API服务、业务逻辑
- "Web前端应用" - 用户界面、交互体验
- "全栈Web应用" - 前后端一体化
- "网络爬虫" - 数据采集、网页解析
- "API客户端" - 第三方服务集成

**系统与工具**:
- "自动化脚本" - 任务自动化、批处理
- "命令行工具" - CLI应用、系统管理
- "开发工具" - 代码生成、辅助开发
- "测试工具" - 单元测试、集成测试、性能测试
- "DevOps工具" - CI/CD、部署、监控

**特定领域**:
- "科学计算" - 数值计算、仿真模拟
- "图像处理" - 图像编辑、格式转换
- "音频/视频处理" - 多媒体编辑、转码
- "文档处理" - PDF、Word、文本处理
- "游戏开发" - 游戏引擎、游戏工具
- "区块链" - 智能合约、DApp
- "物联网" - 设备管理、数据采集
- "金融科技" - 交易系统、风控
- "医疗健康" - 医疗信息系统、健康管理
- "教育" - 在线学习、教学管理

**其他**:
- "通用库/框架" - 可复用组件、工具库
- 如不属于以上分类，请准确描述具体领域

## 3. 目标用户 (target_user)
识别软件的**主要使用者**，从以下分类中选择（可多选），如果不在以下类别，可以自行补充，确保准确、细致：

**技术角色**:
- "软件工程师" - 后端、前端、全栈开发者
- "数据工程师" - 数据管道、ETL开发者
- "数据科学家" - 数据分析、建模专家
- "机器学习工程师" - AI/ML模型开发者
- "算法工程师" - 算法研究与实现
- "DevOps工程师" - 运维、部署专家
- "测试工程师" - QA、自动化测试
- "系统管理员" - 服务器、网络管理
- "研究人员" - 学术研究、实验

**业务角色**:
- "产品经理" - 产品规划、需求管理
- "数据分析师" - 业务数据分析
- "内容创作者" - 写作、设计、多媒体
- "教育工作者" - 教师、培训师
- "企业用户" - 公司、组织使用

**一般用户**:
- "普通用户" - 非技术背景的最终用户
- "学生" - 学习、教育用途
- "爱好者" - 个人兴趣项目

---

# 输出要求

1. **仔细阅读README**：重点关注项目简介、功能特性、使用场景
2. **分析依赖和配置**：推断技术栈和应用类型
3. **准确分类**：选择最贴切的分类，避免过于宽泛
4. **完整性**：如有多个场景或用户群体，都应列出
5. **仅输出JSON**：不要添加任何解释或额外文本

# JSON格式

```json
{{
    "description": "软件的核心功能描述（1-3句话）",
    "target_application": ["应用场景1", "应用场景2"],
    "target_user": ["用户群体1", "用户群体2"]
}}
```

请开始分析："""
        # TODO: 优化prompt
        prompt = BASIC_INFO_PROMPT.format(
            repo_name=repo_path.name, 
            readme_content=repo_info.get('readme_content', '')[:3000], 
            config_files_formatted=_format_config_files(repo_info.get('config_files', []))
            )

        try:
            result = self.llm_client.complete(prompt)
            
            # 保存对话历史
            if repo_name and self.storage_manager:
                conversation_data = {
                    "step": "basic_info_analysis",
                    "timestamp": datetime.now().isoformat(),
                    "prompt": prompt,
                    "response": result,
                    "parsed_result": parse_llm_json(result)
                }
                path_parts = (repo_name, version) if version else (repo_name,)
                self.storage_manager.save_conversation("basic_info", conversation_data, *path_parts)
            
            return parse_llm_json(result)
        except Exception as e:
            # 回退到基于规则的分析
            return _rule_based_basic_analysis(repo_path, repo_info)
    
   

        
    def _summarize_each_file(self, file_path_list: List, max_files=None, repo_name: str = None, version: str = None, repo_path: Path = None) -> Dict[str, str]:
        """
        通过query llm，生成每个文件的简要描述， 用于分析business logic。
        
        支持断点续传：已分析的文件会被跳过，每分析一批文件后自动保存。
        
        Args:
            file_path_list: 文件路径列表（相对路径）
            max_files: 最大文件数限制
            repo_name: 仓库名称（用于保存检查点）
            version: 版本号（commit hash）
            repo_path: 仓库根目录路径（用于将相对路径转换为绝对路径读取文件）
            
        Returns:
            {
                "path/to/file1.py": {"functionality": "...", "key_functions": [...]},
                ...
            }
        """
        # 尝试加载已有的文件摘要检查点
        file_summaries = {}
        if repo_name and self.storage_manager:
            path_parts = (repo_name, version) if version else (repo_name,)
            existing_summaries = self.storage_manager.load_checkpoint("file_summaries", *path_parts)
            if existing_summaries:
                file_summaries = existing_summaries
                print(f"[INFO] Loaded {len(file_summaries)} existing file summaries from checkpoint")

        CODE_SNIPPET_PROMPT = """请分析以下代码文件，提取其功能特征和技术要素。

# 代码文件

**文件路径**: `{file_path}`

**代码内容**:
```
{file_content}
```

---

# 分析任务

## 1. main_purpose (主要目的)
- 用一句话概括这个文件在整个项目中的作用
- 例如："提供用户认证和授权功能"、"实现HTTP请求处理"、"定义数据模型和数据库映射"

## 2. key_functions (关键函数/类)
- 列出文件中**最重要的**函数名或类名（3-10个）
- 优先包括：
  * 公共API（被其他模块调用的函数）
  * 核心业务逻辑函数
  * 重要的类定义
- 格式：使用实际的函数/类名称，不要添加括号或参数
- 例如：["UserController", "authenticate", "validate_token", "get_user_profile"]

## 3. dependencies (主要依赖)
- 列出文件导入的**关键外部库或模块**（3-8个）
- 优先包括：
  * 核心功能依赖的第三方库
  * 项目内部的重要模块引用
- 忽略：标准库的常见导入（如os, sys, json等，除非是核心功能）
- 格式：使用库/模块的实际名称
- 例如：["flask", "sqlalchemy", "jwt", "bcrypt"]

## 4. functionality (核心功能描述)
- 用2-4句话详细描述文件实现的功能
- 说明文件做什么、如何做、与什么交互
- 包括：主要的业务逻辑、数据处理流程、对外接口
- 例如："该文件实现了用户认证系统的核心逻辑。通过JWT令牌验证用户身份，提供登录、注销和令牌刷新接口。使用bcrypt对密码进行加密存储，并与数据库交互管理用户会话。"

---

# 分析指导

**代码理解**:
- 快速浏览导入语句，了解依赖关系
- 识别主要的类和函数定义
- 理解函数间的调用关系和数据流

**准确性优先**:
- 使用代码中实际出现的名称
- 不要猜测或添加不存在的内容
- 如果代码很短或功能单一，列表可以较短

**避免**:
- 不要包含辅助函数（如_private_helper）除非它很重要
- 不要列出所有函数，只选择最关键的
- 不要在functionality中重复列举函数名

---

# JSON格式

```json
{{
    "main_purpose": "一句话描述文件作用",
    "key_functions": ["function1", "ClassName1", "method2"],
    "dependencies": ["library1", "module2"],
    "functionality": "2-4句话的详细功能描述"
}}
```

请开始分析："""

        # 遍历所有文件（限制数量避免token过多）
        files_to_analyze = file_path_list
        if max_files is not None:
            files_to_analyze = files_to_analyze[:max_files]
        
        # 过滤掉已分析的文件
        files_remaining = [f for f in files_to_analyze if f not in file_summaries]
        total_files = len(files_to_analyze)
        already_done = total_files - len(files_remaining)
        
        if already_done > 0:
            print(f"[INFO] Skipping {already_done} already analyzed files, {len(files_remaining)} remaining")
        
        # 增量保存的批次大小
        save_batch_size = 10
        files_since_last_save = 0

        for idx, file_path in enumerate(files_remaining):
            print(f"[INFO] Analyzing file {already_done + idx + 1}/{total_files}: {Path(file_path).name}")
            
            try:
                # 如果提供了repo_path，将相对路径转换为绝对路径读取文件
                if repo_path:
                    absolute_path = repo_path / file_path
                else:
                    absolute_path = Path(file_path)

                content = absolute_path.read_text(encoding="utf-8")

                prompt = CODE_SNIPPET_PROMPT.format(
                    file_path=file_path,
                    file_content=content
                )
                
                # LLM client now has built-in retry mechanism
                try:
                    result = self.llm_client.complete(prompt)
                    summary = parse_llm_json(result)
                    
                    # 保存对话历史
                    if repo_name and self.storage_manager:
                        conversation_data = {
                            "step": "file_summary",
                            "timestamp": datetime.now().isoformat(),
                            "file_path": file_path,
                            "prompt": prompt,
                            "response": result,
                            "parsed_result": summary
                        }
                        # 使用文件名作为标识符
                        file_id = Path(file_path).name
                        path_parts = (repo_name, version) if version else (repo_name,)
                        self.storage_manager.save_conversation("file_summary", conversation_data, *path_parts, file_identifier=file_id)
                    
                    if summary is None:
                        print(f"[WARN] Failed to parse summary for {file_path}")
                        file_summaries[file_path] = {
                            "main_purpose": "Failed to parse LLM response",
                            "key_functions": [],
                            "dependencies": [],
                            "functionality": "Failed to parse LLM response",
                        }
                    else:
                        # Build the summary entry with all fields from LLM response
                        file_summaries[file_path] = {
                            "main_purpose": summary.get("main_purpose", ""),
                            "key_functions": summary.get("key_functions", []),
                            "dependencies": summary.get("dependencies", []),
                            "functionality": summary.get("functionality", "No description available"),
                        }
                except Exception as e:
                    # LLM client already handled retries, this is final failure
                    print(f"[ERROR] Failed to analyze {file_path} after all retries: {e}")
                    file_summaries[file_path] = {
                        "main_purpose": f"Error analyzing file: {str(e)}",
                        "key_functions": [],
                        "dependencies": [],
                        "functionality": f"Error analyzing file: {str(e)}",
                    }
                
            except Exception as e:
                # Error reading file
                file_summaries[file_path] = {
                    "main_purpose": f"Error reading file: {str(e)}",
                    "key_functions": [],
                    "dependencies": [],
                    "functionality": f"Error reading file: {str(e)}",
                }
            
            # 增量保存检查点
            files_since_last_save += 1
            if repo_name and self.storage_manager and files_since_last_save >= save_batch_size:
                path_parts = (repo_name, version) if version else (repo_name,)
                self.storage_manager.save_checkpoint("file_summaries", file_summaries, *path_parts)
                files_since_last_save = 0
        
        # 最终保存
        if repo_name and self.storage_manager and files_since_last_save > 0:
            path_parts = (repo_name, version) if version else (repo_name,)
            self.storage_manager.save_checkpoint("file_summaries", file_summaries, *path_parts)
        
        return file_summaries

    def _summarize_each_file_concurrent(self, file_path_list: List, max_files=None, repo_name: str = None, 
                                         version: str = None, repo_path: Path = None, 
                                         max_workers: int = 5) -> Dict[str, str]:
        """
        并发版本：通过query llm，生成每个文件的简要描述，用于分析business logic。
        
        使用线程池并发处理多个文件，大幅提高分析速度。
        支持断点续传：已分析的文件会被跳过，每分析一批文件后自动保存。
        
        Args:
            file_path_list: 文件路径列表（相对路径）
            max_files: 最大文件数限制
            repo_name: 仓库名称（用于保存检查点）
            version: 版本号（commit hash）
            repo_path: 仓库根目录路径（用于将相对路径转换为绝对路径读取文件）
            max_workers: 最大并发线程数（默认5，避免API限流）
            
        Returns:
            {
                "path/to/file1.py": {"functionality": "...", "key_functions": [...]},
                ...
            }
        """
        # 尝试加载已有的文件摘要检查点
        file_summaries = {}
        if repo_name and self.storage_manager:
            path_parts = (repo_name, version) if version else (repo_name,)
            existing_summaries = self.storage_manager.load_checkpoint("file_summaries", *path_parts)
            if existing_summaries:
                file_summaries = existing_summaries
                print(f"[INFO] Loaded {len(file_summaries)} existing file summaries from checkpoint")

        CODE_SNIPPET_PROMPT = """请分析以下代码文件，提取其功能特征和技术要素。

# 代码文件

**文件路径**: `{file_path}`

**代码内容**:
```
{file_content}
```

---

# 分析任务

## 1. main_purpose (主要目的)
- 用一句话概括这个文件在整个项目中的作用
- 例如："提供用户认证和授权功能"、"实现HTTP请求处理"、"定义数据模型和数据库映射"

## 2. key_functions (关键函数/类)
- 列出文件中**最重要的**函数名或类名（3-10个）
- 优先包括：
  * 公共API（被其他模块调用的函数）
  * 核心业务逻辑函数
  * 重要的类定义
- 格式：使用实际的函数/类名称，不要添加括号或参数
- 例如：["UserController", "authenticate", "validate_token", "get_user_profile"]

## 3. dependencies (主要依赖)
- 列出文件导入的**关键外部库或模块**（3-8个）
- 优先包括：
  * 核心功能依赖的第三方库
  * 项目内部的重要模块引用
- 忽略：标准库的常见导入（如os, sys, json等，除非是核心功能）
- 格式：使用库/模块的实际名称
- 例如：["flask", "sqlalchemy", "jwt", "bcrypt"]

## 4. functionality (核心功能描述)
- 用2-4句话详细描述文件实现的功能
- 说明文件做什么、如何做、与什么交互
- 包括：主要的业务逻辑、数据处理流程、对外接口
- 例如："该文件实现了用户认证系统的核心逻辑。通过JWT令牌验证用户身份，提供登录、注销和令牌刷新接口。使用bcrypt对密码进行加密存储，并与数据库交互管理用户会话。"

---

# 分析指导

**代码理解**:
- 快速浏览导入语句，了解依赖关系
- 识别主要的类和函数定义
- 理解函数间的调用关系和数据流

**准确性优先**:
- 使用代码中实际出现的名称
- 不要猜测或添加不存在的内容
- 如果代码很短或功能单一，列表可以较短

**避免**:
- 不要包含辅助函数（如_private_helper）除非它很重要
- 不要列出所有函数，只选择最关键的
- 不要在functionality中重复列举函数名

---

# JSON格式

```json
{{
    "main_purpose": "一句话描述文件作用",
    "key_functions": ["function1", "ClassName1", "method2"],
    "dependencies": ["library1", "module2"],
    "functionality": "2-4句话的详细功能描述"
}}
```

请开始分析："""

        # 遍历所有文件（限制数量避免token过多）
        files_to_analyze = file_path_list
        if max_files is not None:
            files_to_analyze = files_to_analyze[:max_files]
        
        # 过滤掉已分析的文件
        files_remaining = [f for f in files_to_analyze if f not in file_summaries]
        total_files = len(files_to_analyze)
        already_done = total_files - len(files_remaining)
        
        if already_done > 0:
            print(f"[INFO] Skipping {already_done} already analyzed files, {len(files_remaining)} remaining")
        
        if not files_remaining:
            return file_summaries
        
        print(f"[INFO] Starting concurrent analysis with {max_workers} workers for {len(files_remaining)} files")
        
        # 线程安全的计数器和锁
        lock = threading.Lock()
        completed_count = [0]  # 使用列表以便在闭包中修改
        save_batch_size = 10
        
        def analyze_single_file(file_path: str) -> tuple:
            """分析单个文件（在线程中执行）"""
            try:
                # 读取文件内容
                if repo_path:
                    absolute_path = repo_path / file_path
                else:
                    absolute_path = Path(file_path)
                
                content = absolute_path.read_text(encoding="utf-8")
                
                prompt = CODE_SNIPPET_PROMPT.format(
                    file_path=file_path,
                    file_content=content
                )
                
                # 调用LLM（LLM client有内置重试机制）
                result = self.llm_client.complete(prompt)
                summary = parse_llm_json(result)
                
                # 保存对话历史（线程安全）
                if repo_name and self.storage_manager:
                    conversation_data = {
                        "step": "file_summary",
                        "timestamp": datetime.now().isoformat(),
                        "file_path": file_path,
                        "prompt": prompt,
                        "response": result,
                        "parsed_result": summary
                    }
                    file_id = Path(file_path).name
                    path_parts = (repo_name, version) if version else (repo_name,)
                    with lock:
                        self.storage_manager.save_conversation("file_summary", conversation_data, *path_parts, file_identifier=file_id)
                
                if summary is None:
                    return (file_path, {
                        "main_purpose": "Failed to parse LLM response",
                        "key_functions": [],
                        "dependencies": [],
                        "functionality": "Failed to parse LLM response",
                    }, False)
                else:
                    return (file_path, {
                        "main_purpose": summary.get("main_purpose", ""),
                        "key_functions": summary.get("key_functions", []),
                        "dependencies": summary.get("dependencies", []),
                        "functionality": summary.get("functionality", "No description available"),
                    }, True)
                    
            except Exception as e:
                return (file_path, {
                    "main_purpose": f"Error: {str(e)}",
                    "key_functions": [],
                    "dependencies": [],
                    "functionality": f"Error analyzing file: {str(e)}",
                }, False)
        
        # 使用线程池并发处理
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_file = {executor.submit(analyze_single_file, fp): fp for fp in files_remaining}
            
            # 收集结果
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    fp, summary_data, success = future.result()
                    
                    with lock:
                        file_summaries[fp] = summary_data
                        completed_count[0] += 1
                        current_count = completed_count[0]
                    
                    status = "✓" if success else "✗"
                    print(f"[INFO] [{status}] Analyzed {already_done + current_count}/{total_files}: {Path(fp).name}")
                    
                    # 增量保存检查点（线程安全）
                    if repo_name and self.storage_manager and current_count % save_batch_size == 0:
                        with lock:
                            path_parts = (repo_name, version) if version else (repo_name,)
                            self.storage_manager.save_checkpoint("file_summaries", file_summaries, *path_parts)
                            print(f"[INFO] Checkpoint saved ({current_count} files)")
                            
                except Exception as e:
                    print(f"[ERROR] Unexpected error processing {file_path}: {e}")
                    with lock:
                        file_summaries[file_path] = {
                            "main_purpose": f"Error: {str(e)}",
                            "key_functions": [],
                            "dependencies": [],
                            "functionality": f"Unexpected error: {str(e)}",
                        }
                        completed_count[0] += 1
        
        # 最终保存
        if repo_name and self.storage_manager:
            path_parts = (repo_name, version) if version else (repo_name,)
            self.storage_manager.save_checkpoint("file_summaries", file_summaries, *path_parts)
            print(f"[INFO] Final checkpoint saved ({len(file_summaries)} total files)")
        
        return file_summaries


    def _analyze_modules(self, repo_info: Dict, repo_name: str = None, version: str = None, repo_path: Path = None) -> Dict[str, Any]:
        """
        使用LLM以智能体方式分析仓库模块结构
        
        通过多轮对话，智能体可以：
        1. 读取文件摘要（通过repo_info）
        2. 读取完整文件内容
        3. 根据分析结果决定下一步行动
        
        Args:
            repo_info: 仓库信息字典，包含files, file_summaries等
            repo_name: 仓库名称（用于保存检查点）
            version: 版本号（commit hash）
            repo_path: 仓库根目录路径（用于将相对路径转换为绝对路径读取文件）
            
        Returns:
            模块分析结果字典
        """
        # 定义智能体可用的动作
        AVAILABLE_ACTIONS = ["read_file_summary", "read_full_file", "finalize"]
        
        # 构建文件结构概览
        file_list = repo_info.get("files", [])
        file_summaries = repo_info.get("file_summaries", {})
        
        # 构建目录结构树
        dir_structure = self._build_directory_structure(file_list)
        print("[INFO] Starting module analysis...")
        # 初始化对话历史
        conversation_history = []
        
        # 系统提示词
        system_prompt = """你是一个软件架构分析专家，负责分析代码仓库并识别其模块结构。

# 目标
你的任务是识别仓库中的功能模块。模块不仅限于特定的包或文件夹，它泛指负责某一功能的组件，例如：
- Web接口模块
- 数据加载模块
- 数据预处理模块
- 模型加载模块
- 核心算法模块
- LLM交互模块
- 配置管理模块
- 工具函数模块
- 测试模块
等等

# 动作
你可以执行以下动作来获取更多信息：
1. read_file_summary: 读取文件的文字摘要描述（已预先生成）
2. read_full_file: 读取文件的完整内容
3. finalize: 完成分析并输出最终结果

# 响应格式
请以JSON格式返回你的响应：
{
    "thinking": "你的思考过程，解释你为什么选择这个动作，以及你的分析进展，如果有的话",
    "action": "动作名称（read_file_summary/read_full_file/finalize）",
    "action_input": "动作参数（一个列表，包含完整文件路径，或空列表）"
}

# 注意事项
- 你应该尽量通过读取文件摘要来获取信息，只有在必要时才读取完整文件内容
- 你可以一次请求多个文件的摘要或内容，以提高效率
- 确保对所有文件进行充分分析，直到你有足够的信息来识别模块
- 遇到不明确或模糊的情况时，可以主动询问以获取更多上下文信息
- 在分析过程中，保持对话的连贯性和上下文的完整性
- 尽量避免在没有足够信息的情况下做出假设
- 作出最终决定前，检查文件列表，确保你已经考虑了所有文件夹、模块或文件

# 最终输出格式
- 当action为finalize时，请返回最终分析结果，modules部分以一个列表形式返回：
{
    "thinking": "最终思考",
    "action": "finalize",
    "action_input": "",
    "modules": [
        {
            "name": "模块1名称",
            "category": "模块1类别（如：web_interface, data_loading, core_algorithm等）",
            "description": "模块1功能描述",
            "files": ["模块1相关文件路径列表"],
            "key_functions": ["模块1关键函数或类名"],
            "dependencies": ["模块1依赖的其他模块"],
        }
    ]
}
- 返回的文件路径列表、关键函数或类名、依赖的其他模块应全面、准确，不得遗漏。
- 只返回JSON，符合上述格式，不要输出其他内容。"""

        # 初始用户消息：提供仓库结构概览
        initial_message = f"""请分析以下代码仓库的模块结构：

## 目录结构
{dir_structure}

## 文件列表
共有 {len(file_list)} 个代码文件

## README摘要
{repo_info.get('readme_content', '')[:2000]}

## 已识别的主要语言
{', '.join(repo_info.get('languages', []))}

## 主要依赖
{', '.join(repo_info.get('dependencies', [])[:20])}

请开始分析，你可以通过执行动作来获取更多文件信息。"""

        conversation_history.append({"role": "system", "content": system_prompt})
        conversation_history.append({"role": "user", "content": initial_message})
        
        # 尝试加载已有的对话历史检查点
        if repo_name and self.storage_manager:
            path_parts = (repo_name, version) if version else (repo_name,)
            saved_state = self.storage_manager.load_checkpoint("module_analysis_state", *path_parts)
            if saved_state:
                conversation_history = saved_state.get("conversation_history", conversation_history)
                start_iteration = saved_state.get("last_iteration", 0)
                print(f"[INFO] Resuming module analysis from iteration {start_iteration + 1}")
            else:
                start_iteration = 0
        else:
            start_iteration = 0
        
        # 智能体循环（最多20轮）
        max_iterations = self.config.max_module_analysis_iterations
        final_result = None
        
        for iteration in range(start_iteration, max_iterations):
            print(f"[INFO] Module analysis iteration {iteration + 1}/{max_iterations}")
            try:
                # 调用LLM
                response = self.llm_client.chat(conversation_history)
                parsed_response = parse_llm_json(response)
                
                # 保存每次迭代的对话
                if repo_name and self.storage_manager:
                    conversation_data = {
                        "step": "module_analysis_iteration",
                        "timestamp": datetime.now().isoformat(),
                        "iteration": iteration + 1,
                        "conversation_history": conversation_history,
                        "response": response,
                        "parsed_response": parsed_response
                    }
                    path_parts = (repo_name, version) if version else (repo_name,)
                    self.storage_manager.save_conversation("module_analysis", conversation_data, *path_parts, file_identifier=f"iter_{iteration+1:02d}")
                
                if not parsed_response:
                    # 解析失败，尝试继续
                    conversation_history.append({"role": "assistant", "content": response})
                    conversation_history.append({
                        "role": "user", 
                        "content": "请以有效的JSON格式返回你的响应。"
                    })
                    continue
                
                action = parsed_response.get("action", "")
                action_input = parsed_response.get("action_input", [])
                if isinstance(action_input, str):
                    action_input = [action_input] if action_input else []
                
                conversation_history.append({"role": "assistant", "content": response})
                
                if action == "finalize":
                    # 完成分析
                    print("DONE", parsed_response)
                    final_result = {
                        "modules": parsed_response.get("modules", []),
                        "iterations": iteration + 1
                    }
                    # 清除中间状态检查点（分析完成）
                    if repo_name and self.storage_manager:
                        path_parts = (repo_name, version) if version else (repo_name,)
                        checkpoint_dir = self.storage_manager.get_checkpoint_dir(*path_parts)
                        if checkpoint_dir:
                            state_file = checkpoint_dir / "module_analysis_state.json"
                            if state_file.exists():
                                state_file.unlink()
                                print(f"[INFO] Cleaned up module_analysis_state.json")
                    break
                    
                elif action == "read_file_summary":
                    # 读取文件摘要
                    # 读取文件摘要
                    file_paths = action_input if isinstance(action_input, list) else [action_input]
                    
                    summaries_collected = []
                    for file_path in file_paths:
                        
                        if file_path in file_summaries:
                            summary_info = file_summaries[file_path]
                            summary_text = f"""## 文件摘要: {file_path}

主要目的: {summary_info.get('main_purpose', 'N/A')}
功能描述: {summary_info.get('functionality', 'N/A')}
关键函数: {', '.join(summary_info.get('key_functions', []))}
主要依赖: {', '.join(summary_info.get('dependencies', []))}
"""
                            summaries_collected.append(summary_text)
                        else:
                            # 尝试模糊匹配
                            
                            matching_files = [f for f in file_summaries.keys() if file_path in f]
                            if matching_files:
                                summaries_collected.append(f"找到以下匹配 '{file_path}' 的文件：\n" + "\n".join(matching_files[:10]))
                            else:
                                summaries_collected.append(f"未找到文件 '{file_path}' 的摘要。")
                    
                    if summaries_collected:
                        conversation_history.append({
                            "role": "user",
                            "content": "\n\n".join(summaries_collected)
                        })
                    else:
                        available_info = f"未找到任何请求的文件摘要。可用文件包括：\n" + "\n".join(list(file_summaries.keys())[:20])
                        conversation_history.append({
                            "role": "user",
                            "content": available_info
                        })
                   
                        
                elif action == "read_full_file":
                    # 读取完整文件内容
                    file_path = action_input
                    # 读取完整文件内容
                    file_paths = action_input if isinstance(action_input, list) else [action_input]
                    
                    files_content = []
                    for file_path in file_paths:
                        try:
                            # 检查文件是否在仓库文件列表中
                            if file_path in file_list or any(file_path in f for f in file_list):
                                # 找到实际路径（相对路径）
                                actual_path = file_path
                                if file_path not in file_list:
                                    actual_path = next((f for f in file_list if file_path in f), file_path)
                                
                                # 如果提供了repo_path，将相对路径转换为绝对路径读取文件
                                if repo_path:
                                    absolute_path = repo_path / actual_path
                                else:
                                    absolute_path = Path(actual_path)
                                
                                content = absolute_path.read_text(encoding="utf-8")
                                # 限制内容长度以避免token过多
                                if len(content) > 5000:
                                    content = content[:5000] + "\n\n... [内容已截断，共 {} 字符] ...".format(len(content))
                                
                                files_content.append(f"## 文件完整内容: {actual_path}\n\n```\n{content}\n```")
                            else:
                                files_content.append(f"未找到文件 '{file_path}'。请检查文件路径是否正确。")
                        except Exception as e:
                            files_content.append(f"读取文件 '{file_path}' 时出错: {str(e)}")
                    
                    if files_content:
                        conversation_history.append({
                            "role": "user",
                            "content": "\n\n".join(files_content)
                        })
                    else:
                        conversation_history.append({
                            "role": "user",
                            "content": f"未能读取任何请求的文件内容。"
                        })
                else:
                    # 未知动作
                    conversation_history.append({
                        "role": "user",
                        "content": f"未知动作 '{action}'。请使用以下动作之一: {', '.join(AVAILABLE_ACTIONS)}"
                    })
                
                # 每次迭代后保存状态检查点
                if repo_name and self.storage_manager:
                    path_parts = (repo_name, version) if version else (repo_name,)
                    self.storage_manager.save_checkpoint("module_analysis_state", {
                        "conversation_history": conversation_history,
                        "last_iteration": iteration
                    }, *path_parts)
                    
            except Exception as e:
                # LLM调用失败
                print(f"[WARN] Error during module analysis iteration {iteration + 1}: {e}")
                conversation_history.append({
                    "role": "user",
                    "content": f"处理响应时出错: {str(e)}。请继续分析。"
                })
                # 保存错误状态以便恢复
                if repo_name and self.storage_manager:
                    path_parts = (repo_name, version) if version else (repo_name,)
                    self.storage_manager.save_checkpoint("module_analysis_state", {
                        "conversation_history": conversation_history,
                        "last_iteration": iteration
                    }, *path_parts)
        
        # 如果没有得到最终结果，尝试从对话历史中提取
        if final_result is None:
            final_result = self._fallback_module_analysis(repo_info, repo_name, version, repo_path)
        
        # 迭代完成后，无论是否得到最终结果，都清理状态文件
        if repo_name and self.storage_manager and final_result is not None:
            path_parts = (repo_name, version) if version else (repo_name,)
            checkpoint_dir = self.storage_manager.get_checkpoint_dir(*path_parts)
            if checkpoint_dir:
                state_file = checkpoint_dir / "module_analysis_state.json"
                if state_file.exists():
                    state_file.unlink()
                    print(f"[INFO] Iteration completed, cleaned up module_analysis_state.json")
        
        return final_result
    
    def _build_directory_structure(self, file_list: List[str]) -> str:
        """根据文件列表构建目录结构树（假设file_list已经是相对路径）"""
        from collections import defaultdict
        
        if not file_list:
            return "Empty"
        
        # 构建目录结构（假设路径已经是相对的）
        dir_tree = defaultdict(list)
        for file_path in file_list:
            try:
                parts = Path(file_path).parts
                if len(parts) > 1:
                    top_dir = parts[0]
                    dir_tree[top_dir].append(file_path)
                else:
                    dir_tree["."].append(file_path)
            except Exception:
                continue
        
        # 格式化输出
        result = []
        for dir_name, files in sorted(dir_tree.items()):
            if dir_name == ".":
                result.append(f"根目录: {len(files)} 个文件")
            else:
                result.append(f"{dir_name}/: {len(files)} 个文件")
                # 显示前几个文件作为示例
                for f in files[:5000]:
                    result.append(f"  - {f}")
                if len(files) > 5000:
                    result.append(f"  ... 还有 {len(files) - 5000} 个文件")
        
        return "\n".join(result)
    
    def _fallback_module_analysis(self, repo_info: Dict, repo_name: str = None, version: str = None, repo_path: Path = None) -> Dict[str, Any]:
        """
        当智能体分析失败时的回退方案
        基于规则和LLM单次调用进行模块分析
        
        Args:
            repo_info: 仓库信息字典
            repo_name: 仓库名称
            version: 版本号
            repo_path: 仓库根目录路径（当前未使用，为了保持接口一致性）
        """
        file_summaries = repo_info.get("file_summaries", {})
        file_list = repo_info.get("files", [])
        
        # 构建摘要文本
        summaries_text = ""
        for file_path, summary in list(file_summaries.items())[:30]:
            if isinstance(summary, dict):
                main_purpose = summary.get('main_purpose', '')
                functionality = summary.get('functionality', 'N/A')
                key_functions = ', '.join(summary.get('key_functions', [])[:5])  # 限制前5个
                dependencies = ', '.join(summary.get('dependencies', [])[:5])  # 限制前5个
                
                summary_line = f"\n{file_path}:"
                if main_purpose:
                    summary_line += f" [{main_purpose}]"
                summary_line += f" {functionality}"
                if key_functions:
                    summary_line += f" | 关键函数: {key_functions}"
                if dependencies:
                    summary_line += f" | 依赖: {dependencies}"
                summaries_text += summary_line
            else:
                summaries_text += f"\n{file_path}: {summary}"
        
        # 构建目录结构
        dir_structure = self._build_directory_structure(file_list)
        
        prompt = f"""请根据以下信息分析代码仓库的模块结构。

## 目录结构
{dir_structure}

## 文件功能摘要
{summaries_text}

## README内容
{repo_info.get('readme_content', '')[:2000]}

请识别并分类代码仓库中的功能模块。模块不仅限于特定的包或文件夹，它泛指负责某一功能的组件。

请以JSON格式返回分析结果：
{{
    "modules": [
        {{
            "name": "模块名称",
            "category": "模块类别",
            "description": "模块功能描述",
            "files": ["相关文件路径"],
            "key_functions": ["关键函数"],
            "dependencies": ["依赖的其他模块"],
            "security_relevant": true/false
        }}
    ]
}}

只返回JSON，不要其他内容。"""

        try:
            response = self.llm_client.complete(prompt)
            result = parse_llm_json(response)
            
            # 保存fallback对话历史
            if repo_name and self.storage_manager:
                conversation_data = {
                    "step": "module_analysis_fallback",
                    "timestamp": datetime.now().isoformat(),
                    "prompt": prompt,
                    "response": response,
                    "parsed_result": result
                }
                path_parts = (repo_name, version) if version else (repo_name,)
                self.storage_manager.save_conversation("module_analysis_fallback", conversation_data, *path_parts)
            
            if result:
                return {"modules": result.get("modules", []), "fallback": True}
        except Exception:
            pass
        
        # 如果LLM也失败，返回基于规则的基本分析
        return self._rule_based_module_analysis(repo_info)
    
    def _rule_based_module_analysis(self, repo_info: Dict) -> Dict[str, Any]:
        """
        基于规则的模块分析（完全回退方案）
        """
        file_list = repo_info.get("files", [])
        modules = []
        
        # 根据常见目录名识别模块
        module_patterns = {
            "api": {"name": "API模块", "category": "web_interface", "security_relevant": True},
            "web": {"name": "Web接口模块", "category": "web_interface", "security_relevant": True},
            "routes": {"name": "路由模块", "category": "web_interface", "security_relevant": True},
            "handlers": {"name": "请求处理模块", "category": "web_interface", "security_relevant": True},
            "models": {"name": "数据模型模块", "category": "data_model", "security_relevant": False},
            "schemas": {"name": "数据模式模块", "category": "data_model", "security_relevant": False},
            "data": {"name": "数据处理模块", "category": "data_loading", "security_relevant": True},
            "loaders": {"name": "数据加载模块", "category": "data_loading", "security_relevant": True},
            "utils": {"name": "工具函数模块", "category": "utilities", "security_relevant": False},
            "helpers": {"name": "辅助函数模块", "category": "utilities", "security_relevant": False},
            "core": {"name": "核心功能模块", "category": "core_algorithm", "security_relevant": True},
            "engine": {"name": "引擎模块", "category": "core_algorithm", "security_relevant": True},
            "llm": {"name": "LLM交互模块", "category": "llm_interaction", "security_relevant": True},
            "ai": {"name": "AI模块", "category": "llm_interaction", "security_relevant": True},
            "agents": {"name": "智能体模块", "category": "llm_interaction", "security_relevant": True},
            "config": {"name": "配置管理模块", "category": "configuration", "security_relevant": False},
            "settings": {"name": "设置模块", "category": "configuration", "security_relevant": False},
            "tests": {"name": "测试模块", "category": "testing", "security_relevant": False},
            "test": {"name": "测试模块", "category": "testing", "security_relevant": False},
            "auth": {"name": "认证模块", "category": "authentication", "security_relevant": True},
            "security": {"name": "安全模块", "category": "security", "security_relevant": True},
            "db": {"name": "数据库模块", "category": "database", "security_relevant": True},
            "database": {"name": "数据库模块", "category": "database", "security_relevant": True},
        }
        
        from collections import defaultdict
        dir_files = defaultdict(list)
        
        # 按目录分组文件
        for file_path in file_list:
            parts = Path(file_path).parts
            for i, part in enumerate(parts):
                part_lower = part.lower()
                if part_lower in module_patterns:
                    dir_files[part_lower].append(file_path)
                    break
        
        # 根据目录创建模块
        for dir_name, files in dir_files.items():
            pattern = module_patterns.get(dir_name, {})
            modules.append({
                "name": pattern.get("name", f"{dir_name}模块"),
                "category": pattern.get("category", "other"),
                "description": f"基于目录 '{dir_name}' 识别的模块",
                "files": files[:10],  # 限制文件数量
                "key_functions": [],
                "dependencies": [],
                "security_relevant": pattern.get("security_relevant", False)
            })
        
        return {"modules": modules, "rule_based": True}
