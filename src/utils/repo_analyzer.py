"""
Repository Analyzer - 基于 CodeQL 的仓库静态分析工具

功能：
1. 调用图分析：提取函数间调用关系
2. 数据流分析：追踪数据从源到汇的流动
3. 程序切片：提取影响特定代码行的相关代码
4. 依赖分析：分析第三方库依赖
5. 入口点检测：识别 HTTP 端点、CLI 入口等

使用示例：
    analyzer = RepoAnalyzer("/path/to/repo", language="python")
    
    # 获取调用图
    call_graph = analyzer.call_graph
    
    # 获取特定行的代码上下文
    context = analyzer.get_code_context("main.py", 42, window=20)
    
    # 程序切片：找出影响第42行的所有代码
    slice_result = analyzer.backward_slice("main.py", 42, max_depth=3)
"""

import os
import json
import hashlib
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
import logging

from .codeql_native import CodeQLAnalyzer, load_codeql_config, CallGraphEdge, CodeQLFinding
from .git_utils import get_git_commit
from .logger import get_logger

# Initialize logger for this module
logger = get_logger(__name__)


# ========== 数据结构定义 ==========

@dataclass
class CodeLocation:
    """代码位置"""
    file: str
    line: int
    column: int = 0
    code: str = ""
    
    def __str__(self):
        return f"{self.file}:{self.line}"
    
    def __hash__(self):
        return hash((self.file, self.line))
    
    def __eq__(self, other):
        return isinstance(other, CodeLocation) and \
               self.file == other.file and self.line == other.line


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    file: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    is_entry_point: bool = False  # 是否为入口点（main, HTTP handler 等）
    calls: List[str] = field(default_factory=list)  # 调用的函数列表
    called_by: List[str] = field(default_factory=list)  # 被哪些函数调用
    
    def __str__(self):
        return f"{self.name} @ {self.file}:{self.start_line}"


@dataclass
class DependencyInfo:
    """依赖信息"""
    name: str
    version: Optional[str] = None
    import_locations: List[CodeLocation] = field(default_factory=list)
    is_builtin: bool = False
    is_third_party: bool = True


@dataclass
class SliceResult:
    """程序切片结果"""
    target: CodeLocation
    related_locations: List[Dict[str, Any]] = field(default_factory=list)
    data_flow_paths: List[List[str]] = field(default_factory=list)
    files_involved: Set[str] = field(default_factory=set)
    depth: int = 0
    
    def to_dict(self):
        """转换为字典（便于序列化）"""
        return {
            "target": {
                "file": self.target.file,
                "line": self.target.line,
                "code": self.target.code
            },
            "related_locations": self.related_locations,
            "data_flow_paths": self.data_flow_paths,
            "files_involved": list(self.files_involved),
            "depth": self.depth
        }
    
    def to_markdown(self) -> str:
        """转换为 Markdown 格式（便于人类阅读）"""
        md = f"## 程序切片结果\n\n"
        md += f"**目标位置**: `{self.target.file}:{self.target.line}`\n\n"
        
        if self.target.code:
            md += f"```python\n{self.target.code}\n```\n\n"
        
        md += f"**分析深度**: {self.depth}\n"
        md += f"**涉及文件数**: {len(self.files_involved)}\n"
        md += f"**相关代码位置数**: {len(self.related_locations)}\n\n"
        
        if self.data_flow_paths:
            md += "### 数据流路径\n\n"
            for i, path in enumerate(self.data_flow_paths, 1):
                md += f"{i}. {' → '.join(path)}\n"
            md += "\n"
        
        if self.related_locations:
            md += "### 相关代码\n\n"
            for loc in self.related_locations[:10]:  # 只显示前10个
                md += f"#### {loc['file']}:{loc['start_line']}-{loc['end_line']}\n"
                md += f"**关系**: {loc['relationship']}\n\n"
                if loc.get('code'):
                    md += f"```python\n{loc['code']}\n```\n\n"
        
        return md


# ========== 主类 ==========

class RepoAnalyzer:
    """
    仓库分析器 - 使用 CodeQL 进行深度静态分析
    
    特性：
    - 自动语言检测（支持 Python, C/C++）
    - 基于 commit hash 的智能缓存
    - 调用图、数据流、程序切片
    - 依赖分析、入口点检测、敏感数据追踪
    
    参数：
        repo_path: 仓库路径
        language: 编程语言（auto, python, cpp）
        cache_dir: 缓存目录
        max_slice_depth: 程序切片最大深度（默认3层）
        max_slice_files: 程序切片最大文件数（默认10个）
    """
    
    @classmethod
    def _load_entry_point_patterns(cls, config_path: Optional[Path] = None) -> Dict[str, List[str]]:
        """加载入口点检测规则
        
        Args:
            config_path: 配置文件路径，默认为 config/repo_analyzer_rules.yaml
            
        Returns:
            入口点模式字典
        """
        import yaml
        
        if config_path is None:
            # 默认使用项目根目录的 config/repo_analyzer_rules.yaml
            project_root = Path(__file__).parent.parent.parent
            config_path = project_root / "config" / "repo_analyzer_rules.yaml"
        
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                return config.get('entry_point_patterns', {})
            else:
                logger.warning(f"Config file not found: {config_path}, using default patterns")
        except Exception as e:
            logger.error(f"Failed to load entry point patterns: {e}, using defaults")
        
        # 默认模式（如果配置文件加载失败）
        return {
            "python": ["main", "__main__"],
            "cpp": ["main"],
        }
    
    def __init__(
        self,
        repo_path: str,
        language: str = "auto",
        cache_dir: Optional[str] = None,
        max_slice_depth: int = 3,
        max_slice_files: int = 10,
        rebuild_cache: bool = False
    ):
        """初始化分析器"""
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        
        self.max_slice_depth = max_slice_depth
        self.max_slice_files = max_slice_files
        
        # 自动检测语言
        if language == "auto":
            self.language = self._detect_language()
        else:
            self.language = language
        
        logger.info(f"Detected language: {self.language}")
        
        # 设置缓存目录
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(__file__), "..", ".cache", "repo_analyzer")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # 获取当前 commit hash
        self.commit_hash = get_git_commit(str(self.repo_path))
        if not self.commit_hash:
            logger.warning("Could not get commit hash, using timestamp as fallback")
            import time
            self.commit_hash = str(int(time.time()))
        
        # 初始化 CodeQL 分析器
        try:
            from config import _path_config
        except ImportError as e:
            logger.warning(f"Failed to import config module: {e}, using default config")
            _path_config = None
        
        codeql_config = load_codeql_config()
        
        # 只有成功导入 _path_config 时才设置 database_dir
        if _path_config:
            codeql_config['database_dir'] = str(_path_config['codeql_db_path'])
        
        logger.debug(f"CodeQL config queries_path before init: {codeql_config.get('queries_path')}")
        self.codeql_analyzer = CodeQLAnalyzer(codeql_config)
        logger.debug(f"CodeQL analyzer queries_path after init: {self.codeql_analyzer.config.get('queries_path')}")
        

        if not self.codeql_analyzer.is_available:
            raise RuntimeError("CodeQL is not installed or not in PATH. "
                             "Please install from https://github.com/github/codeql-cli-binaries/releases")
        
        logger.info(f"Using CodeQL version: {self.codeql_analyzer.version}")
        
        # 数据存储
        self._call_graph_edges: List[CallGraphEdge] = []
        self._functions: Dict[str, FunctionInfo] = {}
        self._dependencies: Dict[str, DependencyInfo] = {}
        self._entry_points: List[FunctionInfo] = []
        self._findings: List[CodeQLFinding] = []
        
        # 加载或构建分析数据
        self._load_or_build(rebuild_cache)
    
    def _detect_language(self) -> str:
        """自动检测仓库主要语言"""
        # 统计文件扩展名
        extensions = defaultdict(int)
        
        for root, dirs, files in os.walk(self.repo_path):
            # 跳过常见的忽略目录
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'build', 'dist'}]
            
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in {'.py', '.c', '.cpp', '.cc', '.h', '.hpp'}:
                    extensions[ext] += 1
        
        # 判断主要语言
        total_py = extensions.get('.py', 0)
        total_cpp = extensions.get('.cpp', 0) + extensions.get('.cc', 0) + \
                    extensions.get('.c', 0) + extensions.get('.h', 0) + extensions.get('.hpp', 0)
        
        if total_py > total_cpp:
            return "python"
        elif total_cpp > 0:
            return "cpp"
        else:
            return "python"  # 默认
    
    def _get_cache_key(self) -> str:
        """生成缓存键（基于 repo 路径和 commit hash）"""
        key_str = f"{self.repo_path}:{self.commit_hash}:{self.language}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self) -> Path:
        """获取缓存文件路径"""
        cache_key = self._get_cache_key()
        return self.cache_dir / f"{cache_key}.pkl"
    
    def _load_or_build(self, rebuild: bool = False):
        """加载缓存或重新构建分析数据"""
        cache_path = self._get_cache_path()
        
        # 尝试加载缓存
        if not rebuild and cache_path.exists():
            try:
                logger.info(f"Loading cache from {cache_path}")
                with open(cache_path, 'rb') as f:
                    cache_data = pickle.load(f)
                
                self._call_graph_edges = cache_data['call_graph_edges']
                self._functions = cache_data['functions']
                self._dependencies = cache_data['dependencies']
                self._entry_points = cache_data['entry_points']
                self._findings = cache_data.get('findings', [])
                
                logger.info(f"Cache loaded successfully")
                logger.info(f"  - Functions: {len(self._functions)}")
                logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
                logger.info(f"  - Dependencies: {len(self._dependencies)}")
                logger.info(f"  - Entry points: {len(self._entry_points)}")
                return
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}, rebuilding...")
        
        # 构建分析数据
        logger.info(f"Building analysis data (this may take a few minutes)...")
        self._build_analysis()
        
        # 保存缓存
        try:
            cache_data = {
                'call_graph_edges': self._call_graph_edges,
                'functions': self._functions,
                'dependencies': self._dependencies,
                'entry_points': self._entry_points,
                'findings': self._findings,
            }
            with open(cache_path, 'wb') as f:
                pickle.dump(cache_data, f)
            logger.info(f"Cache saved to {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def _build_analysis(self):
        """构建完整的分析数据"""
        # Step 1: 创建 CodeQL 数据库
        logger.info("[1/5] Creating CodeQL database...")
        db_name = f"{self.repo_path.name}-{self.commit_hash[:8]}-{self.language}-db"
        success, db_path = self.codeql_analyzer.create_database(
            source_path=str(self.repo_path),
            language=self.language,
            database_name=db_name,
            overwrite=False
        )
        
        if not success:
            raise RuntimeError(f"Failed to create CodeQL database: {db_path}")
        
        self.db_path = db_path
        logger.info(f"    Database created: {db_path}")
        
        # Step 2: 构建调用图
        logger.info("[2/5] Building call graph...")
        self._build_call_graph()
        
        # Step 3: 提取函数信息
        logger.info("[3/5] Extracting function information...")
        self._extract_functions()
        
        # Step 4: 分析依赖
        logger.info("[4/5] Analyzing dependencies...")
        self._analyze_dependencies()
        
        # Step 5: 检测入口点
        logger.info("[5/5] Detecting entry points...")
        self._detect_entry_points()
        
        logger.info("[RepoAnalyzer] Analysis complete!")
        logger.info(f"  - Functions: {len(self._functions)}")
        logger.info(f"  - Call graph edges: {len(self._call_graph_edges)}")
        logger.info(f"  - Dependencies: {len(self._dependencies)}")
        logger.info(f"  - Entry points: {len(self._entry_points)}")
    
    def _build_call_graph(self):
        """构建调用图（使用 CodeQL）"""
        # 尝试使用 CodeQL 内置的调用图分析
        try:
            logger.info(f"Building call graph with CodeQL for database: {self.db_path}")
            self._call_graph_edges = self.codeql_analyzer._build_call_graph(
                self.db_path,
                self.language
            )
            logger.info(f"CodeQL returned {len(self._call_graph_edges)} call graph edges")
        except Exception as e:
            logger.warning(f"Failed to build call graph via CodeQL: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            self._call_graph_edges = []
        
        # 如果 CodeQL 调用图为空，使用简单的 AST 解析作为后备
        if not self._call_graph_edges:
            logger.info("Using fallback AST-based call graph extraction...")
            self._call_graph_edges = self._build_call_graph_fallback()
    
    def _build_call_graph_fallback(self) -> List[CallGraphEdge]:
        """后备方案：使用 AST 解析构建调用图"""
        edges = []
        
        if self.language != "python":
            return edges
        
        try:
            import ast
        except ImportError:
            return edges
        
        # 扫描所有 Python 文件
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', 'build'}]
            
            for file in files:
                if not file.endswith('.py'):
                    continue
                
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, self.repo_path)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        source = f.read()
                    
                    tree = ast.parse(source, filename=rel_path)
                    
                    # 遍历 AST 提取函数定义和调用
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef):
                            func_name = node.name
                            func_line = node.lineno
                            
                            # 查找函数内的调用
                            for child in ast.walk(node):
                                if isinstance(child, ast.Call):
                                    callee_name = self._extract_call_name(child)
                                    if callee_name:
                                        edge = CallGraphEdge(
                                            caller_name=func_name,
                                            caller_file=rel_path,
                                            caller_line=func_line,
                                            callee_name=callee_name,
                                            callee_file=rel_path,  # 简化：假设在同一文件
                                            callee_line=getattr(child, 'lineno', 0),
                                            call_site_line=getattr(child, 'lineno', 0)
                                        )
                                        edges.append(edge)
                
                except Exception:
                    continue
        
        return edges
    
    def _extract_call_name(self, call_node) -> Optional[str]:
        """从 Call 节点提取被调用的函数名"""
        try:
            import ast
            
            if isinstance(call_node.func, ast.Name):
                return call_node.func.id
            elif isinstance(call_node.func, ast.Attribute):
                # 处理 obj.method() 形式
                return call_node.func.attr
            else:
                return None
        except Exception:
            return None
    
    def _extract_functions(self):
        """提取函数信息（从调用图）"""
        # 从调用图边提取函数
        seen_functions = set()
        
        for edge in self._call_graph_edges:
            # 添加 caller
            if edge.caller_name not in seen_functions:
                func = FunctionInfo(
                    name=edge.caller_name,
                    file=edge.caller_file,
                    start_line=edge.caller_line,
                    end_line=edge.caller_line  # 简化处理
                )
                self._functions[edge.caller_name] = func
                seen_functions.add(edge.caller_name)
            
            # 添加 callee
            if edge.callee_name not in seen_functions:
                func = FunctionInfo(
                    name=edge.callee_name,
                    file=edge.callee_file,
                    start_line=edge.callee_line,
                    end_line=edge.callee_line
                )
                self._functions[edge.callee_name] = func
                seen_functions.add(edge.callee_name)
            
            # 建立调用关系
            if edge.caller_name in self._functions:
                self._functions[edge.caller_name].calls.append(edge.callee_name)
            if edge.callee_name in self._functions:
                self._functions[edge.callee_name].called_by.append(edge.caller_name)
    
    def _analyze_dependencies(self):
        """分析第三方库依赖"""
        # 扫描 import 语句
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules'}]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.repo_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                line = line.strip()
                                if line.startswith('import ') or line.startswith('from '):
                                    self._extract_import(line, rel_path, line_num)
                    except Exception:
                        continue
    
    def _extract_import(self, line: str, file: str, line_num: int):
        """从 import 语句提取依赖"""
        try:
            # 简单的 import 解析
            if line.startswith('import '):
                modules = line[7:].split(',')
            elif line.startswith('from '):
                parts = line.split('import')
                if len(parts) >= 2:
                    modules = [parts[0][5:].split()[0]]
                else:
                    return
            else:
                return
            
            for module in modules:
                module = module.strip().split()[0].split('.')[0]
                
                if module not in self._dependencies:
                    # 判断是否为内置库
                    import sys
                    is_builtin = module in sys.builtin_module_names or \
                                 module in {'os', 'sys', 'json', 'time', 're', 'math'}
                    
                    self._dependencies[module] = DependencyInfo(
                        name=module,
                        is_builtin=is_builtin,
                        is_third_party=not is_builtin
                    )
                
                # 添加导入位置
                loc = CodeLocation(file=file, line=line_num, code=line)
                self._dependencies[module].import_locations.append(loc)
        except Exception:
            pass
    
    def _detect_entry_points(self):
        """检测入口点函数"""
        entry_point_patterns = self._load_entry_point_patterns()
        patterns = entry_point_patterns.get(self.language, [])
        
        for func in self._functions.values():
            # 检查函数名是否匹配入口点模式
            func_name_lower = func.name.lower()
            
            for pattern in patterns:
                if pattern in func_name_lower:
                    func.is_entry_point = True
                    self._entry_points.append(func)
                    break
            
            # 特殊检查：没有被调用的函数可能是入口点
            if not func.called_by and len(func.calls) > 0:
                if func not in self._entry_points:
                    func.is_entry_point = True
                    self._entry_points.append(func)
    
    # ========== 公共属性 ==========
    
    @property
    def call_graph(self) -> List[CallGraphEdge]:
        """获取调用图"""
        return self._call_graph_edges
    
    @property
    def functions(self) -> Dict[str, FunctionInfo]:
        """获取所有函数信息"""
        return self._functions
    
    @property
    def dependencies(self) -> Dict[str, DependencyInfo]:
        """获取依赖信息"""
        return self._dependencies
    
    @property
    def entry_points(self) -> List[FunctionInfo]:
        """获取入口点函数"""
        return self._entry_points
    
    # ========== 公共方法 ==========
    
    def get_function_callers(self, func_name: str) -> List[FunctionInfo]:
        """获取调用指定函数的所有函数"""
        if func_name not in self._functions:
            return []
        
        caller_names = self._functions[func_name].called_by
        return [self._functions[name] for name in caller_names if name in self._functions]
    
    def get_function_callees(self, func_name: str) -> List[FunctionInfo]:
        """获取指定函数调用的所有函数"""
        if func_name not in self._functions:
            return []
        
        callee_names = self._functions[func_name].calls
        return [self._functions[name] for name in callee_names if name in self._functions]
    
    def get_code_context(
        self,
        file: str,
        line: int,
        window: int = 20
    ) -> str:
        """
        获取指定位置的代码上下文
        
        Args:
            file: 文件路径（相对于仓库根目录）
            line: 行号
            window: 上下文窗口大小（前后行数）
        
        Returns:
            代码片段（带行号）
        """
        file_path = self.repo_path / file
        if not file_path.exists():
            return f"File not found: {file}"
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line - window - 1)
            end = min(len(lines), line + window)
            
            context_lines = []
            for i in range(start, end):
                line_num = i + 1
                marker = ">>>" if line_num == line else "   "
                context_lines.append(f"{marker} {line_num:4d} | {lines[i].rstrip()}")
            
            return "\n".join(context_lines)
        except Exception as e:
            return f"Error reading file: {e}"
    
    def backward_slice(
        self,
        file: str,
        line: int,
        max_depth: Optional[int] = None,
        max_files: Optional[int] = None
    ) -> SliceResult:
        """
        向后程序切片：找出所有影响指定代码行的代码
        
        Args:
            file: 文件路径
            line: 行号
            max_depth: 最大追踪深度（None 使用默认值）
            max_files: 最大文件数（None 使用默认值）
        
        Returns:
            SliceResult 对象
        """
        if max_depth is None:
            max_depth = self.max_slice_depth
        if max_files is None:
            max_files = self.max_slice_files
        
        target = CodeLocation(file=file, line=line)
        
        # 读取目标行代码
        code = self._read_line(file, line)
        target.code = code
        
        # 查找影响该行的函数
        affected_functions = self._find_functions_in_file(file, line)
        
        # 向后追踪调用链
        related_locations = []
        data_flow_paths = []
        files_involved = {file}
        
        for func in affected_functions:
            # 获取调用者
            callers = self.get_function_callers(func.name)
            
            for depth in range(1, max_depth + 1):
                if len(files_involved) >= max_files:
                    break
                
                for caller in callers:
                    files_involved.add(caller.file)
                    
                    # 提取调用者代码
                    caller_code = self.get_code_context(caller.file, caller.start_line, window=10)
                    
                    related_locations.append({
                        "file": caller.file,
                        "start_line": caller.start_line,
                        "end_line": caller.end_line,
                        "code": caller_code,
                        "relationship": f"caller (depth {depth})",
                        "function_name": caller.name
                    })
                    
                    # 构建数据流路径
                    path = [f"{caller.file}:{caller.start_line}", f"{file}:{line}"]
                    data_flow_paths.append(path)
                
                # 继续向上追踪
                next_callers = []
                for caller in callers:
                    next_callers.extend(self.get_function_callers(caller.name))
                callers = next_callers
                
                if not callers:
                    break
        
        result = SliceResult(
            target=target,
            related_locations=related_locations,
            data_flow_paths=data_flow_paths,
            files_involved=files_involved,
            depth=max_depth
        )
        
        return result
    
    def forward_slice(
        self,
        file: str,
        line: int,
        max_depth: Optional[int] = None,
        max_files: Optional[int] = None
    ) -> SliceResult:
        """
        向前程序切片：找出指定代码行影响的所有代码
        
        Args:
            file: 文件路径
            line: 行号
            max_depth: 最大追踪深度
            max_files: 最大文件数
        
        Returns:
            SliceResult 对象
        """
        if max_depth is None:
            max_depth = self.max_slice_depth
        if max_files is None:
            max_files = self.max_slice_files
        
        target = CodeLocation(file=file, line=line)
        code = self._read_line(file, line)
        target.code = code
        
        # 查找该行所在的函数
        affected_functions = self._find_functions_in_file(file, line)
        
        # 向前追踪调用链
        related_locations = []
        data_flow_paths = []
        files_involved = {file}
        
        for func in affected_functions:
            # 获取被调用者
            callees = self.get_function_callees(func.name)
            
            for depth in range(1, max_depth + 1):
                if len(files_involved) >= max_files:
                    break
                
                for callee in callees:
                    files_involved.add(callee.file)
                    
                    # 提取被调用者代码
                    callee_code = self.get_code_context(callee.file, callee.start_line, window=10)
                    
                    related_locations.append({
                        "file": callee.file,
                        "start_line": callee.start_line,
                        "end_line": callee.end_line,
                        "code": callee_code,
                        "relationship": f"callee (depth {depth})",
                        "function_name": callee.name
                    })
                    
                    # 构建数据流路径
                    path = [f"{file}:{line}", f"{callee.file}:{callee.start_line}"]
                    data_flow_paths.append(path)
                
                # 继续向下追踪
                next_callees = []
                for callee in callees:
                    next_callees.extend(self.get_function_callees(callee.name))
                callees = next_callees
                
                if not callees:
                    break
        
        result = SliceResult(
            target=target,
            related_locations=related_locations,
            data_flow_paths=data_flow_paths,
            files_involved=files_involved,
            depth=max_depth
        )
        
        return result
    
    def find_data_flow(
        self,
        source_pattern: str,
        sink_pattern: str,
        max_paths: int = 10
    ) -> List[List[str]]:
        """
        查找从 source 到 sink 的数据流路径
        
        Args:
            source_pattern: 源函数名模式（部分匹配）
            sink_pattern: 汇函数名模式（部分匹配）
            max_paths: 最大返回路径数
        
        Returns:
            路径列表，每条路径是函数名列表
        """
        # 找到匹配的 source 和 sink 函数
        sources = [f for name, f in self._functions.items() 
                   if source_pattern.lower() in name.lower()]
        sinks = [f for name, f in self._functions.items() 
                 if sink_pattern.lower() in name.lower()]
        
        if not sources or not sinks:
            return []
        
        # BFS 搜索路径
        all_paths = []
        
        for source in sources:
            for sink in sinks:
                paths = self._find_paths_bfs(source.name, sink.name, max_depth=10)
                all_paths.extend(paths)
                
                if len(all_paths) >= max_paths:
                    return all_paths[:max_paths]
        
        return all_paths[:max_paths]
    
    def search_pattern(self, pattern: str) -> List[CodeLocation]:
        """
        搜索代码模式（简单文本搜索）
        
        Args:
            pattern: 搜索模式（正则表达式）
        
        Returns:
            匹配的代码位置列表
        """
        import re
        
        results = []
        regex = re.compile(pattern, re.IGNORECASE)
        
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__'}]
            
            for file in files:
                if file.endswith(('.py', '.c', '.cpp', '.h')):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.repo_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line_num, line in enumerate(f, 1):
                                if regex.search(line):
                                    loc = CodeLocation(
                                        file=rel_path,
                                        line=line_num,
                                        code=line.strip()
                                    )
                                    results.append(loc)
                    except Exception:
                        continue
        
        return results
    
    def get_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        return {
            "repo_path": str(self.repo_path),
            "language": self.language,
            "commit_hash": self.commit_hash,
            "statistics": {
                "total_functions": len(self._functions),
                "call_graph_edges": len(self._call_graph_edges),
                "dependencies": {
                    "total": len(self._dependencies),
                    "third_party": sum(1 for d in self._dependencies.values() if d.is_third_party),
                    "builtin": sum(1 for d in self._dependencies.values() if d.is_builtin),
                },
                "entry_points": len(self._entry_points),
            },
            "entry_points": [
                {"name": ep.name, "file": ep.file, "line": ep.start_line}
                for ep in self._entry_points[:10]  # 只显示前10个
            ],
            "top_dependencies": [
                {"name": name, "import_count": len(dep.import_locations)}
                for name, dep in sorted(
                    self._dependencies.items(),
                    key=lambda x: len(x[1].import_locations),
                    reverse=True
                )[:10]
            ]
        }
    
    # ========== 辅助方法 ==========
    
    def _read_line(self, file: str, line: int) -> str:
        """读取文件的指定行"""
        file_path = self.repo_path / file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, l in enumerate(f, 1):
                    if i == line:
                        return l.strip()
        except Exception:
            pass
        return ""
    
    def _find_functions_in_file(self, file: str, line: int) -> List[FunctionInfo]:
        """查找文件中包含指定行的函数"""
        results = []
        
        for func in self._functions.values():
            if func.file == file and func.start_line <= line <= func.end_line:
                results.append(func)
        
        return results
    
    def _find_paths_bfs(
        self,
        start: str,
        end: str,
        max_depth: int
    ) -> List[List[str]]:
        """BFS 搜索函数调用路径"""
        if start not in self._functions or end not in self._functions:
            return []
        
        paths = []
        queue = deque([(start, [start])])
        visited = set()
        
        while queue:
            current, path = queue.popleft()
            
            if len(path) > max_depth:
                continue
            
            if current == end:
                paths.append(path)
                continue
            
            if current in visited:
                continue
            visited.add(current)
            
            # 获取被调用的函数
            if current in self._functions:
                for callee in self._functions[current].calls:
                    if callee not in path:  # 避免循环
                        queue.append((callee, path + [callee]))
        
        return paths
