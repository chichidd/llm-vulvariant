"""
真正的 CodeQL 分析器

基于 GitHub CodeQL CLI 工具的分析器封装，提供：
1. 数据库创建
2. 查询执行
3. 结果解析
4. 跨函数/跨文件调用图构建


### 方法1: 使用 CodeQLNativeAnalyzer（推荐）

```python
from core.codeql_native import CodeQLNativeAnalyzer

# 初始化分析器
analyzer = CodeQLNativeAnalyzer()

# 创建数据库
success, db_path = analyzer.create_database(
    source_path="/path/to/repo",
    language="python",
    database_name="my_project"
)

print(f"数据库路径: {db_path}")
```

### 方法2: 直接使用 CodeQL CLI

```bash
# 设置环境变量
export PATH="$HOME/.codeql/codeql-cli/codeql:$PATH"

# 创建数据库
codeql database create my_db --language=python --source-root=/path/to/repo

# 运行分析（需要查询包）
codeql database analyze my_db --format=sarif-latest --output=results.sarif
```
"""

import json
import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


@dataclass
class CodeQLConfig:
    """CodeQL 配置"""
    codeql_cli_path: str = ""  # CodeQL CLI 路径，空则使用 PATH 中的
    queries_path: str = ""  # 自定义查询路径
    database_dir: str = ""  # 数据库存储目录
    threads: int = 0  # 0 表示自动检测
    memory: int = 0  # MB，0 表示自动
    timeout: int = 600  # 查询超时时间（秒）
    
    def __post_init__(self):
        if not self.database_dir:
            self.database_dir = os.path.join(tempfile.gettempdir(), "codeql-dbs")
        os.makedirs(self.database_dir, exist_ok=True)
        
        # 默认查询路径
        if not self.queries_path:
            self.queries_path = os.path.join(
                os.path.dirname(__file__), "codeql", "queries"
            )


@dataclass
class CodeQLFinding:
    """CodeQL 发现的问题"""
    rule_id: str
    severity: str
    message: str
    file_path: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    cwe_ids: List[str] = field(default_factory=list)
    
    # 数据流路径（如果是污点分析结果）
    source: Optional[Dict[str, Any]] = None
    sink: Optional[Dict[str, Any]] = None
    path_nodes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass 
class CallGraphEdge:
    """调用图边"""
    caller_name: str
    caller_file: str
    caller_line: int
    callee_name: str
    callee_file: str
    callee_line: int
    call_site_line: int


@dataclass
class CodeQLAnalysisResult:
    """CodeQL 分析结果"""
    success: bool
    database_path: str
    query_results: Dict[str, List[CodeQLFinding]] = field(default_factory=dict)
    call_graph: List[CallGraphEdge] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    execution_time: float = 0.0


class CodeQLAnalyzer:
    """
    真正的 CodeQL 分析器
    
    使用 GitHub CodeQL CLI 进行代码分析，支持：
    - 创建 CodeQL 数据库
    - 执行自定义和标准查询
    - 构建跨函数/跨文件调用图
    - 污点分析
    """
    
    # 支持的语言及其别名
    SUPPORTED_LANGUAGES = {
        "python": ["python", "py"],
        "javascript": ["javascript", "js", "typescript", "ts"],
        "java": ["java"],
        "csharp": ["csharp", "cs", "c#"],
        "cpp": ["cpp", "c++", "c"],
        "go": ["go", "golang"],
        "ruby": ["ruby", "rb"],
    }
    
    # 预定义查询包
    QUERY_SUITES = {
        "security": "codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls",
        "quality": "codeql/{lang}-queries:codeql-suites/{lang}-code-quality.qls",
        "all": "codeql/{lang}-queries:codeql-suites/{lang}-security-and-quality.qls",
    }
    
    def __init__(self, config: Optional[CodeQLConfig] = None):
        self.config = config or CodeQLConfig()
        self._codeql_cmd = self._find_codeql()
        self._verify_installation()
    
    def _find_codeql(self) -> str:
        """查找 CodeQL CLI"""
        if self.config.codeql_cli_path:
            return self.config.codeql_cli_path
        
        # 尝试从 PATH 中查找
        result = shutil.which("codeql")
        if result:
            return result
        
        # 尝试常见安装位置
        common_paths = [
            os.path.expanduser("~/.codeql/codeql-cli/codeql/codeql"),
            "/opt/codeql/codeql",
            "/usr/local/bin/codeql",
        ]
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        return "codeql"  # 假设在 PATH 中
    
    def _verify_installation(self) -> bool:
        """验证 CodeQL 安装"""
        try:
            result = subprocess.run(
                [self._codeql_cmd, "version", "--format=json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                version_info = json.loads(result.stdout)
                self._version = version_info.get("version", "unknown")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        
        self._version = None
        return False
    
    @property
    def is_available(self) -> bool:
        """CodeQL 是否可用"""
        return self._version is not None
    
    @property
    def version(self) -> Optional[str]:
        """CodeQL 版本"""
        return self._version
    
    def _run_codeql(self, args: List[str], timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        """运行 CodeQL 命令"""
        cmd = [self._codeql_cmd] + args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.config.timeout
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def create_database(
        self,
        source_path: str,
        language: str = "python",
        database_name: Optional[str] = None,
        overwrite: bool = True
    ) -> Tuple[bool, str]:
        """
        创建 CodeQL 数据库
        
        Args:
            source_path: 源代码路径
            language: 编程语言
            database_name: 数据库名称
            overwrite: 是否覆盖已存在的数据库
        
        Returns:
            (成功与否, 数据库路径或错误信息)
        """
        source_path = os.path.abspath(source_path)
        
        if not os.path.exists(source_path):
            return False, f"Source path does not exist: {source_path}"
        
        # 规范化语言名称
        lang_lower = language.lower()
        normalized_lang = None
        for lang, aliases in self.SUPPORTED_LANGUAGES.items():
            if lang_lower in aliases:
                normalized_lang = lang
                break
        
        if not normalized_lang:
            return False, f"Unsupported language: {language}"
        
        # 确定数据库路径
        if not database_name:
            database_name = os.path.basename(source_path) + f"-{normalized_lang}-db"
        
        db_path = os.path.join(self.config.database_dir, database_name)
        
        # 如果数据库已存在
        if os.path.exists(db_path):
            if overwrite:
                shutil.rmtree(db_path)
            else:
                return True, db_path  # 使用现有数据库
        
        # 构建命令
        args = [
            "database", "create",
            db_path,
            f"--language={normalized_lang}",
            f"--source-root={source_path}",
        ]
        
        if self.config.threads > 0:
            args.append(f"--threads={self.config.threads}")
        
        # 执行创建
        success, stdout, stderr = self._run_codeql(args, timeout=1800)  # 30分钟超时
        
        if success:
            return True, db_path
        else:
            return False, f"Failed to create database: {stderr}"
    
    def run_query(
        self,
        database_path: str,
        query: str,
        output_format: str = "sarif-latest"
    ) -> Tuple[bool, Any]:
        """
        运行 CodeQL 查询
        
        Args:
            database_path: 数据库路径
            query: 查询路径或查询套件名称
            output_format: 输出格式 (sarif-latest, csv, json)
        
        Returns:
            (成功与否, 查询结果或错误信息)
        """
        if not os.path.exists(database_path):
            return False, f"Database does not exist: {database_path}"
        
        # 确定查询路径
        query_path = query
        if not os.path.exists(query):
            # 可能是内置查询套件
            if query in self.QUERY_SUITES:
                # 从数据库推断语言
                lang = self._get_database_language(database_path)
                if lang:
                    query_path = self.QUERY_SUITES[query].format(lang=lang)
            else:
                # 尝试自定义查询目录
                custom_query = os.path.join(self.config.queries_path, query)
                if os.path.exists(custom_query):
                    query_path = custom_query
        
        # 创建临时输出文件
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            output_path = f.name
        
        try:
            print("????", database_path, query_path)
            args = [
                "database", "analyze",
                database_path,
                query_path,
                f"--format={output_format}",
                f"--output={output_path}",
                "--sarif-add-snippets",
            ]
            
            if self.config.threads > 0:
                args.append(f"--threads={self.config.threads}")
            
            success, stdout, stderr = self._run_codeql(args)
            
            if success and os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    result = json.load(f)
                return True, result
            else:
                return False, f"Query failed: {stderr}"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def _get_database_language(self, database_path: str) -> Optional[str]:
        """从数据库获取语言信息"""
        db_info_path = os.path.join(database_path, "codeql-database.yml")
        if os.path.exists(db_info_path):
            try:
                import yaml
                with open(db_info_path) as f:
                    info = yaml.safe_load(f)
                    return info.get("primaryLanguage")
            except:
                pass
        
        # 从目录名推断
        db_name = os.path.basename(database_path)
        for lang in self.SUPPORTED_LANGUAGES:
            if lang in db_name.lower():
                return lang
        
        return "python"  # 默认
    
    def analyze(
        self,
        source_path: str,
        language: str = "python",
        queries: Optional[List[str]] = None,
        include_call_graph: bool = True
    ) -> CodeQLAnalysisResult:
        """
        完整分析流程
        
        Args:
            source_path: 源代码路径
            language: 编程语言
            queries: 要执行的查询列表，None 表示使用默认安全查询
            include_call_graph: 是否包含调用图分析
        
        Returns:
            CodeQLAnalysisResult
        """
        start_time = datetime.now()
        result = CodeQLAnalysisResult(
            success=False,
            database_path=""
        )
        
        # 检查 CodeQL 是否可用
        if not self.is_available:
            result.errors.append("CodeQL is not installed or not in PATH")
            return result
        
        # 创建数据库
        success, db_path_or_error = self.create_database(source_path, language)
        if not success:
            result.errors.append(db_path_or_error)
            return result
        
        result.database_path = db_path_or_error
        
        # 确定要执行的查询
        if queries is None:
            queries = self._get_default_queries(language)
        
        # 执行查询
        for query in queries:
            query_success, query_result = self.run_query(result.database_path, query)
            
            if query_success:
                findings = self._parse_sarif_results(query_result)
                query_name = os.path.basename(query).replace(".ql", "")
                result.query_results[query_name] = findings
            else:
                result.errors.append(f"Query '{query}' failed: {query_result}")
        
        # 构建调用图
        if include_call_graph:
            call_graph = self._build_call_graph(result.database_path, language)
            result.call_graph = call_graph
        
        # 统计信息
        result.statistics = {
            "total_findings": sum(len(f) for f in result.query_results.values()),
            "findings_by_query": {k: len(v) for k, v in result.query_results.items()},
            "call_graph_edges": len(result.call_graph),
        }
        
        result.success = True
        result.execution_time = (datetime.now() - start_time).total_seconds()
        
        return result
    
    def _get_default_queries(self, language: str) -> List[str]:
        """获取默认查询列表"""
        queries_dir = os.path.join(self.config.queries_path, language)
        
        if os.path.exists(queries_dir):
            return [
                os.path.join(queries_dir, f)
                for f in os.listdir(queries_dir)
                if f.endswith(".ql")
            ]
        
        # 使用内置安全查询
        return ["security"]
    
    def _parse_sarif_results(self, sarif: Dict) -> List[CodeQLFinding]:
        """解析 SARIF 格式结果"""
        findings = []
        
        for run in sarif.get("runs", []):
            # 获取规则信息
            rules = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules[rule["id"]] = rule
            
            # 解析结果
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule_info = rules.get(rule_id, {})
                
                # 获取位置信息
                locations = result.get("locations", [{}])
                if locations:
                    location = locations[0].get("physicalLocation", {})
                    artifact = location.get("artifactLocation", {})
                    region = location.get("region", {})
                    
                    file_path = artifact.get("uri", "")
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine", start_line)
                    start_col = region.get("startColumn", 0)
                    end_col = region.get("endColumn", 0)
                else:
                    file_path = ""
                    start_line = end_line = start_col = end_col = 0
                
                # 获取严重程度
                severity = "warning"
                if "security-severity" in rule_info.get("properties", {}):
                    sec_sev = float(rule_info["properties"]["security-severity"])
                    if sec_sev >= 9.0:
                        severity = "critical"
                    elif sec_sev >= 7.0:
                        severity = "high"
                    elif sec_sev >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                
                # 获取 CWE
                cwe_ids = []
                for tag in rule_info.get("properties", {}).get("tags", []):
                    if tag.startswith("external/cwe/cwe-"):
                        cwe_ids.append(tag.replace("external/cwe/", "").upper())
                
                # 解析数据流路径
                source = None
                sink = None
                path_nodes = []
                
                code_flows = result.get("codeFlows", [])
                if code_flows:
                    thread_flows = code_flows[0].get("threadFlows", [])
                    if thread_flows:
                        locations = thread_flows[0].get("locations", [])
                        for i, loc in enumerate(locations):
                            node_info = self._parse_flow_location(loc)
                            if i == 0:
                                source = node_info
                            elif i == len(locations) - 1:
                                sink = node_info
                            else:
                                path_nodes.append(node_info)
                
                finding = CodeQLFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=result.get("message", {}).get("text", ""),
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    start_column=start_col,
                    end_column=end_col,
                    cwe_ids=cwe_ids,
                    source=source,
                    sink=sink,
                    path_nodes=path_nodes
                )
                findings.append(finding)
        
        return findings
    
    def _parse_flow_location(self, location: Dict) -> Dict[str, Any]:
        """解析数据流位置"""
        phys_loc = location.get("location", {}).get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})
        
        return {
            "file": artifact.get("uri", ""),
            "line": region.get("startLine", 0),
            "column": region.get("startColumn", 0),
            "snippet": region.get("snippet", {}).get("text", ""),
            "message": location.get("location", {}).get("message", {}).get("text", "")
        }
    
    def _build_call_graph(self, database_path: str, language: str) -> List[CallGraphEdge]:
        """构建调用图"""
        call_graph_query = os.path.join(
            self.config.queries_path, language, "call_graph.ql"
        )
        
        if not os.path.exists(call_graph_query):
            return []
        
        # 执行调用图查询
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            output_path = f.name
        
        try:
            args = [
                "database", "analyze",
                database_path,
                call_graph_query,
                "--format=csv",
                f"--output={output_path}",
            ]
            
            success, _, _ = self._run_codeql(args)
            
            if success and os.path.exists(output_path):
                return self._parse_call_graph_csv(output_path)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
        
        return []
    
    def _parse_call_graph_csv(self, csv_path: str) -> List[CallGraphEdge]:
        """解析调用图 CSV"""
        edges = []
        
        with open(csv_path, 'r') as f:
            import csv
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    edge = CallGraphEdge(
                        caller_name=row.get("caller_name", ""),
                        caller_file=row.get("caller_file", ""),
                        caller_line=int(row.get("caller_line", 0)),
                        callee_name=row.get("callee_name", ""),
                        callee_file=row.get("callee_file", ""),
                        callee_line=int(row.get("callee_line", 0)),
                        call_site_line=int(row.get("call_site_line", 0))
                    )
                    edges.append(edge)
                except (ValueError, KeyError):
                    continue
        
        return edges
    
    def find_paths_to_sink(
        self,
        call_graph: List[CallGraphEdge],
        sink_name: str,
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        在调用图中查找到达 sink 的所有路径
        
        Args:
            call_graph: 调用图边列表
            sink_name: 目标 sink 函数名（部分匹配）
            max_depth: 最大搜索深度
        
        Returns:
            路径列表，每个路径是函数名列表
        """
        # 构建图
        graph = {}  # caller -> [callees]
        reverse_graph = {}  # callee -> [callers]
        
        for edge in call_graph:
            caller = edge.caller_name
            callee = edge.callee_name
            
            if caller not in graph:
                graph[caller] = []
            graph[caller].append(callee)
            
            if callee not in reverse_graph:
                reverse_graph[callee] = []
            reverse_graph[callee].append(caller)
        
        # 找到匹配的 sink
        sinks = [name for name in reverse_graph if sink_name in name]
        
        # 从 sink 反向搜索
        all_paths = []
        for sink in sinks:
            paths = self._find_paths_bfs(reverse_graph, sink, max_depth)
            all_paths.extend(paths)
        
        return all_paths
    
    def _find_paths_bfs(
        self,
        graph: Dict[str, List[str]],
        start: str,
        max_depth: int
    ) -> List[List[str]]:
        """BFS 搜索路径"""
        paths = []
        queue = [(start, [start])]
        
        while queue:
            node, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            if node not in graph or not graph[node]:
                # 到达入口
                paths.append(list(reversed(path)))
            else:
                for next_node in graph[node]:
                    if next_node not in path:  # 避免循环
                        queue.append((next_node, path + [next_node]))
        
        return paths
    


