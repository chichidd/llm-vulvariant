"""
漏洞画像数据模型

# 漏洞profile:
A. 应用相关
1. 漏洞影响的repo版本
2. 所在应用类型
3. 所在应用模块

B. 漏洞数据
1. vuln type，cwe
2. 触发链路，sink，source
3. 漏洞payload/PoC
4. 脆弱点（例如，os.system)

C. 影响相关
4. 触发场景(e.g., 使用web上传checkpoint)
4.1 sink source性质， 
4.2 链路性质
5. 触发条件(e.g., 输入恶意路文件路径/ 注入路径名)
6. 漏洞原因 (e.g., development? logic?)

"""
import os
import re
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
import hashlib
from dataclasses import dataclass, field

from core.llm_client import BaseLLMClient
from core.config import REPO_BASE_PATH
from core.software_profile import SoftwareProfile
from utils.git_utils import get_git_commit, checkout_commit
from utils.llm_utils import (
    parse_llm_json,
    extract_function_snippet_based_on_name_with_ast
)

    

@dataclass
class SourceFeature:
    """Source信息（数据来源）"""
    description: str # 描述数据来源
    api: str
    data_type: str  # user_input, file_input, network_input, env_var, etc.
    location: str  # 文件路径:行号
    trust_level: str = "untrusted"  # trusted, semi-trusted, untrusted

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceFeature":
        return cls(
            description=data.get("description", ""),
            api=data.get("api", ""),
            data_type=data.get("data_type", ""),
            location=data.get("location", ""),
            trust_level=data.get("trust_level", "untrusted"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "api": self.api,
            "data_type": self.data_type,
            "location": self.location,
            "trust_level": self.trust_level,
        }

@dataclass
class FlowFeature:
    """Flow features信息（污点传播路径）
    
    描述从Source到Sink的完整污点传播路径及其特征。
    """
    description: str  # 污点传播路径的整体描述
    
    # 路径相关
    call_path: List[Dict[str, str]] = field(default_factory=list)  # 调用路径，每个元素包含file, function, line
    path_conditions: List[str] = field(default_factory=list)  # 路径上的条件分支
    
    # 依赖相关
    path_dependency: List[str] = field(default_factory=list)  # 影响路径的依赖项（函数、模块、外部库）
    
    # 污点数据相关
    operations: List[str] = field(default_factory=list)  # 污点数据经历的操作（拼接、编码、解码等）
    alias: List[str] = field(default_factory=list)  # 污点数据的别名（变量名）
    transformations: List[str] = field(default_factory=list)  # 数据转换（类型变化、格式变化）
    
    # 安全相关
    sanitizers: List[str] = field(default_factory=list)  # 路径上的净化操作（如果有）
    validators: List[str] = field(default_factory=list)  # 路径上的验证操作（如果有）

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowFeature":
        return cls(
            description=data.get("description", ""),
            call_path=data.get("call_path", []),
            path_conditions=data.get("path_conditions", []),
            path_dependency=data.get("path_dependency", []),
            operations=data.get("operations", []),
            alias=data.get("alias", []),
            transformations=data.get("transformations", []),
            sanitizers=data.get("sanitizers", []),
            validators=data.get("validators", []),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "call_path": self.call_path,
            "path_conditions": self.path_conditions,
            "path_dependency": self.path_dependency,
            "operations": self.operations,
            "alias": self.alias,
            "transformations": self.transformations,
            "sanitizers": self.sanitizers,
            "validators": self.validators,
        } 

@dataclass
class SinkFeature:
    """Sink信息（危险操作点）TODO"""
    description: str
    type: str  # deserialization, code_execution, file_operation, etc.
    location: str
    function: str
    parameter: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SinkFeature":
        return cls(
            description=data.get("description", ""),
            type=data.get("type", ""),
            location=data.get("location", ""),
            function=data.get("function", ""),
            parameter=data.get("parameter", ""),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "type": self.type,
            "location": self.location,
            "function": self.function,
            "parameter": self.parameter,
        }

@dataclass
class VulnEntry:
    """漏洞数据条目模型"""
    repo_name: str
    commit: str
    call_chain: List[Dict[str, Any]]  # list of dictionary with key (file_path, function_name) or "vuln_sink"
    payload: Optional[str] = None
    cve_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnEntry":
        return cls(
            repo_name=data.get("repo_name", ""),
            commit=data.get("commit", ""),
            call_chain=data.get("call_chain", []),
            payload=data.get("payload", None),
            cve_id=data.get("cve_id", None),
        )


@dataclass
class VulnerabilityProfile:
    """漏洞画像数据模型"""
    
    repo_name: str
    affected_version: Optional[str] = None
    cve_id: Optional[str] = None
    payload: Optional[str] = None
    call_chain: List[Dict[str, Any]] = field(default_factory=list)

    source_features: Optional[SourceFeature] = None
    flow_features: Optional[FlowFeature] = None
    sink_features: Optional[SinkFeature] = None

    exploit_scenarios: List[str] = field(default_factory=list)
    exploit_conditions: List[str] = field(default_factory=list)
    vuln_description: Optional[str] = None
    vuln_cause: Optional[str] = None
    
    # 新增安全评估字段
    cwe_id: str = ""  # CWE漏洞分类ID，暂时留空
    severity: str = ""  # 严重程度: critical/high/medium/low
    attack_vector: str = ""  # 攻击向量: network/local/physical
    user_interaction: str = ""  # 是否需要用户交互: required/none
    privileges_required: str = ""  # 所需权限: none/low/high
    exploit_complexity: str = ""  # 利用复杂度: low/high
    affected_modules: List[str] = field(default_factory=list)  # 受影响的模块列表
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "repo_name": self.repo_name,
            "affected_version": self.affected_version,
            "cve_id": self.cve_id,
            "payload": self.payload,
            "call_chain": self.call_chain,
            "source_features": self.source_features.to_dict() if self.source_features else None,
            "flow_features": self.flow_features.to_dict() if self.flow_features else None,
            "sink_features": self.sink_features.to_dict() if self.sink_features else None,
            "exploit_scenarios": self.exploit_scenarios,
            "exploit_conditions": self.exploit_conditions,
            "vuln_description": self.vuln_description,
            "vuln_cause": self.vuln_cause,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "attack_vector": self.attack_vector,
            "user_interaction": self.user_interaction,
            "privileges_required": self.privileges_required,
            "exploit_complexity": self.exploit_complexity,
            "affected_modules": self.affected_modules,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityProfile":
        """从字典创建实例"""
        return cls(
            repo_name=data.get("repo_name", ""),
            affected_version=data.get("affected_version"),
            cve_id=data.get("cve_id"),
            payload=data.get("payload"),
            call_chain=data.get("call_chain", []),
            source_features=SourceFeature.from_dict(data["source_features"]) if data.get("source_features") else None,
            flow_features=FlowFeature.from_dict(data["flow_features"]) if data.get("flow_features") else None,
            sink_features=SinkFeature.from_dict(data["sink_features"]) if data.get("sink_features") else None,
            exploit_scenarios=data.get("exploit_scenarios", []),
            exploit_conditions=data.get("exploit_conditions", []),
            vuln_description=data.get("vuln_description"),
            vuln_cause=data.get("vuln_cause"),
            cwe_id=data.get("cwe_id", ""),
            severity=data.get("severity", ""),
            attack_vector=data.get("attack_vector", ""),
            user_interaction=data.get("user_interaction", ""),
            privileges_required=data.get("privileges_required", ""),
            exploit_complexity=data.get("exploit_complexity", ""),
            affected_modules=data.get("affected_modules", []),
        )
    

class VulnerabilityProfiler:
    """
    漏洞画像生成器
    
    负责分析已知漏洞并生成完整的漏洞画像，包括：·
    2.1 Source-Sink的污点路径及其特征
    2.2 软件架构角度的漏洞存在原因
    2.3 构建漏洞画像与归类
    """
    
    def __init__(
        self, 
        llm_client: BaseLLMClient = None, 
        repo_profile: SoftwareProfile = None, 
        vuln_entry: VulnEntry = None,
        output_dir: Path = None
    ):
        self.llm_client = llm_client
        self.repo_profile = repo_profile
        self.vuln_entry = vuln_entry
        self.output_dir = Path(output_dir) if output_dir else None
        
        # 初始化存储管理器
        from core.profile_storage import ProfileStorageManager
        self.storage_manager = ProfileStorageManager(
            base_dir=self.output_dir,
            profile_type="vulnerability_profile"
        ) if self.output_dir else None
    
    # ==================== Helper Methods ====================
    
    def _read_function_snippet(self, file_path: str, function_name: str) -> str:
        """
        读取指定函数的代码片段（带行号）
        
        Args:
            file_path: 相对于仓库根目录的文件路径
            function_name: 函数名
            
        Returns:
            带行号的函数代码片段，失败时返回错误信息
        """
        repo_path = REPO_BASE_PATH / self.vuln_entry.repo_name
        full_file_path = repo_path / file_path
        
        try:
            file_content = full_file_path.read_text(encoding='utf-8', errors='ignore')
            
            code_snippet = extract_function_snippet_based_on_name_with_ast(
                file_content,
                function_name,
                with_line_numbers=True,
                line_number_format="standard"
            )
            
            if code_snippet:
                return code_snippet
            return f"[Failed to extract function: {function_name}]"
            
        except Exception as e:
            return f"[Error reading file {file_path}: {e}]"
    
    def _get_file_summary(self, file_path: str) -> str:
        """
        获取文件的功能摘要
        
        Args:
            file_path: 相对于仓库根目录的文件路径
            
        Returns:
            文件功能摘要字符串
        """
        if not self.repo_profile or not hasattr(self.repo_profile, 'repo_info'):
            return "No summary available"
        
        file_summaries = self.repo_profile.repo_info.get('file_summaries', {})
        
        # 直接匹配
        if file_path in file_summaries:
            summary_data = file_summaries[file_path]
            if isinstance(summary_data, dict):
                return summary_data.get('functionality', 'No description')
            return str(summary_data)
        
        # 模糊匹配（路径格式可能不同）
        for key, value in file_summaries.items():
            if file_path in key or key in file_path:
                if isinstance(value, dict):
                    return value.get('functionality', 'No description')
                return str(value)
        
        return "No summary available"
    
    def _is_file_in_module_scope(self, file_path: str, module_files: List[str]) -> bool:
        """
        检查文件是否在模块范围内（考虑多级父目录）
        
        Args:
            file_path: 要检查的文件路径
            module_files: 模块包含的文件/目录列表
            
        Returns:
            如果文件在模块范围内返回True
        """
        file_path_obj = Path(file_path)
        
        for mf in module_files:
            mf_path = Path(mf)
            
            # 1. 直接匹配：文件路径完全相同
            if file_path == mf:
                return True
            
            # 2. 文件在模块目录下：file_path以mf开头（mf是目录）
            if file_path.startswith(mf.rstrip('/') + '/'):
                return True
            
            # 3. 模块文件是文件路径的子路径（mf在file_path目录下）
            if mf.startswith(file_path.rstrip('/') + '/'):
                return True
            
            # 4. 检查多级父目录匹配
            # 获取file_path的所有父目录
            current = file_path_obj
            while current != current.parent:
                current = current.parent
                current_str = str(current)
                
                # 模块路径是当前父目录或其子目录
                if current_str == mf or mf.startswith(current_str.rstrip('/') + '/'):
                    return True
                
                # 当前父目录是模块路径或在模块路径下
                if mf == current_str or current_str.startswith(mf.rstrip('/') + '/'):
                    return True
        
        return False
    
    def _get_module_info(self, file_path: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        获取文件所属的模块信息
        
        Args:
            file_path: 相对于仓库根目录的文件路径
            
        Returns:
            (格式化的模块信息字符串, 匹配的模块列表)
        """
        if not self.repo_profile or not hasattr(self.repo_profile, 'modules'):
            return "No module information available", []
        
        modules = self.repo_profile.modules
        matched_modules = []
        
        for module in modules:
            if isinstance(module, dict):
                module_files = module.get('files', [])
                if self._is_file_in_module_scope(file_path, module_files):
                    if module not in matched_modules:
                        matched_modules.append(module)
        
        if not matched_modules:
            return "No module information available", []
        
        module_info = "\n".join([
            f"- Module: {m.get('name', 'unknown')}\n"
            f"  Category: {m.get('category', 'unknown')}\n"
            f"  Description: {m.get('description', 'N/A')}"
            for m in matched_modules[:3]  # 限制最多3个模块
        ])
        
        return module_info, matched_modules
    
    def _get_affected_modules(self) -> List[str]:
        """
        根据调用链获取所有受影响的模块名称列表
        
        Returns:
            受影响的模块名称列表（去重）
        """
        affected = set()
        
        for call in self.vuln_entry.call_chain:
            file_path = call.get('file_path', '')
            if file_path:
                _, matched_modules = self._get_module_info(file_path)
                for m in matched_modules:
                    module_name = m.get('name', '')
                    if module_name:
                        affected.add(module_name)
        
        return list(affected)
    
    # ==================== Main Methods ====================
    
    def generate_vulnerability_profile(self, repo_path: str, save_results: bool = True) -> VulnerabilityProfile:
        """
        生成完整的漏洞画像
        
        Args:
            repo_path: 仓库路径
            save_results: 是否保存结果到文件
            
        Returns:
            VulnerabilityProfile对象
        """
        repo_path = Path(repo_path)
        repo_name = repo_path.name
        assert self.repo_profile.name == repo_name, "Repo profile does not match the target repo"

        target_commit = self.vuln_entry.commit
        current_commit = get_git_commit(str(repo_path))

        if current_commit != target_commit:
            checkout_commit(str(repo_path), target_commit)
        
        # 获取路径标识符 (repo_name, commit, cve_id)
        cve_id = self.vuln_entry.cve_id or "no_cve"
        path_parts = (repo_name, target_commit, cve_id)
        
        # 保存或更新元数据
        if save_results and self.storage_manager:
            from datetime import datetime
            vuln_profile_info = {
                "repo_name": repo_name,
                "commit": target_commit,
                "cve_id": self.vuln_entry.cve_id,
                "analysis_date": datetime.now().isoformat(),
                "llm_config": {
                    "model": self.llm_client.config.model if self.llm_client else "none",
                    "temperature": self.llm_client.config.temperature if self.llm_client else 0.0,
                } if self.llm_client else {},
                "payload": self.vuln_entry.payload,
                "call_chain": self.vuln_entry.call_chain,
            }
            self.storage_manager.save_profile_info(
                vuln_profile_info, 
                *path_parts, 
                info_filename="vuln_profile_info.json"
            )
        
        # 提取Source/Flow/Sink特征（启用对话保存）
        source_features = self._extract_source_features(save_conversations=save_results)
        sink_features = self._extract_sink_features(save_conversations=save_results)
        flow_features = self._extract_flow_features(save_conversations=save_results)
        
        # 获取漏洞综合描述
        describe_vuln = self._describe_vuln(save_conversations=save_results)
        
        # 获取受影响模块
        affected_modules = self._get_affected_modules()
        
        # 构建漏洞画像
        profile = VulnerabilityProfile(
            repo_name=repo_name,
            affected_version=target_commit,
            call_chain=self.vuln_entry.call_chain,
            payload=self.vuln_entry.payload,
            cve_id=self.vuln_entry.cve_id,

            source_features=source_features,
            sink_features=sink_features,
            flow_features=flow_features,

            exploit_scenarios=describe_vuln['exploit_scenarios'],
            exploit_conditions=describe_vuln['exploit_conditions'],
            vuln_description=describe_vuln['vuln_description'],
            vuln_cause=describe_vuln['vuln_cause'],
            
            # 安全评估字段
            cwe_id="",  # 暂时留空
            severity=describe_vuln['severity'],
            attack_vector=describe_vuln['attack_vector'],
            user_interaction=describe_vuln['user_interaction'],
            privileges_required=describe_vuln['privileges_required'],
            exploit_complexity=describe_vuln['exploit_complexity'],
            affected_modules=affected_modules,
        )
        
        # 保存各部分结果到checkpoints
        if save_results and self.storage_manager:
            self.storage_manager.save_checkpoint(
                "source_features", 
                source_features.to_dict(), 
                *path_parts
            )
            self.storage_manager.save_checkpoint(
                "sink_features", 
                sink_features.to_dict(), 
                *path_parts
            )
            self.storage_manager.save_checkpoint(
                "flow_features", 
                flow_features.to_dict(), 
                *path_parts
            )
            self.storage_manager.save_checkpoint(
                "vuln_description", 
                describe_vuln, 
                *path_parts
            )
            
            # 保存最终完整画像
            self.storage_manager.save_final_result(
                "vulnerability_profile.json",
                json.dumps(profile.to_dict(), indent=2, ensure_ascii=False),
                *path_parts
            )

        return profile


        
    

    def _extract_source_features(self, save_conversations: bool = False) -> SourceFeature:
        """
        提取漏洞的Source特征
        
        通过分析调用链的第一个函数调用，结合代码片段、文件摘要和模块信息，
        使用LLM提取Source的详细特征。
        
        Returns:
            SourceFeature对象，包含数据来源的详细信息
        """
        # 提取第一个调用点作为Source
        if not self.vuln_entry.call_chain:
            return SourceFeature(
                description="No call chain available",
                api="unknown",
                data_type="unknown",
                location="unknown",
                trust_level="untrusted"
            )
        
        first_call = self.vuln_entry.call_chain[0]
        file_path = first_call.get('file_path', '')
        function_name = first_call.get('function_name', '')
        
        if not file_path or not function_name:
            # 如果是直接的sink调用，没有file_path
            return SourceFeature(
                description=f"Direct sink call: {first_call.get('vuln_sink', 'unknown')}",
                api=first_call.get('vuln_sink', 'unknown'),
                data_type="direct_call",
                location="N/A",
                trust_level="untrusted"
            )
        
        # 使用helper方法获取信息
        code_snippet = self._read_function_snippet(file_path, function_name)
        file_summary = self._get_file_summary(file_path)
        module_info, _ = self._get_module_info(file_path)
        
        # 4. 构建优化的prompt
        prompt = f"""# 任务：分析漏洞Source特征

你是一个污点分析和漏洞分析专家。请仔细分析以下代码片段，识别并提取漏洞的Source（数据来源）特征。

## 背景信息

**仓库名称**: {self.vuln_entry.repo_name}
**受影响版本**: {self.vuln_entry.commit[:8]}
**CVE ID**: {self.vuln_entry.cve_id or 'N/A'}

## Source 代码片段（带行号）

文件路径: `{file_path}`
函数名称: `{function_name}`

```python
{code_snippet}
```

## 文件功能摘要

{file_summary}

## 所属模块信息

{module_info}

## 完整调用链

{' -> '.join([
    f"{call.get('file_path', '')}#{call.get('function_name', call.get('vuln_sink', 'unknown'))}" 
    for call in self.vuln_entry.call_chain
])}

## 漏洞Payload示例

```
{self.vuln_entry.payload or 'N/A'}
```

---

## 分析要求

请仔细分析上述代码片段，重点关注：

1. **数据来源识别**：
   - 这个函数如何接收外部输入？（命令行参数、文件读取、网络请求、环境变量等）
   - 输入来自哪个API或函数参数？
   - 数据是从哪个具体的位置进入的？

2. **数据类型判断**：
   - 确定数据类型（必须是以下之一）：
     * `user_input`: 用户直接输入（命令行参数、表单输入等）
     * `file_input`: 从文件读取的数据
     * `network_input`: 网络请求或API调用获得的数据
     * `env_var`: 环境变量
     * `database_input`: 数据库查询结果
     * `config_input`: 配置文件输入
   - 如果不确定，根据代码逻辑合理推断

3. **信任级别评估**：
   - `untrusted`: 完全不可信的外部输入（默认，大多数情况）
   - `semi-trusted`: 部分可信的输入（如来自配置文件但未验证）
   - `trusted`: 可信的输入（极少见，需要有明确的验证逻辑）

4. **精确定位**：
   - 记录准确的代码位置（文件路径:行号）
   - 识别具体的API或函数调用

## 注意事项

⚠️ **重要**：
- 仔细查看行号，确保location准确
- 不要遗漏关键的输入处理逻辑
- 如果代码片段不完整，基于上下文合理推断
- description应该简洁但包含关键信息

## 输出格式

**必须**严格按照以下格式输出，JSON主体包含在"```json"和"```"之间，不要包含任何其他内容：

```json
{{
    "thinking": "你的详细分析思路（2-3句话说明你如何识别Source，为什么这样判断数据类型和信任级别）",
    "description": "简洁描述数据来源（1-2句话，说明数据从哪里来，如何进入系统）",
    "api": "具体的API、函数名或参数名（如argparse.ArgumentParser, sys.argv, request.args.get等）",
    "data_type": "数据类型（必须是user_input/file_input/network_input/env_var/database_input/config_input之一）",
    "location": "代码位置（格式: 文件路径:行号，如 tools/asr_evaluator.py:42）",
    "trust_level": "信任级别（必须是untrusted/semi-trusted/trusted之一，默认untrusted）"
}}
```

请开始分析："""

        # 5. 查询LLM
        conversations = [
            {"role": "system", "content": "你是一个污点分析和漏洞分析领域的资深专家，擅长识别代码中的安全漏洞和数据流分析。"},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.llm_client.chat(conversations)
            
            # 保存对话记录
            if save_conversations and self.storage_manager:
                cve_id = self.vuln_entry.cve_id or "no_cve"
                path_parts = (self.vuln_entry.repo_name, self.vuln_entry.commit, cve_id)
                self.storage_manager.save_conversation(
                    "source_features",
                    conversations + [{"role": "assistant", "content": response}],
                    *path_parts
                )
            
            result = parse_llm_json(response)
            
            if not result:
                raise ValueError("Failed to parse LLM response as JSON")
            
            # 6. 构建并返回SourceFeature对象
            source_feature = SourceFeature(
                description=result.get('description', f"Source at {file_path}"),
                api=result.get('api', function_name),
                data_type=result.get('data_type', 'user_input'),
                location=result.get('location', f"{file_path}:unknown"),
                trust_level=result.get('trust_level', 'untrusted')
            )
            
            return source_feature
            
        except Exception as e:
            print(f"[ERROR] Failed to extract source features: {e}")
            # 返回基于启发式规则的默认结果
            return SourceFeature(
                description=f"Source function: {function_name} in {file_path}",
                api=function_name,
                data_type="user_input",
                location=f"{file_path}:unknown",
                trust_level="untrusted"
            )

    def _extract_flow_features(self, save_conversations: bool = False) -> FlowFeature:
        """
        提取漏洞的Flow特征（污点传播路径）
        
        通过分析完整的调用链，读取每个中间函数的代码片段，
        使用LLM提取污点数据如何从Source传播到Sink的详细特征。
        
        Returns:
            FlowFeature对象，包含污点传播路径的详细信息
        """
        call_chain = self.vuln_entry.call_chain
        
        if not call_chain or len(call_chain) < 2:
            return FlowFeature(
                description="Call chain too short for flow analysis",
                call_path=[],
                path_conditions=[],
                path_dependency=[],
                operations=[],
                alias=[],
                transformations=[],
                sanitizers=[],
                validators=[]
            )
        
        # 1. 收集所有函数的代码片段（使用helper方法）
        code_snippets = []
        for i, call in enumerate(call_chain):
            if 'vuln_sink' in call:
                code_snippets.append({
                    "index": i + 1,
                    "type": "sink",
                    "function": call['vuln_sink'],
                    "snippet": f"[Dangerous Sink Function: {call['vuln_sink']}]"
                })
                continue
            
            file_path = call.get('file_path', '')
            function_name = call.get('function_name', '')
            
            if not file_path or not function_name:
                continue
            
            # 使用helper方法读取代码片段
            snippet = self._read_function_snippet(file_path, function_name)
            code_snippets.append({
                "index": i + 1,
                "type": "function",
                "file_path": file_path,
                "function_name": function_name,
                "snippet": snippet
            })
        
        # 2. 格式化代码片段为prompt内容
        formatted_snippets = []
        for cs in code_snippets:
            if cs["type"] == "sink":
                formatted_snippets.append(
                    f"### Step {cs['index']}: Sink Function\n"
                    f"**Function**: `{cs['function']}`\n"
                    f"{cs['snippet']}"
                )
            elif cs["type"] == "function":
                formatted_snippets.append(
                    f"### Step {cs['index']}: {cs['file_path']}#{cs['function_name']}\n"
                    f"```python\n{cs['snippet']}\n```"
                )
            else:
                formatted_snippets.append(
                    f"### Step {cs['index']}: {cs.get('file_path', 'Unknown')}\n"
                    f"{cs['snippet']}"
                )
        
        code_context = "\n\n".join(formatted_snippets)
        
        # 3. 收集文件摘要信息（使用helper方法）
        summaries = []
        for call in call_chain:
            file_path = call.get('file_path', '')
            if file_path:
                summary = self._get_file_summary(file_path)
                if summary != "No summary available":
                    summaries.append(f"- `{file_path}`: {summary}")
        
        file_summaries_text = "\n".join(summaries) if summaries else "No file summaries available"
        
        # 4. 构建prompt
        prompt = f"""# 任务：分析漏洞污点传播路径（Flow）特征

你是一个污点分析和数据流分析专家。请仔细分析以下调用链中的代码，追踪污点数据如何从Source传播到Sink。

## 背景信息

**仓库名称**: {self.vuln_entry.repo_name}
**受影响版本**: {self.vuln_entry.commit[:8]}
**CVE ID**: {self.vuln_entry.cve_id or 'N/A'}

## 调用链概览

{' -> '.join([
    call.get('function_name', call.get('vuln_sink', 'unknown'))
    for call in call_chain
])}

## 完整代码片段（按调用顺序）

{code_context}

## 文件功能摘要

{file_summaries_text}

## 漏洞Payload

```
{self.vuln_entry.payload or 'N/A'}
```

---

## 分析要求

请仔细分析上述代码，追踪污点数据的完整传播路径：

1. **调用路径分析**：
   - 从Source函数开始，污点数据如何逐步传递到Sink？
   - 每个函数中，污点数据通过哪个参数进入，通过什么方式传出？
   - 记录每个关键步骤的文件路径、函数名和大致行号

2. **路径条件**：
   - 路径上有哪些条件分支（if/else, try/except等）？
   - 是否有任何条件可能阻止污点传播？
   - 记录关键的条件判断

3. **路径依赖**：
   - 污点传播依赖哪些函数调用？
   - 依赖哪些外部模块或库？
   - 是否依赖特定的配置或环境？

4. **污点数据操作**：
   - 污点数据经历了哪些操作？（字符串拼接、格式化、编码、解码等）
   - 这些操作是否改变了数据的危险性？

5. **污点别名**：
   - 污点数据在传播过程中使用了哪些变量名？
   - 追踪变量名的变化

6. **数据转换**：
   - 数据类型是否发生变化？（字符串→列表，dict→字符串等）
   - 数据格式是否发生变化？

7. **安全措施检查**：
   - 路径上是否有任何净化（sanitization）操作？
   - 是否有输入验证（validation）？
   - 如果有，它们是否有效？为什么没能阻止漏洞？

## 注意事项

⚠️ **重要**：
- 仔细阅读每个函数的代码，理解数据流向
- 关注函数参数和返回值
- 识别所有可能影响污点传播的操作
- 如果某个步骤不确定，基于代码逻辑合理推断
- 确保alias列表包含所有出现过的污点变量名

## 输出格式

**必须**严格按照以下格式输出，JSON主体包含在"```json"和"```"之间，不要包含任何其他内容：

```json
{{
    "thinking": "你的详细分析思路（3-5句话，说明你如何追踪污点传播，关键的传播节点是什么）",
    "description": "污点传播路径的整体描述（2-3句话，概括从Source到Sink的传播过程）",
    "call_path": [
        {{"file": "文件路径", "function": "函数名", "line": "行号或范围", "role": "source/propagator/sink"}}
    ],
    "path_conditions": ["条件1: 描述", "条件2: 描述"],
    "path_dependency": ["依赖的函数或模块1", "依赖2"],
    "operations": ["操作1: 字符串拼接", "操作2: 命令构造"],
    "alias": ["变量名1", "变量名2", "参数名"],
    "transformations": ["转换1: str -> list", "转换2: 格式化"],
    "sanitizers": ["无" 或 "净化操作描述"],
    "validators": ["无" 或 "验证操作描述"]
}}
```

请开始分析："""

        # 5. 查询LLM
        conversations = [
            {"role": "system", "content": "你是一个污点分析和数据流分析领域的资深专家，擅长追踪代码中的数据传播路径和识别安全漏洞。请严格按照JSON格式输出，不要包含其他内容。"},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.llm_client.chat(conversations)
            
            # 保存对话记录
            if save_conversations and self.storage_manager:
                cve_id = self.vuln_entry.cve_id or "no_cve"
                path_parts = (self.vuln_entry.repo_name, self.vuln_entry.commit, cve_id)
                self.storage_manager.save_conversation(
                    "flow_features",
                    conversations + [{"role": "assistant", "content": response}],
                    *path_parts
                )
            
            result = parse_llm_json(response)
            
            if not result:
                raise ValueError("Failed to parse LLM response as JSON")
            
            # 6. 构建并返回FlowFeature对象
            flow_feature = FlowFeature(
                description=result.get('description', ''),
                call_path=result.get('call_path', []),
                path_conditions=result.get('path_conditions', []),
                path_dependency=result.get('path_dependency', []),
                operations=result.get('operations', []),
                alias=result.get('alias', []),
                transformations=result.get('transformations', []),
                sanitizers=result.get('sanitizers', []),
                validators=result.get('validators', [])
            )
            
            return flow_feature
            
        except Exception as e:
            print(f"[ERROR] Failed to extract flow features: {e}")
            # 返回基于调用链的默认结果
            default_call_path = []
            for call in call_chain:
                if 'vuln_sink' in call:
                    default_call_path.append({
                        "file": "N/A",
                        "function": call['vuln_sink'],
                        "line": "N/A",
                        "role": "sink"
                    })
                else:
                    default_call_path.append({
                        "file": call.get('file_path', ''),
                        "function": call.get('function_name', ''),
                        "line": "unknown",
                        "role": "propagator"
                    })
            
            if default_call_path:
                default_call_path[0]["role"] = "source"
            
            return FlowFeature(
                description=f"Flow from {call_chain[0].get('function_name', 'source')} to {call_chain[-1].get('vuln_sink', call_chain[-1].get('function_name', 'sink'))}",
                call_path=default_call_path,
                path_conditions=[],
                path_dependency=[],
                operations=[],
                alias=[],
                transformations=[],
                sanitizers=[],
                validators=[]
            )
    
    def _extract_sink_features(self, save_conversations: bool = False) -> SinkFeature:
        """
        提取漏洞的Sink特征
        
        通过分析调用链的最后一个函数调用（危险操作点），结合代码片段、文件摘要和模块信息，
        使用LLM提取Sink的详细特征。
        
        Returns:
            SinkFeature对象，包含危险操作点的详细信息
        """
        if not self.vuln_entry.call_chain:
            return SinkFeature(
                description="No call chain available",
                type="unknown",
                location="unknown",
                function="unknown",
                parameter="unknown"
            )
        
        last_call = self.vuln_entry.call_chain[-1]
        
        # 检查是否是直接的sink调用（如subprocess.run, os.system）
        sink_function = last_call.get('vuln_sink', '')
        if not sink_function:
            # 如果最后一个调用不是vuln_sink，使用函数名
            sink_function = last_call.get('function_name', 'unknown')
            
        # 对于直接的sink调用，尝试从倒数第二个调用获取上下文
        if len(self.vuln_entry.call_chain) < 2:
            return SinkFeature(
                description=f"Direct sink call: {sink_function}",
                type=self._infer_sink_type_by_rules(sink_function),
                location="unknown",
                function=sink_function,
                parameter="unknown"
            )
        
        context_call = self.vuln_entry.call_chain[-2]
        file_path = context_call.get('file_path', '')
        function_name = context_call.get('function_name', '')
        
        if not file_path or not function_name:
            return SinkFeature(
                description="Sink information incomplete",
                type=self._infer_sink_type_by_rules(sink_function),
                location="unknown",
                function=sink_function,
                parameter="unknown"
            )
        
        # 使用helper方法获取信息
        code_snippet = self._read_function_snippet(file_path, function_name)
        file_summary = self._get_file_summary(file_path)
        module_info, _ = self._get_module_info(file_path)
        

    
        # 5. 构建优化的prompt
        prompt = f"""# 任务：分析漏洞Sink特征

你是一个污点分析和漏洞分析专家。请仔细分析以下代码片段，识别并提取漏洞的Sink（危险操作点）特征。

## 背景信息

**仓库名称**: {self.vuln_entry.repo_name}
**受影响版本**: {self.vuln_entry.commit[:8]}
**CVE ID**: {self.vuln_entry.cve_id or 'N/A'}

## Sink 代码片段（带行号）

文件路径: `{file_path}`
函数名称: `{function_name}`

```python
{code_snippet}
```

## 文件功能摘要

{file_summary}

## 所属模块信息

{module_info}

## 完整调用链

{' -> '.join([
    f"{call.get('file_path', '')}#{call.get('function_name', call.get('vuln_sink', 'unknown'))}" 
    for call in self.vuln_entry.call_chain
])}

## 实际的危险函数

最终的危险操作: `{sink_function}`

## 漏洞Payload示例

```
{self.vuln_entry.payload or 'N/A'}
```

---

## 分析要求

请仔细分析上述代码片段，重点关注：

1. **危险操作识别**：
   - 这个函数执行什么危险操作？（命令执行、反序列化、文件操作、SQL查询等）
   - 具体调用了哪个危险的API或函数？
   - 这个操作为什么是危险的？

2. **Sink类型判断**：
   - 确定Sink类型（包括但不限于）：
     * `command_injection`: 命令注入（如subprocess.run, os.system, exec等）
     * `code_execution`: 代码执行（如eval, exec, compile等）
     * `deserialization`: 反序列化漏洞（如pickle.loads, yaml.load等）
     * `sql_injection`: SQL注入
     * `path_traversal`: 路径遍历
     * `file_operation`: 危险的文件操作（如任意文件写入、删除）
     * `ssrf`: 服务端请求伪造
     * `xxe`: XML外部实体注入
     * `template_injection`: 模板注入
   - 如果不确定，根据代码逻辑合理推断

3. **参数识别**：
   - 哪个参数接收了污点数据？
   - 参数名是什么？
   - 参数在第几个位置？

4. **精确定位**：
   - 记录准确的代码位置（文件路径:行号）
   - 识别具体的危险函数调用

## 常见Sink模式识别

**命令注入**: subprocess.run(), os.system(), os.popen(), subprocess.call(), subprocess.Popen()
**代码执行**: eval(), exec(), compile(), __import__()
**反序列化**: pickle.loads(), yaml.load(), json.loads() (某些情况)
**文件操作**: open() with 'w'/'a', os.remove(), shutil.rmtree()

## 注意事项

⚠️ **重要**：
- 仔细查看行号，确保location准确
- 识别真正执行危险操作的函数，而不是中间的包装函数
- description应该简洁但准确描述危险操作的本质
- 如果代码片段包含多个可能的sink，选择最危险的那个
- parameter应该是具体的参数名或位置（如 "command", "args[0]", "input_data"等）

## 输出格式

**必须**严格按照以下格式输出，JSON主体包含在"```json"和"```"之间，不要包含任何其他内容：

```json
{{
    "thinking": "你的详细分析思路（2-3句话说明你如何识别Sink，为什么判断为这种类型，哪个参数接收了污点数据）",
    "description": "简洁描述危险操作（1-2句话，说明这个Sink做什么危险操作，为什么危险）",
    "type": "Sink类型（例如command_injection/code_execution/deserialization/sql_injection/path_traversal/file_operation/ssrf/xxe/template_injection等等）",
    "location": "代码位置（格式: 文件路径:行号，如 tools/asr_evaluator/utils.py:156）",
    "function": "危险函数名称（如 subprocess.run, os.system, eval等）",
    "parameter": "接收污点数据的参数名或位置（如 'command', 'args[0]', 'input_data'等）"
}}
```

请开始分析："""

        # 6. 查询LLM
        conversations = [
            {"role": "system", "content": "你是一个污点分析和漏洞分析领域的资深专家，擅长识别代码中的危险操作点和安全漏洞。请严格按照JSON格式输出，不要包含其他内容。"},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.llm_client.chat(conversations)
            
            # 保存对话记录
            if save_conversations and self.storage_manager:
                cve_id = self.vuln_entry.cve_id or "no_cve"
                path_parts = (self.vuln_entry.repo_name, self.vuln_entry.commit, cve_id)
                self.storage_manager.save_conversation(
                    "sink_features",
                    conversations + [{"role": "assistant", "content": response}],
                    *path_parts
                )
            
            result = parse_llm_json(response)
            
            if not result:
                raise ValueError("Failed to parse LLM response as JSON")
            
            # 7. 构建并返回SinkFeature对象
            sink_feature = SinkFeature(
                description=result.get('description', f"Sink at {file_path}"),
                type=result.get('type', self._infer_sink_type_by_rules(sink_function)),
                location=result.get('location', f"{file_path}:unknown"),
                function=result.get('function', sink_function),
                parameter=result.get('parameter', 'unknown')
            )
            assert sink_feature.function != "unknown", "Sink function cannot be unknown"
            
            return sink_feature
            
        except Exception as e:
            print(f"[ERROR] Failed to extract sink features: {e}")
            # 返回基于启发式规则的默认结果
            return SinkFeature(
                description=f"Sink function: {function_name} calls {sink_function}",
                type=self._infer_sink_type_by_rules(sink_function),
                location=f"{file_path}:unknown",
                function=sink_function,
                parameter="unknown"
            )
    

        
    
    def _infer_sink_type_by_rules(self, sink_function: str) -> str:
        """
        基于sink函数名推断sink类型
        
        Args:
            sink_function: 危险函数名称
            
        Returns:
            推断的sink类型
        """
        sink_function_lower = sink_function.lower()
        
        # 命令注入模式
        if any(pattern in sink_function_lower for pattern in [
            'system', 'popen', 'subprocess', 'shell', 'exec', 'call', 'run'
        ]):
            return "command_injection"
        
        # 代码执行模式
        if any(pattern in sink_function_lower for pattern in [
            'eval', 'compile', '__import__'
        ]):
            return "code_execution"
        
        # 反序列化模式
        if any(pattern in sink_function_lower for pattern in [
            'pickle', 'yaml.load', 'loads', 'deserialize', 'unmarshal'
        ]):
            return "deserialization"
        
        # SQL注入模式
        if any(pattern in sink_function_lower for pattern in [
            'execute', 'query', 'sql', 'cursor'
        ]):
            return "sql_injection"
        
        # 文件操作模式
        if any(pattern in sink_function_lower for pattern in [
            'open', 'write', 'read', 'remove', 'delete', 'unlink'
        ]):
            return "file_operation"
        
        # 默认
        return "unknown"

    def _describe_vuln(self, save_conversations: bool = False) -> Dict[str, Any]:
        """
        分析漏洞的综合描述，包括利用场景、利用条件、漏洞描述、漏洞原因和安全评估
        
        Returns:
            包含以下字段的字典：
            - exploit_scenarios: 利用场景列表
            - exploit_conditions: 利用条件列表
            - vuln_description: 漏洞描述
            - vuln_cause: 漏洞原因
            - severity: 严重程度
            - attack_vector: 攻击向量
            - user_interaction: 用户交互要求
            - privileges_required: 所需权限
            - exploit_complexity: 利用复杂度
        """
        # 收集上下文信息
        call_chain = self.vuln_entry.call_chain
        
        # 获取Source和Sink信息
        source_info = "Unknown"
        sink_info = "Unknown"
        
        if call_chain:
            first_call = call_chain[0]
            if 'function_name' in first_call:
                source_info = f"{first_call.get('file_path', '')}#{first_call.get('function_name', '')}"
            
            last_call = call_chain[-1]
            if 'vuln_sink' in last_call:
                sink_info = last_call['vuln_sink']
            elif 'function_name' in last_call:
                sink_info = f"{last_call.get('file_path', '')}#{last_call.get('function_name', '')}"
        
        # 收集代码片段（Source和Sink）
        code_snippets = []
        if call_chain and len(call_chain) >= 1:
            first_call = call_chain[0]
            if first_call.get('file_path') and first_call.get('function_name'):
                snippet = self._read_function_snippet(
                    first_call['file_path'],
                    first_call['function_name']
                )
                code_snippets.append(f"### Source Function: {first_call['function_name']}\n```python\n{snippet}\n```")
        
        if call_chain and len(call_chain) >= 2:
            # 获取Sink上下文（倒数第二个函数，因为最后一个通常是危险API）
            context_call = call_chain[-2] if 'vuln_sink' in call_chain[-1] else call_chain[-1]
            if context_call.get('file_path') and context_call.get('function_name'):
                snippet = self._read_function_snippet(
                    context_call['file_path'],
                    context_call['function_name']
                )
                code_snippets.append(f"### Sink Context Function: {context_call['function_name']}\n```python\n{snippet}\n```")
        
        code_context = "\n\n".join(code_snippets) if code_snippets else "No code snippets available"
        
        # 获取软件画像信息
        software_info = "No software profile available"
        if self.repo_profile:
            software_info = f"""
**名称**: {self.repo_profile.name}
**描述**: {getattr(self.repo_profile, 'description', 'N/A')}
**目标用户**: {', '.join(getattr(self.repo_profile, 'target_user', [])) or 'N/A'}
**目标应用**: {', '.join(getattr(self.repo_profile, 'target_application', [])) or 'N/A'}
"""
        
        # 获取受影响模块
        affected_modules = self._get_affected_modules()
        affected_modules_text = ", ".join(affected_modules) if affected_modules else "Unknown"
        
        # 推断sink类型
        sink_type = "unknown"
        if call_chain and 'vuln_sink' in call_chain[-1]:
            sink_type = self._infer_sink_type_by_rules(call_chain[-1]['vuln_sink'])
        
        # 构建prompt
        prompt = f"""# 任务：漏洞综合分析

你是一个资深的安全研究员。请基于以下漏洞信息，进行全面的安全分析。

## 基本信息

**仓库名称**: {self.vuln_entry.repo_name}
**受影响版本**: {self.vuln_entry.commit[:8]}
**CVE ID**: {self.vuln_entry.cve_id or 'N/A'}
**漏洞类型（推断）**: {sink_type}

## 软件画像

{software_info}

## 调用链

**Source**: {source_info}
**Sink**: {sink_info}
**完整调用链**: {' -> '.join([c.get('function_name', c.get('vuln_sink', '?')) for c in call_chain])}

## 受影响模块

{affected_modules_text}

## 关键代码片段

{code_context}

## 漏洞Payload

```
{self.vuln_entry.payload or 'N/A'}
```

---

## 分析要求

请从以下几个方面分析这个漏洞：

### 1. 利用场景 (exploit_scenarios)
- 在什么实际使用场景下，攻击者可以利用这个漏洞？
- 考虑软件的目标用户和应用场景
- 列出2-4个具体的利用场景

### 2. 利用条件 (exploit_conditions)
- 成功利用这个漏洞需要满足哪些条件？
- 例如：特定的配置、网络访问、用户操作等
- 列出所有必要的前提条件

### 3. 漏洞描述 (vuln_description)
- 用2-3句话简洁描述这个漏洞的本质
- 说明漏洞的技术原理

### 4. 漏洞原因 (vuln_cause)
- 从软件开发角度分析，这个漏洞为什么会存在？
- 是设计缺陷、实现错误、还是缺少安全检查？
- 具体说明根本原因

### 5. CVSS评估（简化版）

**severity**（严重程度）：
- `critical`: 远程代码执行，无需认证
- `high`: 远程代码执行需要低权限，或敏感数据泄露
- `medium`: 需要特定条件才能利用
- `low`: 影响有限

**attack_vector**（攻击向量）：
- `network`: 可通过网络远程利用
- `local`: 需要本地访问
- `physical`: 需要物理接触

**user_interaction**（用户交互）：
- `none`: 无需用户交互
- `required`: 需要用户执行某些操作

**privileges_required**（所需权限）：
- `none`: 无需任何权限
- `low`: 需要低级权限（普通用户）
- `high`: 需要高级权限（管理员）

**exploit_complexity**（利用复杂度）：
- `low`: 容易利用，有现成方法
- `high`: 需要特殊条件或技术

## 输出格式

**必须**严格按照以下JSON格式输出：

```json
{{
    "thinking": "你的分析思路（3-5句话）",
    "exploit_scenarios": ["场景1描述", "场景2描述"],
    "exploit_conditions": ["条件1", "条件2"],
    "vuln_description": "漏洞描述（2-3句话）",
    "vuln_cause": "漏洞原因分析",
    "severity": "critical/high/medium/low",
    "attack_vector": "network/local/physical",
    "user_interaction": "none/required",
    "privileges_required": "none/low/high",
    "exploit_complexity": "low/high"
}}
```

请开始分析："""

        # 查询LLM
        conversations = [
            {"role": "system", "content": "你是一个资深的安全研究员，擅长漏洞分析和风险评估。请严格按照JSON格式输出。"},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.llm_client.chat(conversations)
            
            # 保存对话记录
            if save_conversations and self.storage_manager:
                cve_id = self.vuln_entry.cve_id or "no_cve"
                path_parts = (self.vuln_entry.repo_name, self.vuln_entry.commit, cve_id)
                self.storage_manager.save_conversation(
                    "vuln_description",
                    conversations + [{"role": "assistant", "content": response}],
                    *path_parts
                )
            
            result = parse_llm_json(response)
            
            if not result:
                raise ValueError("Failed to parse LLM response as JSON")
            
            return {
                "exploit_scenarios": result.get('exploit_scenarios', []),
                "exploit_conditions": result.get('exploit_conditions', []),
                "vuln_description": result.get('vuln_description', ''),
                "vuln_cause": result.get('vuln_cause', ''),
                "severity": result.get('severity', ''),
                "attack_vector": result.get('attack_vector', ''),
                "user_interaction": result.get('user_interaction', ''),
                "privileges_required": result.get('privileges_required', ''),
                "exploit_complexity": result.get('exploit_complexity', ''),
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to describe vulnerability: {e}")
            # 返回默认值
            return {
                "exploit_scenarios": [],
                "exploit_conditions": [],
                "vuln_description": f"Vulnerability in {self.vuln_entry.repo_name}",
                "vuln_cause": "Unknown",
                "severity": "",
                "attack_vector": "",
                "user_interaction": "",
                "privileges_required": "",
                "exploit_complexity": "",
            }


