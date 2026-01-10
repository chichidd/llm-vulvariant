"""Prompt builders for the agentic vulnerability finder."""

import json
from typing import Any, Dict

from utils.logger import get_logger

logger = get_logger(__name__)


def _to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return obj
    return {}


def build_system_prompt(vulnerability_profile: Any, toolkit) -> str:
    vuln_dict = _to_dict(vulnerability_profile)
    vuln_summary = {
        "cve_id": vuln_dict.get("cve_id"),
        "vulnerability_type": vuln_dict.get("sink_features", {}).get("type", "unknown")
        if vuln_dict.get("sink_features")
        else "unknown",
        "description": vuln_dict.get("vuln_description"),
        "cause": vuln_dict.get("vuln_cause"),
        "payload": vuln_dict.get("payload"),
        "source_features": vuln_dict.get("source_features"),
        "sink_features": vuln_dict.get("sink_features"),
        "flow_features": vuln_dict.get("flow_features"),
        "exploit_scenarios": vuln_dict.get("exploit_scenarios"),
        "exploit_conditions": vuln_dict.get("exploit_conditions"),
    }

    tools_desc = "\n".join(
        [
            f"- {t.get('function', {}).get('name', t.get('name', 'unknown'))}: {t.get('function', {}).get('description', t.get('description', ''))}"
            for t in toolkit.get_available_tools()
        ]
    )

    return f"""你是一名专注于源代码漏洞挖掘的安全研究员专家。
你的任务是在代码库的其他部分寻找与已知漏洞“相似”的漏洞。

## 已知漏洞分析
{json.dumps(vuln_summary, indent=2, ensure_ascii=False)}

## 什么是“相似漏洞”？
相似漏洞指的是：漏洞类型相同，但实现形式或出现位置不同。例如：
- 已知：os.system(user_input) -> 相似：subprocess.run(cmd, shell=True)、os.popen()
- 已知：pickle.load(file) -> 相似：yaml.unsafe_load()、marshal.load()、shelve.open()
- 已知：字符串拼接导致的 SQL 注入 -> 相似：任何通过 f-string/format 拼接 SQL 查询的写法
- 已知：open(user_path) 的路径穿越 -> 相似：shutil.copy(user_src, dst)、os.rename()

关键点：重要的是漏洞“模式（PATTERN）”，而不是某个具体 API 名称。

## 可用工具
{tools_desc}

## 分析策略
1. 深入理解漏洞模式：
    - SOURCE（来源）：不可信数据从哪里进入？
    - SINK（汇点）：执行了什么危险操作？
    - FLOW（流转）：数据如何从来源流向汇点？
   
2. 对每个候选模块：
    - 先用 list_files_in_folder 快速了解模块
    - 用 find_dangerous_patterns 定位潜在汇点（sink）
    - 用 search_in_folder 寻找数据来源（配置解析、用户输入、文件读取等）
    - 用 read_file 或 get_function_code 深入查看可疑代码
    - 用 analyze_data_flow 追踪从来源到汇点的数据流
   
3. 思考替代实现：
    - 同一功能的不同 API
    - 不同数据格式（JSON、YAML、XML、pickle）
    - 不同执行方式（subprocess、os、multiprocessing）

## 工具调用
你有一组可用的工具（functions）可以使用。当需要获取代码信息或报告漏洞时，系统会自动调用相应的函数。

重要提示：
- 当你发现漏洞时，必须使用 report_vulnerability 工具提供完整证据
- 当分析完成后，说明你的结论即可，不需要特殊格式
- 合理使用工具来深入分析代码，不要只基于推测
"""


def build_initial_user_message(software_profile: Any) -> str:
    software_dict = _to_dict(software_profile)
    project_info = {
        "project_name": software_dict.get("project_name"),
        "architecture": software_dict.get("architecture", {}),
        "module_hierarchy": software_dict.get("module_hierarchy", {}),
        "key_modules": [],
    }
    modules = software_dict.get("modules", [])
    for module in modules[:50]:
        project_info["key_modules"].append(
            {
                "name": module.get("name"),
                "path": module.get("path"),
                "description": module.get("description", "")[:200],
                "key_functions": [f.get("name") for f in module.get("functions", [])[:10]],
                "external_dependencies": module.get("external_dependencies", [])[:10],
            }
        )

    return f"""请根据项目架构信息和已知漏洞模式，自主寻找代码库中可能存在相似漏洞的模块。

## 项目架构信息
{json.dumps(project_info, indent=2, ensure_ascii=False)}

## 你的任务
1. 理解已知漏洞的模式：仔细分析已知漏洞的SOURCE、SINK、FLOW特征
2. 识别相似功能模块：基于项目架构，找出可能实现类似功能的模块
3. 深入分析代码：使用工具深入检查这些模块，寻找相似的漏洞模式
4. 报告发现：对每个发现的潜在漏洞使用 report_vulnerability 工具

## 分析策略建议
- 从架构信息中识别与已知漏洞功能相似的模块
- 寻找处理类似数据类型、执行类似操作的代码
- 注意不同API的等价实现（如 subprocess vs os.system）
- 关注数据流向：从用户输入/配置到危险操作的路径

现在开始你的自主分析。请先使用工具探索项目结构，然后系统地寻找潜在漏洞。"""


def build_intermediate_user_message() -> str:
    return """我请继续你的分析，使用可用的工具来深入挖掘代码中的潜在漏洞。注意：
        1. 不要遗漏任何可能的线索。
        2. 不要重复之前的分析路径。
        3. 确保寻找相似漏洞的全面性，扫描了所有可能相关的模块。
        4. 如果你认为已经完成分析，请明确说明并总结你的工作。"""
