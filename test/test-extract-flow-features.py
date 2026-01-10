#!/usr/bin/env python3
"""
测试 VulnerabilityProfiler._extract_flow_features 功能

从 data/vuln.json 读取第一个漏洞条目并测试 Flow 特征提取
"""

import json
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from src.profiler import VulnerabilityProfiler, VulnEntry
from src.profiler import SoftwareProfile
from src.llm import create_llm_client, LLMConfig
from src.config import _path_config 
from src.utils.vuln_utils import read_vuln_data

def load_first_vuln_entry():
    """从 data/vuln.json 加载第一个漏洞条目"""
    vuln_json_path = Path(__file__).parent.parent / "data" / "vuln.json"
    
    with open(vuln_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if not data:
        raise ValueError("No vulnerability data found in vuln.json")
    
    # 取第一个条目
    first_entry = data[0]
    print(f"[INFO] Loaded vulnerability entry:")
    print(f"  Repo: {first_entry['repo_name']}")
    print(f"  Commit: {first_entry['commit'][:8]}...")
    print(f"  CVE ID: {first_entry.get('cve_id', 'N/A')}")
    print(f"  Call chain length: {len(first_entry['call_chain'])}")
    print(f"  Call chain: {' -> '.join([c.split('#')[-1] if '#' in c else c for c in first_entry['call_chain']])}")
    print()
    
    return first_entry

def parse_call_chain(call_chain_str_list):
    """
    将字符串格式的调用链转换为字典格式
    
    Args:
        call_chain_str_list: 字符串列表，如 ["file.py#function", "sink"]
        
    Returns:
        字典列表，如 [{"file_path": "file.py", "function_name": "function"}, ...]
    """
    result = []
    for call in call_chain_str_list:
        if '#' in call:
            file_path, function_name = call.split('#', 1)
            result.append({
                "file_path": file_path,
                "function_name": function_name
            })
        else:
            # 直接的 sink 调用
            result.append({
                "vuln_sink": call
            })
    return result

def load_or_create_mock_repo_profile(repo_name, commit):
    """
    加载或创建mock的软件画像
    
    如果存在真实的软件画像文件则加载，否则创建一个简化的mock版本
    """
    # 尝试加载真实的软件画像
    profile_path = Path(__file__).parent / "repo-profiles" / repo_name / commit / "software_profile.json"
    
    if profile_path.exists():
        print(f"[INFO] Loading existing software profile from {profile_path}")
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return SoftwareProfile.from_dict(data)
    else:
        print(f"[WARN] No existing profile found, creating mock profile")
        # 创建简化的mock软件画像
        return SoftwareProfile(
            name=repo_name,
            version="mock_version",
            description="Mock software profile for testing",
            target_application=["Machine Learning", "Speech Recognition"],
            target_user=["Researchers", "Developers"],
            repo_info={
                "files": [
                    "tools/asr_evaluator/asr_evaluator.py",
                    "tools/asr_evaluator/utils.py"
                ],
                "file_summaries": {
                    "tools/asr_evaluator/asr_evaluator.py": {
                        "functionality": "Main entry point for ASR evaluation tool. Handles command-line arguments and orchestrates the evaluation process.",
                        "key_functions": ["main", "parse_args"]
                    },
                    "tools/asr_evaluator/utils.py": {
                        "functionality": "Utility functions for ASR inference, including offline and online inference modes.",
                        "key_functions": ["run_asr_inference", "run_offline_inference"]
                    }
                }
            },
            modules=[
                {
                    "name": "ASR Evaluation Tools",
                    "category": "tools_module",
                    "description": "Tools for evaluating automatic speech recognition models",
                    "files": [
                        "tools/asr_evaluator/asr_evaluator.py",
                        "tools/asr_evaluator/utils.py"
                    ]
                }
            ]
        )


def test_extract_flow_features_with_real_llm():
    """使用真实的 LLM 进行测试（需要API配置）"""
    print("\n" + "="*80)
    print("测试: 使用真实 LLM Client (HKU LLM via DeepSeek)")
    print("="*80)
    
    try:
        # 1. 加载漏洞数据
        vuln_data = load_first_vuln_entry()
        
        # 2. 解析调用链
        call_chain = parse_call_chain(vuln_data['call_chain'])
        
        # 3. 创建 VulnEntry 对象
        vuln_entry = VulnEntry(
            repo_name=vuln_data['repo_name'],
            commit=vuln_data['commit'],
            call_chain=call_chain,
            payload=vuln_data.get('payload'),
            cve_id=vuln_data.get('cve_id')
        )
        
        # 4. 加载或创建软件画像
        repo_profile = load_or_create_mock_repo_profile(vuln_data['repo_name'], vuln_data['commit'])
        
        # 5. 创建真实的 LLM Client
        print("\n[INFO] Initializing HKU LLM Client (DeepSeek)...")
        llm_client = HKULLMClient(LLMConfig())
        
        # 6. 创建 VulnerabilityProfiler
        profiler = VulnerabilityProfiler(
            llm_client=llm_client,
            repo_profile=repo_profile,
            vuln_entry=vuln_entry
        )
        
        # 7. 执行测试
        print("\n[INFO] Extracting flow features with real LLM...")
        print("[INFO] This may take a moment as the LLM analyzes the taint propagation path...")
        print()
        
        flow_feature = profiler._extract_flow_features()
        
        print("\n" + "="*80)
        print("✅ Flow Feature 提取成功（真实LLM）！")
        print("="*80)
        
        print(f"\n📝 Description:")
        print(f"   {flow_feature.description}")
        
        print(f"\n🔗 Call Path ({len(flow_feature.call_path)} steps):")
        for i, step in enumerate(flow_feature.call_path, 1):
            role_emoji = {"source": "🟢", "propagator": "🔵", "sink": "🔴"}.get(step.get("role", ""), "⚪")
            print(f"   {role_emoji} Step {i}: {step.get('file', 'N/A')}#{step.get('function', 'N/A')} "
                  f"[{step.get('role', 'N/A')}] @ Line {step.get('line', 'N/A')}")
        
        if flow_feature.path_conditions:
            print(f"\n🔀 Path Conditions ({len(flow_feature.path_conditions)}):")
            for cond in flow_feature.path_conditions:
                print(f"   - {cond}")
        else:
            print(f"\n🔀 Path Conditions: None")
        
        if flow_feature.path_dependency:
            print(f"\n📦 Dependencies ({len(flow_feature.path_dependency)}):")
            for dep in flow_feature.path_dependency:
                print(f"   - {dep}")
        else:
            print(f"\n📦 Dependencies: None")
        
        if flow_feature.operations:
            print(f"\n⚙️  Operations ({len(flow_feature.operations)}):")
            for op in flow_feature.operations:
                print(f"   - {op}")
        else:
            print(f"\n⚙️  Operations: None")
        
        if flow_feature.alias:
            print(f"\n🏷️  Aliases ({len(flow_feature.alias)}):")
            print(f"   {', '.join(flow_feature.alias)}")
        else:
            print(f"\n🏷️  Aliases: None")
        
        if flow_feature.transformations:
            print(f"\n🔄 Transformations ({len(flow_feature.transformations)}):")
            for trans in flow_feature.transformations:
                print(f"   - {trans}")
        else:
            print(f"\n🔄 Transformations: None")
        
        if flow_feature.sanitizers and flow_feature.sanitizers != ["无"]:
            print(f"\n🛡️  Sanitizers ({len(flow_feature.sanitizers)}):")
            for san in flow_feature.sanitizers:
                print(f"   - {san}")
        else:
            print(f"\n🛡️  Sanitizers: None")
        
        if flow_feature.validators and flow_feature.validators != ["无"]:
            print(f"\n✅ Validators ({len(flow_feature.validators)}):")
            for val in flow_feature.validators:
                print(f"   - {val}")
        else:
            print(f"\n✅ Validators: None")
        
        print("\n" + "="*80)
        
        # 保存完整结果到JSON文件
        output_file = "test-flow-feature-result.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(flow_feature.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"💾 Full result saved to: {output_file}")
        print("="*80)
        
        return flow_feature
        
    except Exception as e:
        import traceback
        print(f"\n❌ 测试失败: {e}")
        print("\nTraceback:")
        traceback.print_exc()
        print("\n(这可能是因为没有配置API密钥或仓库文件不存在)")
        return None

def main():
    """主测试函数"""
    print("\n" + "🧪 " + "="*76)
    print("  测试 VulnerabilityProfiler._extract_flow_features()")
    print("="*80 + "\n")
    
    result = test_extract_flow_features_with_real_llm()
    
    print("\n" + "="*80)
    if result:
        print("🎉 测试完成！Flow Feature 提取成功")
        print(result.to_dict())
    else:
        print("⚠️  测试未能完成")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
