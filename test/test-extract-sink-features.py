#!/usr/bin/env python3
"""
测试 VulnerabilityProfiler._extract_sink_features 功能

从 data/vuln.json 读取第一个漏洞条目并测试 Sink 特征提取
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
    print(f"  Call chain: {' -> '.join(first_entry['call_chain'])}")
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
    """
    profile_path = Path(__file__).parent / "repo-profiles" / repo_name / commit / "software_profile.json"
    
    if profile_path.exists():
        print(f"[INFO] Loading existing software profile from {profile_path}")
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return SoftwareProfile.from_dict(data)
    else:
        print(f"[WARN] No existing profile found, creating mock profile")
        return SoftwareProfile(
            name=repo_name,
            version=commit,
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
                        "functionality": "Utility functions for ASR inference, including offline and online inference modes. Contains subprocess calls for model evaluation.",
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


def test_extract_sink_features_with_real_llm():
    """使用真实的 LLM 进行测试"""
    print("\n" + "="*80)
    print("测试 2: 使用真实 LLM Client")
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
        llm_client = HKULLMClient(LLMConfig())
        
        # 6. 创建 VulnerabilityProfiler
        profiler = VulnerabilityProfiler(
            llm_client=llm_client,
            repo_profile=repo_profile,
            vuln_entry=vuln_entry
        )
        
        # 7. 执行测试
        print("[INFO] Extracting sink features with real LLM...")
        sink_feature = profiler._extract_sink_features()
        
        print("\n" + "="*80)
        print("✅ Sink Feature 提取成功（真实LLM）！")
        print("="*80)
        print(f"Description: {sink_feature.description}")
        print(f"Type: {sink_feature.type}")
        print(f"Location: {sink_feature.location}")
        print(f"Function: {sink_feature.function}")
        print(f"Parameter: {sink_feature.parameter}")
        print("="*80)
        
        return sink_feature
        
    except Exception as e:
        print(f"\n⚠️ 真实LLM测试跳过或失败: {e}")
        print("(这可能是因为没有配置API密钥，这是正常的)")
        import traceback
        traceback.print_exc()
        return None

def test_both_features():
    """同时测试 Source 和 Sink 特征提取"""
    print("\n" + "="*80)
    print("测试 3: 同时提取 Source 和 Sink 特征")
    print("="*80)
    
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
    try:
        llm_client = HKULLMClient(LLMConfig())
    except:
        print("[WARN] Failed to create real LLM client, using mock")
        mock_response_source = {
            "thinking": "User input source",
            "description": "Command-line argument input",
            "api": "argparse",
            "data_type": "user_input",
            "location": "tools/asr_evaluator/asr_evaluator.py:42",
            "trust_level": "untrusted"
        }
        llm_client = MockLLMClient(mock_response=json.dumps(mock_response_source))
    
    # 6. 创建 VulnerabilityProfiler
    profiler = VulnerabilityProfiler(
        llm_client=llm_client,
        repo_profile=repo_profile,
        vuln_entry=vuln_entry
    )
    
    # 7. 执行测试
    print("[INFO] Extracting both Source and Sink features...")
    try:
        source_feature = profiler._extract_source_features()
        print("\n[Source Feature]")
        print(f"  API: {source_feature.api}")
        print(f"  Type: {source_feature.data_type}")
        print(f"  Location: {source_feature.location}")
        
        sink_feature = profiler._extract_sink_features()
        print("\n[Sink Feature]")
        print(f"  Function: {sink_feature.function}")
        print(f"  Type: {sink_feature.type}")
        print(f"  Location: {sink_feature.location}")
        
        print("\n" + "="*80)
        print("✅ 完整的污点分析路径:")
        print(f"  Source: {source_feature.api} ({source_feature.location})")
        print(f"    ↓")
        print(f"  Call Chain: {len(call_chain)} steps")
        print(f"    ↓")
        print(f"  Sink: {sink_feature.function} ({sink_feature.location})")
        print("="*80)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主测试函数"""
    print("\n" + "🧪 " + "="*76)
    print("  测试 VulnerabilityProfiler._extract_sink_features()")
    print("="*80 + "\n")
    
    result2 = test_extract_sink_features_with_real_llm()
        
    
    
    print("\n" + "="*80)
    print("🎉 测试完成！")
    print(result2)
    print("="*80)

if __name__ == "__main__":
    main()
