#!/usr/bin/env python3
"""
测试 VulnerabilityProfiler.generate_vulnerability_profile 功能

完整测试漏洞画像生成流程，包括：
- Source特征提取
- Sink特征提取
- Flow特征提取
- 漏洞综合描述
- 安全评估
"""

import json
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from core.vuln_profile import VulnerabilityProfiler, VulnEntry
from core.software_profile import SoftwareProfile
from core.llm_client import create_llm_client
from core.config import REPO_BASE_PATH, LLMConfig

def load_last_vuln_entry():
    """从 data/vuln.json 加载最后一个漏洞条目"""
    vuln_json_path = Path(__file__).parent.parent / "data" / "vuln.json"
    
    with open(vuln_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if not data:
        raise ValueError("No vulnerability data found in vuln.json")
    
    first_entry = data[-1]
    print(f"[INFO] Loaded vulnerability entry:")
    print(f"  Repo: {first_entry['repo_name']}")
    print(f"  Commit: {first_entry['commit'][:8]}...")
    print(f"  CVE ID: {first_entry.get('cve_id', 'N/A')}")
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
    """
    profile_path = Path(__file__).parent / "repo-profiles" / repo_name / commit / "software_profile.json"
    
    if profile_path.exists():
        print(f"[INFO] Loading existing software profile from {profile_path}")
        with open(profile_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return SoftwareProfile.from_dict(data)
    else:
        print(f"[WARN] No existing profile found, creating mock profile")
        return None

def display_vulnerability_profile(profile):
    """格式化显示漏洞画像"""
    print("\n" + "="*80)
    print("✅ 漏洞画像生成成功！")
    print("="*80)
    
    print(f"\n📦 基本信息:")
    print(f"   仓库: {profile.repo_name}")
    print(f"   版本: {profile.affected_version[:8] if profile.affected_version else 'N/A'}")
    print(f"   CVE ID: {profile.cve_id or 'N/A'}")
    print(f"   CWE ID: {profile.cwe_id or 'N/A'}")
    
    print(f"\n🔐 安全评估:")
    print(f"   严重程度: {profile.severity or 'N/A'}")
    print(f"   攻击向量: {profile.attack_vector or 'N/A'}")
    print(f"   用户交互: {profile.user_interaction or 'N/A'}")
    print(f"   所需权限: {profile.privileges_required or 'N/A'}")
    print(f"   利用复杂度: {profile.exploit_complexity or 'N/A'}")
    
    if profile.affected_modules:
        print(f"\n📂 受影响模块 ({len(profile.affected_modules)}):")
        for module in profile.affected_modules:
            print(f"   - {module}")
    
    if profile.source_features:
        print(f"\n🟢 Source 特征:")
        print(f"   描述: {profile.source_features.description}")
        print(f"   API: {profile.source_features.api}")
        print(f"   数据类型: {profile.source_features.data_type}")
        print(f"   位置: {profile.source_features.location}")
        print(f"   信任级别: {profile.source_features.trust_level}")
    
    if profile.sink_features:
        print(f"\n🔴 Sink 特征:")
        print(f"   描述: {profile.sink_features.description}")
        print(f"   类型: {profile.sink_features.type}")
        print(f"   函数: {profile.sink_features.function}")
        print(f"   参数: {profile.sink_features.parameter}")
        print(f"   位置: {profile.sink_features.location}")
    
    if profile.flow_features:
        print(f"\n🔵 Flow 特征:")
        print(f"   描述: {profile.flow_features.description}")
        
        if profile.flow_features.call_path:
            print(f"   调用路径 ({len(profile.flow_features.call_path)} 步):")
            for i, step in enumerate(profile.flow_features.call_path, 1):
                role_emoji = {"source": "🟢", "propagator": "🔵", "sink": "🔴"}.get(step.get("role", ""), "⚪")
                print(f"      {role_emoji} {i}. {step.get('function', 'N/A')} [{step.get('role', 'N/A')}]")
        
        if profile.flow_features.operations:
            print(f"   操作 ({len(profile.flow_features.operations)}):")
            for op in profile.flow_features.operations[:3]:
                print(f"      - {op}")
        
        if profile.flow_features.alias:
            print(f"   别名: {', '.join(profile.flow_features.alias[:5])}")
    
    if profile.vuln_description:
        print(f"\n📝 漏洞描述:")
        print(f"   {profile.vuln_description}")
    
    if profile.vuln_cause:
        print(f"\n🔍 漏洞原因:")
        print(f"   {profile.vuln_cause}")
    
    if profile.exploit_scenarios:
        print(f"\n⚔️  利用场景 ({len(profile.exploit_scenarios)}):")
        for i, scenario in enumerate(profile.exploit_scenarios, 1):
            print(f"   {i}. {scenario}")
    
    if profile.exploit_conditions:
        print(f"\n⚠️  利用条件 ({len(profile.exploit_conditions)}):")
        for i, condition in enumerate(profile.exploit_conditions, 1):
            print(f"   {i}. {condition}")
    
    print("\n" + "="*80)

def test_generate_vulnerability_profile():
    """测试完整的漏洞画像生成"""
    print("\n" + "="*80)
    print("测试: 生成完整漏洞画像 (VulnerabilityProfiler.generate_vulnerability_profile)")
    print("="*80)
    
    try:
        # 1. 加载漏洞数据
        vuln_data = load_last_vuln_entry()
        
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
        
        # 5. 创建 LLM Client
        print("\n[INFO] Initializing HKU LLM Client (DeepSeek)...")
        llm_config = LLMConfig()
        llm_client = create_llm_client(llm_config)
        
        # 6. 创建 VulnerabilityProfiler（启用结果保存）
        output_dir = Path(__file__).parent / "vuln-profiles"
        profiler = VulnerabilityProfiler(
            llm_client=llm_client,
            repo_profile=repo_profile,
            vuln_entry=vuln_entry,
            output_dir=str(output_dir)
        )
        
        # 7. 生成完整漏洞画像（启用对话保存）
        print("\n[INFO] Generating vulnerability profile...")
        print("[INFO] Results will be saved to:", output_dir)
        print("[INFO] This may take several minutes as the LLM analyzes:")
        print("       - Source features (data origin)")
        print("       - Sink features (dangerous operations)")
        print("       - Flow features (taint propagation)")
        print("       - Security assessment & exploitation analysis")
        print()
        
        repo_path = REPO_BASE_PATH / vuln_data['repo_name']
        profile = profiler.generate_vulnerability_profile(str(repo_path), save_results=True)
        
        # 8. 显示结果
        display_vulnerability_profile(profile)
        
        
        
        return profile
        
    except Exception as e:
        import traceback
        print(f"\n❌ 测试失败: {e}")
        print("\nTraceback:")
        traceback.print_exc()
        print("\n(这可能是因为没有配置API密钥、仓库文件不存在或网络问题)")
        return None

def main():
    """主测试函数"""
    print("\n" + "🧪 " + "="*76)
    print("  完整漏洞画像生成测试")
    print("  VulnerabilityProfiler.generate_vulnerability_profile()")
    print("="*80 + "\n")
    
    result = test_generate_vulnerability_profile()
    
    print("\n" + "="*80)
    print(result)


if __name__ == "__main__":
    main()
