"""
测试 _compress_iteration_conversation 方法

使用现有的 conversation_history.json 文件测试对话压缩功能
"""

import json
import sys
from pathlib import Path

from src.config import LLMConfig
from src.llm import create_llm_client
from src.profiler import VulnerabilityProfile, SoftwareProfile
from src.scanner import AgenticVulnFinder


def test_compress_iteration_conversation():
    """测试对话压缩功能"""
    
    # 1. 读取测试数据
    conversation_file = Path("scan-results/llama_index_01c96948ecc322c6c3d97c2961213708ed5808a7_CVE-2025-1793_from_aa9db7aaea61/conversation_history.json")
    
    if not conversation_file.exists():
        print(f"[ERROR] Conversation file not found: {conversation_file}")
        return
    
    print(f"[INFO] Loading conversation history from {conversation_file}")
    with open(conversation_file, 'r', encoding='utf-8') as f:
        conversation_history = json.load(f)
    
    print(f"[INFO] Loaded {len(conversation_history)} messages")
    
    # 2. 创建必要的对象
    print("[INFO] Creating LLM client...")
    llm_config = LLMConfig(provider="lab")  # 使用 HKU provider
    llm_client = create_llm_client(llm_config)
    
    # 创建一个简单的 AgenticVulnFinder 实例用于调用压缩方法
    # 这些参数只是为了初始化，不会真正使用
    print("[INFO] Creating AgenticVulnFinder instance...")
    
    # 创建临时的 profile 对象
    vuln_profile = VulnerabilityProfile(
        cve_id="CVE-2025-1793",
        affected_version="aa9db7aaea61a4ef75872233a2e0dee4a0ff44b4",
        vuln_description="Test vulnerability",
        repo_name="llama_index"
    )
    
    software_profile = SoftwareProfile(
        name="llama_index",
        version="test"
    )
    
    repo_path = Path("../data/repos/llama_index")  # 实际不需要访问
    
    finder = AgenticVulnFinder(
        llm_client=llm_client,
        repo_path=repo_path,
        software_profile=software_profile,
        vulnerability_profile=vuln_profile,
        verbose=True
    )
    
    # 3. 提取要压缩的对话部分
    # 跳过 system message，从第一个 user message 开始
    print("\n[INFO] Extracting iteration history...")
    
    # 找到第一个 user message 的位置
    iteration_start_idx = 0
    for i, msg in enumerate(conversation_history):
        if isinstance(msg, dict) and msg.get('role') == 'user':
            iteration_start_idx = i
            break
    
    # 取一部分对话用于测试（比如前100条消息，或到第一个循环结束）
    # 这里我们可以测试不同的切片
    test_slices = [
        ("first_20", conversation_history[iteration_start_idx:iteration_start_idx+20]),
        ("first_50", conversation_history[iteration_start_idx:iteration_start_idx+50]),
        ("all", conversation_history[iteration_start_idx:]),
    ]
    
    output_dir = Path("test_compression_results")
    output_dir.mkdir(exist_ok=True)
    
    for slice_name, iteration_history in test_slices:
        print(f"\n{'='*80}")
        print(f"[INFO] Testing compression for slice: {slice_name}")
        print(f"[INFO] Number of messages: {len(iteration_history)}")
        print(f"{'='*80}\n")
        
        # 4. 调用压缩方法
        try:
            compressed_result = finder._compress_iteration_conversation(
                iteration=0,
                iteration_history=iteration_history
            )
            
            # 5. 保存压缩结果
            output_file = output_dir / f"compressed_{slice_name}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(compressed_result, f, indent=2, ensure_ascii=False)
            
            print(f"\n[SUCCESS] Compression completed!")
            print(f"[INFO] Result saved to: {output_file}")
            
            # 6. 打印压缩结果摘要
            print(f"\n{'='*80}")
            print("[COMPRESSION SUMMARY]")
            print(f"{'='*80}")
            print(f"Iteration: {compressed_result.get('iteration_number')}")
            print(f"Summary: {compressed_result.get('summary', 'N/A')}")
            print(f"Tool calls: {len(compressed_result.get('tool_calls', []))}")
            print(f"Vulnerabilities reported: {len(compressed_result.get('vulnerabilities_reported', []))}")
            print(f"Failed attempts: {len(compressed_result.get('failed_attempts', []))}")
            print(f"Key code snippets: {len(compressed_result.get('key_code_snippets', []))}")
            print(f"Modules checked: {len(compressed_result.get('modules_checked', []))}")
            print(f"Modules pending: {len(compressed_result.get('modules_pending', []))}")
            
            if compressed_result.get('tool_calls'):
                print(f"\n[TOOL CALLS SAMPLE]")
                for i, tool_call in enumerate(compressed_result['tool_calls'][:3], 1):
                    print(f"\n  {i}. {tool_call.get('tool', 'unknown')}")
                    print(f"     Parameters: {tool_call.get('parameters', {})}")
                    print(f"     Key findings: {len(tool_call.get('key_findings', []))} items")
            
            if compressed_result.get('reasoning'):
                print(f"\n[REASONING]")
                reasoning = compressed_result['reasoning']
                print(f"  Motivation: {reasoning.get('motivation', 'N/A')[:150]}...")
                print(f"  Conclusions: {len(reasoning.get('conclusions', []))} items")
            
            print(f"\n{'='*80}\n")
            
        except Exception as e:
            print(f"\n[ERROR] Compression failed for {slice_name}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n[INFO] All tests completed!")
    print(f"[INFO] Results saved to: {output_dir}/")


if __name__ == "__main__":
    test_compress_iteration_conversation()
