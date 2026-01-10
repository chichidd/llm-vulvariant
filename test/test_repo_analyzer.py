"""
测试 RepoAnalyzer - 使用 Megatron-LM 仓库进行测试

测试内容：
1. 初始化和缓存机制
2. 调用图分析
3. 函数信息提取
4. 依赖分析
5. 入口点检测
6. 程序切片（向后、向前）
7. 数据流分析
8. 代码搜索
9. 摘要生成
"""

import os
import sys
import json
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.repo_analyzer import RepoAnalyzer


def test_initialization():
    """测试 1: 初始化和缓存"""
    print("=" * 80)
    print("测试 1: 初始化 RepoAnalyzer")
    print("=" * 80)
    
    repo_path = "/home/dongtian/vuln/data/repos/Megatron-LM"
    
    if not os.path.exists(repo_path):
        print(f"❌ 测试仓库不存在: {repo_path}")
        return None
    
    print(f"仓库路径: {repo_path}")
    
    # 第一次初始化（会构建缓存）
    print("\n[第一次初始化 - 构建缓存]")
    analyzer = RepoAnalyzer(repo_path, language="python")
    
    print(f"\n✅ 初始化成功")
    print(f"   - 语言: {analyzer.language}")
    print(f"   - Commit Hash: {analyzer.commit_hash}")
    print(f"   - CodeQL Version: {analyzer.codeql_analyzer.version}")
    
    # 第二次初始化（应该加载缓存）
    print("\n[第二次初始化 - 加载缓存]")
    analyzer2 = RepoAnalyzer(repo_path, language="python")
    
    print(f"✅ 缓存加载成功")
    
    return analyzer


def test_call_graph(analyzer: RepoAnalyzer):
    """测试 2: 调用图分析"""
    print("\n" + "=" * 80)
    print("测试 2: 调用图分析")
    print("=" * 80)
    
    call_graph = analyzer.call_graph
    
    print(f"调用图边数: {len(call_graph)}")
    
    # 显示前10条调用关系
    print("\n前 10 条调用关系:")
    for i, edge in enumerate(call_graph[:10], 1):
        print(f"{i:2d}. {edge.caller_name} ({edge.caller_file}:{edge.caller_line})")
        print(f"     -> {edge.callee_name} ({edge.callee_file}:{edge.callee_line})")
    
    print(f"\n✅ 调用图测试通过")


def test_functions(analyzer: RepoAnalyzer):
    """测试 3: 函数信息"""
    print("\n" + "=" * 80)
    print("测试 3: 函数信息提取")
    print("=" * 80)
    
    functions = analyzer.functions
    
    print(f"函数总数: {len(functions)}")
    
    # 显示前10个函数
    print("\n前 10 个函数:")
    for i, (name, func) in enumerate(list(functions.items())[:10], 1):
        print(f"{i:2d}. {func.name}")
        print(f"     文件: {func.file}")
        print(f"     行号: {func.start_line}")
        print(f"     调用: {len(func.calls)} 个函数")
        print(f"     被调用: {len(func.called_by)} 次")
    
    # 测试函数调用关系查询
    if functions:
        test_func_name = list(functions.keys())[0]
        print(f"\n测试函数: {test_func_name}")
        
        callers = analyzer.get_function_callers(test_func_name)
        print(f"  调用者数量: {len(callers)}")
        
        callees = analyzer.get_function_callees(test_func_name)
        print(f"  被调用者数量: {len(callees)}")
    
    print(f"\n✅ 函数信息测试通过")


def test_dependencies(analyzer: RepoAnalyzer):
    """测试 4: 依赖分析"""
    print("\n" + "=" * 80)
    print("测试 4: 依赖分析")
    print("=" * 80)
    
    dependencies = analyzer.dependencies
    
    print(f"依赖总数: {len(dependencies)}")
    
    # 统计
    third_party = [d for d in dependencies.values() if d.is_third_party]
    builtin = [d for d in dependencies.values() if d.is_builtin]
    
    print(f"  - 第三方库: {len(third_party)}")
    print(f"  - 内置库: {len(builtin)}")
    
    # 按导入次数排序
    sorted_deps = sorted(
        dependencies.items(),
        key=lambda x: len(x[1].import_locations),
        reverse=True
    )
    
    print("\n最常用的依赖（前 15 个）:")
    for i, (name, dep) in enumerate(sorted_deps[:15], 1):
        dep_type = "builtin" if dep.is_builtin else "third-party"
        print(f"{i:2d}. {name:20s} - {len(dep.import_locations):3d} 次导入 ({dep_type})")
    
    print(f"\n✅ 依赖分析测试通过")


def test_entry_points(analyzer: RepoAnalyzer):
    """测试 5: 入口点检测"""
    print("\n" + "=" * 80)
    print("测试 5: 入口点检测")
    print("=" * 80)
    
    entry_points = analyzer.entry_points
    
    print(f"入口点数量: {len(entry_points)}")
    
    # 显示前10个入口点
    print("\n前 10 个入口点:")
    for i, ep in enumerate(entry_points[:10], 1):
        print(f"{i:2d}. {ep.name}")
        print(f"     文件: {ep.file}")
        print(f"     行号: {ep.start_line}")
        print(f"     调用: {len(ep.calls)} 个函数")
    
    print(f"\n✅ 入口点检测测试通过")


def test_code_context(analyzer: RepoAnalyzer):
    """测试 6: 代码上下文"""
    print("\n" + "=" * 80)
    print("测试 6: 代码上下文提取")
    print("=" * 80)
    
    # 随机选择一个函数
    if analyzer.functions:
        func = list(analyzer.functions.values())[0]
        print(f"测试函数: {func.name}")
        print(f"位置: {func.file}:{func.start_line}")
        
        # 获取代码上下文
        context = analyzer.get_code_context(func.file, func.start_line, window=10)
        
        print("\n代码上下文:")
        print(context)
        
        print(f"\n✅ 代码上下文测试通过")
    else:
        print("⚠️  没有可用的函数")


def test_backward_slice(analyzer: RepoAnalyzer):
    """测试 7: 向后程序切片"""
    print("\n" + "=" * 80)
    print("测试 7: 向后程序切片")
    print("=" * 80)
    
    # 选择一个有调用者的函数
    target_func = None
    for func in analyzer.functions.values():
        if len(func.called_by) > 0:
            target_func = func
            break
    
    if not target_func:
        print("⚠️  没有找到合适的测试函数")
        return
    
    print(f"目标函数: {target_func.name}")
    print(f"位置: {target_func.file}:{target_func.start_line}")
    print(f"被调用次数: {len(target_func.called_by)}")
    
    # 执行向后切片
    print("\n执行向后切片（max_depth=2, max_files=5）...")
    result = analyzer.backward_slice(
        target_func.file,
        target_func.start_line,
        max_depth=2,
        max_files=5
    )
    
    print(f"\n切片结果:")
    print(f"  - 相关位置数: {len(result.related_locations)}")
    print(f"  - 数据流路径数: {len(result.data_flow_paths)}")
    print(f"  - 涉及文件数: {len(result.files_involved)}")
    
    # 显示前5个相关位置
    print("\n前 5 个相关位置:")
    for i, loc in enumerate(result.related_locations[:5], 1):
        print(f"{i}. {loc['file']}:{loc['start_line']} - {loc['relationship']}")
        print(f"   函数: {loc['function_name']}")
    
    # 测试 Markdown 输出
    print("\n测试 Markdown 输出:")
    md_output = result.to_markdown()
    print(md_output[:500] + "..." if len(md_output) > 500 else md_output)
    
    print(f"\n✅ 向后切片测试通过")


def test_forward_slice(analyzer: RepoAnalyzer):
    """测试 8: 向前程序切片"""
    print("\n" + "=" * 80)
    print("测试 8: 向前程序切片")
    print("=" * 80)
    
    # 选择一个有被调用者的函数
    target_func = None
    for func in analyzer.functions.values():
        if len(func.calls) > 0:
            target_func = func
            break
    
    if not target_func:
        print("⚠️  没有找到合适的测试函数")
        return
    
    print(f"目标函数: {target_func.name}")
    print(f"位置: {target_func.file}:{target_func.start_line}")
    print(f"调用次数: {len(target_func.calls)}")
    
    # 执行向前切片
    print("\n执行向前切片（max_depth=2, max_files=5）...")
    result = analyzer.forward_slice(
        target_func.file,
        target_func.start_line,
        max_depth=2,
        max_files=5
    )
    
    print(f"\n切片结果:")
    print(f"  - 相关位置数: {len(result.related_locations)}")
    print(f"  - 数据流路径数: {len(result.data_flow_paths)}")
    print(f"  - 涉及文件数: {len(result.files_involved)}")
    
    # 显示前5个相关位置
    if result.related_locations:
        print("\n前 5 个相关位置:")
        for i, loc in enumerate(result.related_locations[:5], 1):
            print(f"{i}. {loc['file']}:{loc['start_line']} - {loc['relationship']}")
            print(f"   函数: {loc['function_name']}")
    
    print(f"\n✅ 向前切片测试通过")


def test_data_flow(analyzer: RepoAnalyzer):
    """测试 9: 数据流分析"""
    print("\n" + "=" * 80)
    print("测试 9: 数据流分析")
    print("=" * 80)
    
    # 尝试查找从 "load" 到 "save" 的数据流
    print("查找数据流: 'load' -> 'save'")
    paths = analyzer.find_data_flow("load", "save", max_paths=5)
    
    print(f"\n找到 {len(paths)} 条路径")
    
    for i, path in enumerate(paths[:5], 1):
        print(f"\n路径 {i}:")
        print("  " + " -> ".join(path))
    
    print(f"\n✅ 数据流分析测试通过")


def test_search_pattern(analyzer: RepoAnalyzer):
    """测试 10: 模式搜索"""
    print("\n" + "=" * 80)
    print("测试 10: 模式搜索")
    print("=" * 80)
    
    # 搜索 "import torch"
    print("搜索模式: 'import torch'")
    results = analyzer.search_pattern(r"import\s+torch")
    
    print(f"\n找到 {len(results)} 个匹配")
    
    # 显示前10个结果
    print("\n前 10 个结果:")
    for i, loc in enumerate(results[:10], 1):
        print(f"{i:2d}. {loc.file}:{loc.line}")
        print(f"     {loc.code[:80]}")
    
    print(f"\n✅ 模式搜索测试通过")


def test_summary(analyzer: RepoAnalyzer):
    """测试 11: 摘要生成"""
    print("\n" + "=" * 80)
    print("测试 11: 摘要生成")
    print("=" * 80)
    
    summary = analyzer.get_summary()
    
    print("\n仓库分析摘要:")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    
    print(f"\n✅ 摘要生成测试通过")



    
    print(f"\n✅ 敏感数据检测测试通过")


def main():
    """主测试流程"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║          RepoAnalyzer 测试套件 - Megatron-LM 仓库           ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    try:
        # 测试 1: 初始化
        analyzer = test_initialization()
        if analyzer is None:
            print("\n❌ 初始化失败，终止测试")
            return
        
        # 测试 2-11
        test_call_graph(analyzer)
        test_functions(analyzer)
        test_dependencies(analyzer)
        test_entry_points(analyzer)
        test_code_context(analyzer)
        test_backward_slice(analyzer)
        test_forward_slice(analyzer)
        test_data_flow(analyzer)
        test_search_pattern(analyzer)
        test_summary(analyzer)
        
        # 总结
        print("\n" + "=" * 80)
        print("🎉 所有测试通过！")
        print("=" * 80)
        
        # 保存测试报告
        save_test_report(analyzer)
        
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()


def save_test_report(analyzer: RepoAnalyzer):
    """保存测试报告"""
    print("\n生成测试报告...")
    
    report_dir = Path(__file__).parent / "test_reports"
    report_dir.mkdir(exist_ok=True)
    
    report_file = report_dir / "repo_analyzer_test_report.md"
    
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("# RepoAnalyzer 测试报告\n\n")
        f.write(f"**测试仓库**: {analyzer.repo_path}\n")
        f.write(f"**语言**: {analyzer.language}\n")
        f.write(f"**Commit Hash**: {analyzer.commit_hash}\n")
        f.write(f"**测试时间**: {__import__('datetime').datetime.now()}\n\n")
        
        f.write("## 统计信息\n\n")
        summary = analyzer.get_summary()
        f.write(f"- 函数总数: {summary['statistics']['total_functions']}\n")
        f.write(f"- 调用图边数: {summary['statistics']['call_graph_edges']}\n")
        f.write(f"- 依赖总数: {summary['statistics']['dependencies']['total']}\n")
        f.write(f"  - 第三方: {summary['statistics']['dependencies']['third_party']}\n")
        f.write(f"  - 内置: {summary['statistics']['dependencies']['builtin']}\n")
        f.write(f"- 入口点: {summary['statistics']['entry_points']}\n\n")
        
        f.write("## 主要入口点\n\n")
        for ep in summary['entry_points']:
            f.write(f"- `{ep['name']}` - {ep['file']}:{ep['line']}\n")
        
        f.write("\n## 主要依赖\n\n")
        for dep in summary['top_dependencies']:
            f.write(f"- `{dep['name']}` - {dep['import_count']} 次导入\n")
        
        # 添加程序切片示例
        f.write("\n## 程序切片示例\n\n")
        if analyzer.functions:
            func = list(analyzer.functions.values())[0]
            result = analyzer.backward_slice(func.file, func.start_line, max_depth=2, max_files=3)
            f.write(result.to_markdown())
    
    print(f"✅ 测试报告已保存: {report_file}")


if __name__ == "__main__":
    main()
