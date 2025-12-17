#!/usr/bin/env python3
"""
测试 CodeQL 分析器
对 data/repos/NeMo/scripts 进行分析，查找所有的 os.system 调用
"""

import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.codeql_native import CodeQLAnalyzer, CodeQLConfig


def main():
    # 源代码路径
    source_path = "/home/dongtian/vuln/data/repos/NeMo/scripts"
    
    print("="*60)
    print("CodeQL 分析器测试")
    print("="*60)
    print(f"源代码路径: {source_path}")
    print()
    
    # 检查路径是否存在
    if not os.path.exists(source_path):
        print(f"❌ 错误: 路径不存在: {source_path}")
        return
    
    # 初始化分析器
    print("初始化 CodeQL 分析器...")
    config = CodeQLConfig(
        database_dir="/tmp/codeql-test-dbs",
        timeout=1200
    )
    analyzer = CodeQLAnalyzer(config)
    
    # 检查 CodeQL 是否可用
    if not analyzer.is_available:
        print(f"❌ 错误: CodeQL 未安装或不在 PATH 中")
        print("请先安装 CodeQL CLI: https://github.com/github/codeql-cli-binaries")
        return
    
    print(f"✓ CodeQL 版本: {analyzer.version}")
    print()
    
    # 步骤1: 创建数据库
    print("-"*60)
    print("步骤 1: 创建 CodeQL 数据库")
    print("-"*60)
    
    success, db_path = analyzer.create_database(
        source_path=source_path,
        language="python",
        database_name="nemo-scripts",
        overwrite=True
    )
    
    if not success:
        print(f"❌ 创建数据库失败: {db_path}")
        return
    
    print(f"✓ 数据库创建成功")
    print(f"  数据库路径: {db_path}")
    print()
    
    # 步骤2: 创建查询查找 os.system 调用
    print("-"*60)
    print("步骤 2: 执行查询 - 查找 os.system 调用")
    print("-"*60)
    
    # 创建临时查询目录（需要包含 qlpack.yml）
    import tempfile
    temp_dir = tempfile.mkdtemp()
    query_dir = os.path.join(temp_dir, "queries")
    os.makedirs(query_dir, exist_ok=True)
    
    # 创建 qlpack.yml
    qlpack_content = """name: temp-queries
version: 1.0.0
dependencies:
  codeql/python-all: "*"
"""
    qlpack_file = os.path.join(query_dir, "qlpack.yml")
    with open(qlpack_file, 'w') as f:
        f.write(qlpack_content)
    
    # 安装依赖包
    print("安装 CodeQL 包依赖...")
    import subprocess
    install_result = subprocess.run(
        ["codeql", "pack", "install", query_dir],
        capture_output=True,
        text=True,
        cwd=query_dir
    )
    if install_result.returncode != 0:
        print(f"⚠ 警告: 包安装可能有问题: {install_result.stderr}")
    else:
        print("✓ 依赖包安装成功")
    print()
    
    # 创建查询文件
    query_content = """
/**
 * @name Find os.system calls
 * @description Finds all calls to os.system() which can be dangerous
 * @kind problem
 * @problem.severity warning
 * @id python/find-os-system
 */

import python

from Call call, Attribute attr
where 
  attr = call.getFunc() and
  attr.getName() = "system" and
  attr.getObject().(Name).getId() = "os"
select call, "Call to os.system() detected at " + call.getLocation().toString()
"""
    
    query_file = os.path.join(query_dir, "find_os_system.ql")
    with open(query_file, 'w') as f:
        f.write(query_content)
    
    try:
        # 执行查询
        success, result = analyzer.run_query(
            database_path=db_path,
            query=query_file,
            output_format="sarif-latest"
        )
        
        if not success:
            print(f"❌ 查询失败: {result}")
            return
        
        print("✓ 查询执行成功")
        print()
        
        # 步骤3: 解析和打印结果
        print("-"*60)
        print("步骤 3: 查询结果")
        print("-"*60)
        
        findings = analyzer._parse_sarif_results(result)
        
        if not findings:
            print("未找到 os.system() 调用")
        else:
            print(f"找到 {len(findings)} 个 os.system() 调用:\n")
            
            for i, finding in enumerate(findings, 1):
                print(f"{i}. {finding.file_path}:{finding.start_line}")
                print(f"   消息: {finding.message}")
                print(f"   严重程度: {finding.severity}")
                print(f"   位置: 第 {finding.start_line} 行, 第 {finding.start_column} 列")
                print()
        
        print("="*60)
        print(f"分析完成! 共发现 {len(findings)} 个结果")
        print("="*60)
        
    finally:
        # 清理临时查询目录
        import shutil
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
