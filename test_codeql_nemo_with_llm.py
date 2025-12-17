#!/usr/bin/env python3
"""
测试 CodeQL 分析器
对 data/repos/NeMo/scripts 进行分析，查找所有的 os.system 调用
"""

import os
import sys
from pathlib import Path
from core.llm_client import HKULLMClient, DeepSeekClient, LLMConfig
# 添加项目根目录到 Python 路径

from core.codeql_native import CodeQLAnalyzer, CodeQLConfig
from core.config import PROJECT_ROOT, CODEQL_DB_PATH

def _validate_and_fix_codeql_query(query: str) -> str:
    """
    验证并修复CodeQL查询
    
    常见问题：
    1. 缺少必要的导入语句
    2. 使用了错误的包名
    3. 缺少metadata注释
    """
    lines = query.strip().split('\n')
    
    # 检查是否有import语句
    has_import_python = any('import python' in line for line in lines)
    has_metadata = any('@name' in line for line in lines)
    
    # 如果缺少基本导入，添加它们
    if not has_import_python:
        print("⚠️  添加缺失的导入语句")
        # 在第一个非注释行之前添加导入
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('/**') and not line.strip().startswith('*'):
                insert_idx = i
                break
        lines.insert(insert_idx, 'import python')
    
    # 如果缺少metadata，添加基本的
    if not has_metadata:
        print("⚠️  添加缺失的metadata")
        metadata = [
            '/**',
            ' * @name Find dangerous calls',
            ' * @description Finds potentially dangerous function calls',
            ' * @kind problem',
            ' * @problem.severity warning',
            ' * @id python/dangerous-call',
            ' */',
        ]
        lines = metadata + [''] + lines
    
    # 常见错误修复
    fixed_lines = []
    for line in lines:
        # 修复错误的导入语句
        if 'import semmle.python.dataflow' in line:
            print("⚠️  修复错误的导入语句: import semmle.python.dataflow -> import python")
            line = line.replace('import semmle.python.dataflow', 'import python')
        if 'import codeql.python' in line:
            print("⚠️  修复错误的导入语句: import codeql.python -> import python")
            line = line.replace('import codeql.python', 'import python')
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def _generate_codeql_query_with_retry(llm_client, intent: str, max_retries: int = 3) -> str:
    """
    使用LLM生成CodeQL查询，带重试和修复逻辑
    
    Args:
        llm_client: LLM客户端
        intent: 用户意图描述（如"查找os.system调用"）
        max_retries: 最大重试次数
    
    Returns:
        生成的CodeQL查询代码
    """
    # CodeQL Python查询模板和示例
    template = """/**
 * @name {name}
 * @description {description}
 * @kind problem
 * @problem.severity warning
 * @id python/{id}
 */

import python

from Call call
where
  {where_condition}
select call, "{message}"
"""
    
    # 构建详细的prompt
    prompt = f"""Generate a CodeQL query for Python based on this requirement:
"{intent}"

You MUST follow this structure EXACTLY:

{template}

Example for finding os.system() calls:
```ql
/**
 * @name Find os.system calls
 * @description Finds all calls to os.system()
 * @kind problem
 * @problem.severity warning
 * @id python/os-system-call
 */

import python

from Call call
where
  call.getFunc().(Attribute).getObject().(Name).getId() = "os" and
  call.getFunc().(Attribute).getAttr() = "system"
select call, "Call to os.system()"
```

CRITICAL RULES:
1. ONLY use "import python" - NO other imports
2. MUST include the metadata comment block (/** ... */)
3. Use Python AST classes: Call, Attribute, Name, Expr, etc.
4. Return ONLY the complete query code
5. No explanations, no markdown formatting except code fence

Generate the query now:"""
    
    for attempt in range(max_retries):
        print(f"  尝试生成查询 (第 {attempt + 1}/{max_retries} 次)...")
        
        try:
            plain_query_content = llm_client.complete(prompt)
            
            # 清理markdown
            if "```" in plain_query_content:
                import re
                code_blocks = re.findall(r'```(?:ql|codeql)?\s*\n(.*?)\n```', plain_query_content, re.DOTALL)
                if code_blocks:
                    query_content = code_blocks[0]
            else:
                query_content = plain_query_content
            # 验证和修复
            query_content = _validate_and_fix_codeql_query(query_content)
            
            # 基本验证：必须包含import和select
            if 'import python' in query_content and 'select' in query_content:
                print("  ✓ 查询生成成功")
                return query_content
            else:
                print(f"  ✗ 查询验证失败（缺少必要元素），重试...")
                if attempt < max_retries - 1:
                    prompt += f"\n\nPrevious:attempt: {plain_query_content}\n\nPrevious attempt failed. Please ensure the query includes 'import python' and 'select' statement."
        
        except Exception as e:
            print(f"  ✗ 生成失败: {e}")
            if attempt == max_retries - 1:
                raise
    
    # 如果所有重试都失败，返回一个基本的默认查询
    print("  ⚠️  使用默认查询")
    return template.format(
        name="Find function calls",
        description="Finds function calls matching the pattern",
        id="generic-call",
        where_condition="true",
        message="Function call found"
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(description='使用LLM生成CodeQL查询并分析代码')
    parser.add_argument('--source', default="/home/dongtian/vuln/data/repos/NeMo/scripts",
                       help='源代码路径')
    parser.add_argument('--force-rebuild-db', action='store_true',
                       help='强制重新创建数据库')
    parser.add_argument('--intent', default="查找所有 os.system() 调用",
                       help='分析意图描述')
    args = parser.parse_args()
    
    source_path = args.source
    
    print("="*60)
    print("CodeQL 分析器测试")
    print("="*60)
    print(f"源代码路径: {source_path}")
    print(f"分析意图: {args.intent}")
    if args.force_rebuild_db:
        print("⚠️  强制重建数据库模式")
    print()
    
    # 检查路径是否存在
    if not os.path.exists(source_path):
        print(f"❌ 错误: 路径不存在: {source_path}")
        return
    
    # 初始化分析器
    print("初始化 CodeQL 分析器...")
    config = CodeQLConfig(
        database_dir=str(CODEQL_DB_PATH),
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
    
    # 步骤1: 创建或复用数据库
    print("-"*60)
    print("步骤 1: 准备 CodeQL 数据库")
    print("-"*60)
    
    # 数据库路径
    # db_name = "nemo-scripts"
    db_name = '-'.join(args.source.split('/')[-2:])
    print(f"数据库名称: {db_name}")
    expected_db_path = os.path.join(config.database_dir, db_name)
    
    # 检查数据库是否已存在
    db_exists = os.path.exists(expected_db_path) and os.path.exists(
        os.path.join(expected_db_path, "codeql-database.yml")
    )
    
    if db_exists and not args.force_rebuild_db:
        print(f"✓ 发现已存在的数据库")
        print(f"  数据库路径: {expected_db_path}")
        
        # 检查源代码是否有更新
        db_yml = os.path.join(expected_db_path, "codeql-database.yml")
        db_mtime = os.path.getmtime(db_yml)
        
        # 检查源目录的最新修改时间
        source_mtime = 0
        for root, dirs, files in os.walk(source_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    source_mtime = max(source_mtime, os.path.getmtime(file_path))
        
        if source_mtime > db_mtime:
            print(f"  ⚠️  源代码已更新，重新创建数据库...")
            need_recreate = True
        else:
            print(f"  ✓ 数据库是最新的，直接使用")
            need_recreate = False
            db_path = expected_db_path
    else:
        if args.force_rebuild_db:
            print("强制重新创建数据库...")
        else:
            print("未找到已有数据库，创建新数据库...")
        need_recreate = True
    
    if need_recreate:
        success, db_path = analyzer.create_database(
            source_path=source_path,
            language="python",
            database_name=db_name,
            overwrite=db_exists  # 只在需要时覆盖
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
    
    # 使用固定的查询目录（而不是临时目录）
    query_dir = os.path.join(PROJECT_ROOT, "llm-vulvariant", ".codeql", "queries", "python")
    os.makedirs(query_dir, exist_ok=True)
    
    qlpack_file = os.path.join(query_dir, "qlpack.yml")
    
    # 检查是否需要初始化包
    need_setup = not os.path.exists(qlpack_file)
    
    if need_setup:
        print("首次运行，初始化 CodeQL 查询包...")
        
        # 创建 qlpack.yml
        qlpack_content = """name: llm-vuln-queries
version: 1.0.0
dependencies:
  codeql/python-all: "*"
"""
        with open(qlpack_file, 'w') as f:
            f.write(qlpack_content)
        
        # 安装依赖包
        print("  安装 CodeQL 包依赖...")
        import subprocess
        install_result = subprocess.run(
            ["codeql", "pack", "install", query_dir],
            capture_output=True,
            text=True,
            cwd=query_dir
        )
        if install_result.returncode != 0:
            print(f"  ⚠ 警告: 包安装可能有问题: {install_result.stderr}")
        else:
            print("  ✓ 依赖包安装成功")
    else:
        print("✓ 使用已配置的查询包目录")
    
    print(f"  查询目录: {query_dir}")
    print()
    
    # 初始化LLM客户端
    print("初始化 LLM 客户端...")
    llm_config = LLMConfig(provider='deepseek')
    llm_client = DeepSeekClient(llm_config)
    llm_client.max_tokens = 65536
    print("✓ LLM 客户端就绪")
    print()
    
    # 使用改进的生成方法，带验证和重试
    print("生成 CodeQL 查询...")
    query_content = _generate_codeql_query_with_retry(
        llm_client, 
        intent=args.intent,
        max_retries=3
    )
    
    print()
    print("最终查询代码:")
    print("-" * 60)
    print(query_content)
    print("-" * 60)
    print()
    
    # 关键修复：将查询保存到有 qlpack.yml 的包目录中
    query_file = os.path.join(query_dir, "find_system_calls.ql")
    print(f"保存查询到: {query_file}")
    with open(query_file, 'w') as f:
        f.write(query_content)
    print("✓ 查询文件已保存")
    print()
    
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
    
    except Exception as e:
        print(f"\n❌ 执行出错: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
