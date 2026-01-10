#!/usr/bin/env python3
"""测试 CodeQL 配置是否正确加载"""

import logging
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

print("=" * 60)
print("Testing CodeQL Configuration")
print("=" * 60)

# Test 1: Direct load_codeql_config
print("\n[Test 1] load_codeql_config()")
from utils.codeql_native import load_codeql_config
config = load_codeql_config()
print(f"  queries_path: {config.get('queries_path')}")
print(f"  database_dir: {config.get('database_dir')}")

# Test 2: CodeQLAnalyzer without config
print("\n[Test 2] CodeQLAnalyzer() - no config passed")
from utils.codeql_native import CodeQLAnalyzer
analyzer1 = CodeQLAnalyzer()
print(f"  queries_path: {analyzer1.config.get('queries_path')}")

# Test 3: CodeQLAnalyzer with config (like repo_analyzer does)
print("\n[Test 3] CodeQLAnalyzer(config) - with modified config")
from config import _path_config
codeql_config = load_codeql_config()
codeql_config['database_dir'] = str(_path_config['codeql_db_path'])
analyzer2 = CodeQLAnalyzer(codeql_config)
print(f"  queries_path: {analyzer2.config.get('queries_path')}")

# Test 4: Check if call_graph.ql exists
print("\n[Test 4] Checking call_graph.ql file")
import os
call_graph_path = os.path.join(analyzer2.config['queries_path'], 'python', 'call_graph.ql')
print(f"  Path: {call_graph_path}")
print(f"  Exists: {os.path.exists(call_graph_path)}")

# Test 5: Try to run _build_call_graph
print("\n[Test 5] Testing _build_call_graph")
db_path = '/home/dongtian/vuln/codeql_dbs/llama_index-01c96948-python-db'
if os.path.exists(db_path):
    edges = analyzer2._build_call_graph(db_path, 'python')
    print(f"  Found {len(edges)} edges")
else:
    print(f"  Database not found: {db_path}")

print("\n" + "=" * 60)
print("✓ All tests completed")
print("=" * 60)
