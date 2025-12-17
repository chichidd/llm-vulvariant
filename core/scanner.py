"""

# 思路:
漏洞profile -> 生成codeql 查询 (根据repo profile, 指定模块, 指定repo类型, )

or

CodeQL扫描（增全规则比如eval）-》基于repo和vuln profile过滤FP





# 方法

基于A.2, A.3 寻找类似模块
基于B.4找可能存在的脆弱的模块

# 实现



"""


from core.codeql_native import CodeQLAnalyzer

