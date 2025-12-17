/**
 * @name os.system command injection detection
 * @description Detects calls to os.system that may be vulnerable to command injection
 * @kind problem
 * @id custom/os-system-command-injection
 * @problem.severity warning
 */

import python

from Call call, Attribute attr, Name base
where
  call.getFunc() = attr and
  attr.getObject() = base and
  base.getId() = "os" and
  attr.getAttr() = "system"
select call, "Found os.system call that may be vulnerable to command injection"