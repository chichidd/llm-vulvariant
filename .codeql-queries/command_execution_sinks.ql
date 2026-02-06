import python

from CallNode call, DataFlow::Node source, DataFlow::Node sink
where
  call.getTarget().hasQualifiedName("subprocess", "run") or
  call.getTarget().hasQualifiedName("subprocess", "call") or
  call.getTarget().hasQualifiedName("subprocess", "check_call") or
  call.getTarget().hasQualifiedName("subprocess", "check_output") or
  call.getTarget().hasQualifiedName("subprocess", "Popen") or
  call.getTarget().hasQualifiedName("os", "system") or
  call.getTarget().hasQualifiedName("os", "popen")
select call, "Potential command execution"