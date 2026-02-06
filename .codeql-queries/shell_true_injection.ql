import python

from CallNode call, NameNode name
where name.getName() = "subprocess" and
  call.getCalleeName() in ["run", "Popen", "call", "check_output"] and
  call.getArgument("shell").getValue().toString() = "True"
select call, "Potential command injection with shell=True"