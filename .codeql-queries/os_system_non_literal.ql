import python

from CallNode call, Expr arg
where
  call.getTarget().getName() = "system" and
  call.getTarget().getModule().getName() = "os" and
  arg = call.getArg(0) and
  not arg instanceof StringLiteral
select call, arg