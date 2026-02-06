import python

from Call call, Expr arg
where call.getTarget().hasName("subprocess.run") and
  arg = call.getArgument(0) and
  arg instanceof StringLiteral
select call, "subprocess.run with string literal argument"