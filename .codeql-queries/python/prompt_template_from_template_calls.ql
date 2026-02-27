import python

from Call call, Expr arg
where
  call.getTarget().getName() = "from_template" and
  call.getTarget().getQualifier().getType().getName() = "PromptTemplate" and
  arg = call.getArgument(0)
select call, arg