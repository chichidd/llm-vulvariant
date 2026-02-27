import python

from Call call, KeywordArgument kwarg
where
  call.getCalleeName().matches("subprocess%") and
  kwarg = call.getKeywordArgument("shell") and
  kwarg.getExpr().(Literal).getValue() = "true"
select call, "subprocess call with shell=true"
