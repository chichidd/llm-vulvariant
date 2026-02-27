import python

from StringLiteral sl, Call call
where
  call.getCalleeName().regexpMatch("execute|exec_immediate|perform_raw_text_sql") and
  sl.getParent() = call.getAnArgument()
select call, sl