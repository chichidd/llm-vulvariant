/**
 * @description Extract call graph edges from C/C++ code.
 *
 * Uses `Call` (not just `FunctionCall`) so that constructor calls,
 * destructor calls, and overloaded-operator calls are also captured.
 */
import cpp

from Call call, Function caller, Function callee
where
  call.getEnclosingFunction() = caller and
  call.getTarget() = callee
select
  caller.getQualifiedName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getQualifiedName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
