/**
 * @description Extract call graph edges from Go code.
 *
 * Uses `CallExpr.getTarget()` to resolve the callee function.
 * This captures direct function calls, method calls on concrete types,
 * and goroutine/deferred calls when the target can be statically determined.
 *
 * Limitation: interface method dispatch where the concrete type is unknown
 * at compile time may not be resolved.
 */
import go

from CallExpr call, FuncDef caller, Function callee
where
  call.getEnclosingFunction() = caller and
  call.getTarget() = callee
select
  caller.getName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
