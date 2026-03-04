/**
 * @description Extract call graph edges from JavaScript/TypeScript code.
 *
 * `DataFlow::InvokeNode` covers function calls, method calls, `new` expressions,
 * and tagged template literals.  `getACallee()` uses data-flow analysis to
 * resolve call targets across assignments, closures, and dynamic dispatch.
 */
import javascript

from DataFlow::InvokeNode call, Function caller, Function callee
where
  caller = call.getEnclosingFunction() and
  callee = call.getACallee()
select
  caller.getName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.asExpr().getLocation().getStartLine() as call_site_line
