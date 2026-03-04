/**
 * @description Extract call graph edges from C# code.
 *
 * `getARuntimeTarget()` resolves virtual / interface dispatch to the
 * possible runtime implementations, giving a more complete call graph
 * than the static `getTarget()`.
 */
import csharp

from Call call, Callable caller, Callable callee
where
  call.getEnclosingCallable() = caller and
  callee = call.getARuntimeTarget()
select
  caller.getName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
