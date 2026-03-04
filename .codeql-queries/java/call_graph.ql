/**
 * @description Extract call graph edges from Java code.
 *
 * `Call` covers MethodCall, ConstructorCall, SuperConstructorCall, etc.
 * `getCallee()` resolves to the declared target method.
 */
import java

from Call call, Callable caller, Callable callee
where
  call.getCaller() = caller and
  call.getCallee() = callee
select
  caller.getQualifiedName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getQualifiedName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
