/**
 * @description Extract call graph edges from Ruby code.
 *
 * Ruby is highly dynamic so static resolution is limited.
 * We match by method name across the entire codebase (not restricted
 * to the same module), which allows cross-module calls to be captured.
 * Vendor and gem paths are excluded to reduce noise.
 */
import ruby

from Ast::MethodCall call, Ast::MethodBase caller, Ast::MethodBase callee
where
  call.getEnclosingCallable() = caller and
  call.getMethodName() = callee.getName() and
  // Exclude library / vendor paths
  not callee.getLocation().getFile().getRelativePath().matches("%vendor%") and
  not callee.getLocation().getFile().getRelativePath().matches("%/gems/%")
select
  caller.getName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
