/**
 * @description Extract call graph edges from Python code.
 *
 * Uses the points-to analysis (`PythonFunctionObjectInternal`) to resolve
 * call targets.  This captures direct function calls, method calls,
 * class instantiation (__init__), and other callable objects that the
 * points-to analysis can resolve.
 *
 * NOTE: PythonFunctionObjectInternal is an internal API but is the only
 * reliable way to get call resolution in CodeQL for Python.  The public
 * Value/FunctionValue API does not expose a working pointsTo predicate
 * on ControlFlowNode as of CodeQL 2.x.
 */
import python
import semmle.python.objects.Callables

from PythonFunctionObjectInternal calleeObj, Function caller, Function callee, CallNode call
where
  call = calleeObj.getACall() and
  callee = calleeObj.getScope() and
  call.getScope() = caller
select
  caller.getQualifiedName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_line,
  callee.getQualifiedName() as callee_name,
  callee.getLocation().getFile().getRelativePath() as callee_file,
  callee.getLocation().getStartLine() as callee_line,
  call.getLocation().getStartLine() as call_site_line
