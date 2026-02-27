/**
 * @name Command injection via os.system
 * @description Detects calls to os.system where the argument may be user-controlled.
 * @kind path-problem
 * @problem.severity error
 * @id python/command-injection
 */

import python
import semmle.python.security.injection.CommandInjection
import DataFlow::PathGraph

from Call call, Value sink, Value source
where call = sink.getACall() and
  sink instanceof OSSystemCall and
  source instanceof RemoteFlowSource and
  DataFlow::localFlow(source, sink)
select sink, "Potential command injection via os.system", source, "User input flows here."