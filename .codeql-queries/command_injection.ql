/**
 * @name Python command injection
 * @description Finds possible command injection vulnerabilities in Python code.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.0
 * @precision high
 */
import python
import semmle.python.security.CommandInjection
import DataFlow::PathGraph

from CommandInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Possible command injection from $@.", source.getNode(),
  "user input"