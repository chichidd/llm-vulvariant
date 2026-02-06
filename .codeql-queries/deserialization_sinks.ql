import python

from DataFlow::PathNode source, DataFlow::PathNode sink
where exists(DataFlow::PathGraph g |
  g.hasFlowPath(source, sink) and
  // Sources: user input, file reading, network, etc.
  source.asExpr() = any(UserInput userInput).getAnInput() and
  // Sinks: dangerous deserialization functions
  sink.asExpr().(Call).getTarget().hasQualifiedName("yaml", "load") or
  sink.asExpr().(Call).getTarget().hasQualifiedName("pickle", "load") or
  sink.asExpr().(Call).getTarget().hasQualifiedName("marshal", "load") or
  sink.asExpr().(Call).getTarget().hasQualifiedName("jsonpickle", "decode") or
  sink.asExpr().(Call).getTarget().hasQualifiedName("subprocess", "run") or
  sink.asExpr().(Call).getTarget().hasQualifiedName("os", "system")
)
select sink, source, "Potential dangerous deserialization or command execution"