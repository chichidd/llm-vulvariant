import python

from DataFlow::PathNode source, sink
where sink.asExpr().(Call).getCalleeName() = "system" and
  sink.asExpr().(Call).getReceiver().(NameExpr).getId() = "os" and
  exists(DataFlow::path(source, sink))
select sink, source, "os.system call with data flow from $@.", source, "user input"