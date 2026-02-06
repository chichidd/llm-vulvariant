import python

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  exists(DataFlow::Configuration config |
    config.hasFlowPath(source, sink)
  )
select sink, "Data flow to remote command execution", source, sink,
  "This query finds remote code execution via command injection."
