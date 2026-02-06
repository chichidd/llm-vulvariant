import python

from DataFlow::PathNode source, DataFlow::PathNode sink
where
  exists(DataFlow::Configuration cfg |
    cfg.hasFlowPath(source, sink)
  )
select sink, "Data flow from $@ to $@", source, source.toString(), sink, sink.toString()