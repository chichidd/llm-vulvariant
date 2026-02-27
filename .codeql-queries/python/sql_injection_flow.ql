import python

from DataFlow::PathNode source, sink
where
  exists(SQLInjectionConfiguration conf |
    conf.hasFlowPath(source, sink)
  )
select sink, source