import python

from CallNode call
where call.getCalleeName() = "load" 
and call.getImportedPrefix().getName() = "pickle"
select call, call.getLocation()