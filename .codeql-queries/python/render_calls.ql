import python

from CallNode call
where call.getFuncName() = "render"
select call, call.getLocation()