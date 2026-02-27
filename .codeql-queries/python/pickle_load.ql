import python

from Call call
where call.getTarget().hasName("load") and
  call.getTarget().getParentScope().getName() = "pickle"
select call