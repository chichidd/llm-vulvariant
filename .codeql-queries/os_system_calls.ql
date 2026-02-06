import python

from Call call
where call.getAttrName() = "system" and
  call.getReceiver().(Name).getId() = "os"
select call