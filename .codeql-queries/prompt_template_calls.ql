import python

from CallNode call
where call.getCalleeName() = "from_template"
  and call.getReceiver().getType().getName() = "PromptTemplate"
select call, call.getLocation().getFile().getAbsolutePath()