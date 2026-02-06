import python

from Call call, Name name
where
  name = call.getTarget().getBaseName() and
  name.getId() in ["Popen", "run", "system", "popen"]
select call, call.getLocation().getFile(), call.getLocation().getStartLine()