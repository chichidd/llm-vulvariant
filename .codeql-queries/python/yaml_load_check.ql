import python

from Call call, Name name
where
  name.getId() = "yaml" and
  call.getCalleeName() = "load" and
  call.getReceiver() = name
select call, "Potential unsafe yaml.load"