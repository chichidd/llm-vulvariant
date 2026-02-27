import python

from Call call, Name name
where
  name.getId() = "load" and
  call.getFunc() = name and
  call.getCaller().getFile().getAbsolutePath().matches("%yaml%")
select call, call.getLocation()