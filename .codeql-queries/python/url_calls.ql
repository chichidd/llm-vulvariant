import python

from Call call, Name name
where
  name.getId() = "urlopen" or name.getId() = "urlretrieve" and
  call.getFunc() = name
select call, call.getLocation()