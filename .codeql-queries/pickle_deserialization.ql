/**
 * @name Dangerous deserialization: pickle.load
 * @description Finds calls to pickle.load or pickle.loads which can lead to remote code execution.
 * @kind path-problem
 * @problem.severity error
 * @id python/dangerous-deserialization
 */

import python
import DataFlow::PathGraph

class PickleLoadCall extends DataFlow::Node {
  PickleLoadCall() {
    exists(Call call |
      call.getTarget().hasQualifiedName("pickle", "load") or
      call.getTarget().hasQualifiedName("pickle", "loads") |
      this = call
    )
  }
}

from PickleLoadCall sink
select sink, "Dangerous deserialization with pickle.load can lead to remote code execution."