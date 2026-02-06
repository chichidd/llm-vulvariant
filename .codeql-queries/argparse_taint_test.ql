import python
import semmle.python.security.dataflow.TaintTracking
import semmle.python.security.dataflow.Argparse

class ArgparseSource extends DataFlow::Node {
  ArgparseSource() {
    exists(DataFlow::ArgparseNode arg | arg.asSource() = this)
  }
}

class DangerousSink extends DataFlow::Node {
  DangerousSink() {
    exists(DataFlow::DangerousSink sink | sink.asSink() = this)
  }
}

from ArgparseSource source, DangerousSink sink
where DataFlow::localFlow(source, sink)
select source, sink