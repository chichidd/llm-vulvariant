import python

from Expr expr, Call call, stringliteral lit
where
  call.getCalleeName() = "execute" and
  call.getArgument(0) = expr and
  expr instanceof Concatenation and
  expr.getAnOperand() = lit
select call, "Potential SQL injection via string concatenation"