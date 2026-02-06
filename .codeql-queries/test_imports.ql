
/**
 * @name Test Query
 * @description Find all Python imports
 * @kind problem
 * @problem.severity warning
 * @id test/imports
 */
import python

from ImportExpr i
where i.getLocation().getFile().getRelativePath().matches("%autogen%")
select i, "Import statement found"
