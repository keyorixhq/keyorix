/**
 * @name Path-based chmod/chown after a symlink check (TOCTOU)
 * @description Calling os.Chmod/os.Chown with a path string, after that same path was
 *              already checked with os.Lstat (typically to reject a symlink), leaves a
 *              window between the check and the permission change: the path can be
 *              swapped for a symlink to an attacker-chosen target in that window, and
 *              the follow-on os.Chmod/os.Chown call follows a final-component symlink.
 *              Opening the file first with O_NOFOLLOW and calling Chmod/Chown on the
 *              resulting *os.File (an fd-based operation) closes the race, since a
 *              file descriptor cannot be retargeted after open.
 * @kind problem
 * @problem.severity warning
 * @id go/keyorix-path-based-permission-change-toctou
 * @tags security
 *       external/cwe/cwe-367
 */

import go

/** Holds if `call` is a path-based (not fd-based) permission-changing call. */
predicate isPathBasedPermissionCall(DataFlow::CallNode call) {
  call.getTarget().hasQualifiedName("os", ["Chmod", "Chown", "Lchown"])
}

/** Holds if `call` is an os.Lstat call -- the usual way this codebase pre-checks a path is not a symlink before acting on it. */
predicate isLstatCall(DataFlow::CallNode call) { call.getTarget().hasQualifiedName("os", "Lstat") }

from DataFlow::CallNode lstat, DataFlow::CallNode permCall
where
  isLstatCall(lstat) and
  isPathBasedPermissionCall(permCall) and
  // Same enclosing function, and the same path expression (by source text) is passed
  // to both -- a same-function, same-path-variable Lstat-then-Chmod/Chown pattern is
  // exactly the shape of "we thought we checked this," not a coincidental unrelated
  // pair of calls.
  lstat.getEnclosingCallable() = permCall.getEnclosingCallable() and
  lstat.getArgument(0).asExpr().toString() = permCall.getArgument(0).asExpr().toString() and
  lstat.asExpr().getLocation().getStartLine() < permCall.asExpr().getLocation().getStartLine()
select permCall,
  "This path-based permission change follows an os.Lstat check on the same path in $@, leaving a TOCTOU window -- open with O_NOFOLLOW and use the fd-based Chmod/Chown method instead.",
  lstat, "this Lstat call"
