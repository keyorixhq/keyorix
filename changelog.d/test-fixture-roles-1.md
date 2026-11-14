### Testing
- **RBAC fixtures grant project roles at a project.** The `RBACTestHelper`-based tests in `internal/core` no longer grant the install-wide legacy roles (`admin`, `editor`, `viewer`, `auditor`) at a project, a state a real install cannot reach since #3605; they use `project_admin`, `project_developer` and `project_viewer`. Where a test asserts on a bundle difference (`project_developer` also deletes, `project_auditor` reads secrets) it uses the new `RBACTestHelper.CreateProjectRoleWithPermissions` to keep the legacy bundle as a project-tier role. Assertions are unchanged.

### Documentation
- **Closure row for #4025** (`ADMIN-RANK-CEILING-SNAPSHOT`) and a corrected `GetUserRoleScopes` doc comment: the admin-rank ceiling takes the target's role set from one read.
