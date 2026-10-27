### Added
- **`GET /api/v1/groups/{id}/roles` returns each grant's `project_id` and `environment_id`.**
  The same role held globally, on a project and on one environment now comes back as
  distinguishable rows (`0`/`0` = global), so a client can show where a role is assigned.
  The group Manage Roles modal lists every grant with its scope and checks a role only when it
  is held at the scope selected above. Additive response fields; no request changes.
- **`keyorix rbac list-roles` shows where each role may be granted** (`[assignable: global|project|any]`).
- **The project Access Review tab shows `degraded` / `degraded_reasons`.** A degraded review warns
  that it may be incomplete and lists the reasons, and an empty degraded list no longer reads
  "No one has access".
- **Journey for invitation role scopes** (SQLite and Postgres): an install-wide role on a project
  invitation and a project-tier role on a global invitation are refused with 400 and create nothing.

### Changed
- **The access-review campaign warning in the CLI prints the server's `degraded_reasons`** instead of
  claiming that shares could not be read: a campaign can also be degraded by a grant on an
  environment with no project. It says so when the server gave no reason.
- **The user role editor (Admin page) no longer offers project-tier roles.** It replaces a user's
  roles at the global scope, where the server refuses them; they are shown read-only and left out of
  the submitted `role_ids`. Assign them from the project.
- **The Edit Role modal disables "Can be granted" for built-in roles** (the server refuses every
  update of one) and says why. The web's built-in list now matches the server's, so the `system_*`
  and `project_*` roles are marked Built-in too.
