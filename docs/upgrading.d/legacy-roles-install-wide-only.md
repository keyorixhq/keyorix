## The legacy roles can no longer be granted on a project (#3605)

`admin`, `editor`, `viewer`, `auditor` and `super_admin` are now install-wide only (`assignable_scope`
`global`), so the ADR-021 two-tier model is the only one: `system_*` and these roles without a project,
`project_*` roles on a project. This replaces what §6z says about the legacy roles staying `any`.

**What stops being accepted.** A new grant of one of these roles with a project, for users, groups,
machine identities and invitations, on every API, gRPC and CLI path. The refusal is a 400 (gRPC
`InvalidArgument`) that names the role to use:

```
role viewer is install-wide and can no longer be granted on a project; grant project_viewer on the project instead
```

Re-running an automated grant (for example `keyorix machine grant-role ci --project default --role viewer`)
counts as a new grant and is refused even if the machine already holds it. Update such scripts.
Grants of these roles without a project are still accepted. Machine identities always hold their
grants on a project, so they can no longer be given a legacy role at all: use the project role.

| Legacy role at a project | Grant instead | Difference |
|---|---|---|
| `viewer` | `project_viewer` | `project_viewer` has no `audit.read`; use `project_auditor` to keep it |
| `editor` | `project_developer` | same permissions |
| `admin`, `super_admin` | `project_admin` | both bypass permission checks at their project; `project_admin` cannot manage the install |
| `auditor` | `project_auditor` | compare with your own `auditor` role, which is not seeded on new installs |

**Check two settings and requests.** Break-glass grants at a project, so a legacy
`break_glass.emergency_role` (`editor`, `viewer`, `auditor`) now refuses every activation: set it to a
contained project role such as `project_developer` before you need it. It is logged at startup and is a
deviation in the posture report. A pending access request that suggests a legacy role is refused
when approved; a single approver can grant a project role instead, and a request under M-of-N approval,
whose role is fixed, must be made again.

**What does not change.** Grants already held on a project are not removed, narrowed or converted,
and they keep authorizing exactly as before. Removing them, and setting a role set that keeps them, still
work. The first start of this version (or the first `keyorix-server admin` command, which migrates
too) sets the five roles to `global`, whichever older version you come from; it changes no grant,
adds no schema and leaves the schema epoch and its floor alone. That start logs one line, `storage: tightened
assignable_scope of N legacy role row(s) from any to global`, and only when it changed a row.

**How to find what to replace.** With the server stopped, as for every posture check:

```
keyorix-server admin validate --posture
```

The `WARN` section lists every existing per-project grant of a legacy role (user, group or machine
identity, role, project), the exact commands to replace it, pending access requests that suggest a legacy
role (request id, requester, project and the project role to approve it as) and pending invitations that
can no longer be accepted. A name that holds a newline or another control character is shown quoted, and
gets no copy-and-paste command. It does not count toward the exit code. A check that could not read the database reports
a deviation instead of an empty list. The same list appears as a `WARNING` at every server start
(the first 50 grants). Grant the project role first and remove the legacy grant second, so access is
never interrupted. A time-bound grant needs `--ttl` on the replacement to stay time-bound.

**Rolling back the binary.** The roles stay `global`, and an older binary reads the same column, so
it refuses these grants too, without naming the replacement.
