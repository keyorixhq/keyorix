### Testing

- Real-backend web smoke `group-role-scope.spec.ts` selects the Manage Roles "Project" picker with an exact label match. The substring match also hit every `project_*` role checkbox (strict-mode violation, 7 elements), which kept `web-e2e-real-smoke-shard (2/2)` red on main.
