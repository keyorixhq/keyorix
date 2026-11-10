### Changed

- **Breaking:** the legacy roles `admin`, `editor`, `viewer`, `auditor` and `super_admin` are install-wide only and can no longer be granted on a project, to users, groups, machine identities or through invitations (#3605, #3588). The refusal names the replacement (`project_admin`, `project_developer`, `project_viewer`, `project_auditor`). Grants already held on a project are not changed and keep working; `keyorix-server admin validate --posture` and the startup log list each one with the commands to replace it. See `docs/UPGRADING.md`.
