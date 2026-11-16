### Security
- **A user can no longer mint a machine token that carries permissions they lack, and a restricted
  PAT can no longer mint one at all.** `IssueMachineToken` for a user caller required only
  `roles.assign` at the project, so a user with that one permission could issue a token for a
  peer machine whose roles bundle other permissions (for example secrets read and write) and
  act as that peer. A PAT restricted by project, environment, permission or CIDR allowlist
  that still allowed `roles.assign` could mint an unrestricted, non-expiring `kx_machine_`
  token and use it from anywhere. The user path now requires the caller to hold every
  permission the target holds, at each scope the target holds it (the rule machine callers
  already follow), and refuses restricted PATs. Both need a caller that already holds
  `roles.assign` at the project. Found by review of keyorixhq/keyorix#3993 (fuzz-corpus#91).
