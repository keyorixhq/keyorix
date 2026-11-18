- **INV-STORAGE-upgrade-authz-unchanged** After an upgrade `core.Authorize` gives the same answer the
  source release gave: the verdicts that release recorded on its own users, and on generated grants a
  model that agreed with that release's real `Authorize` before the snapshot was accepted (40 seeds,
  about 16k probes per release). Why: `rebuildRolePKIfNeeded`, `alterRoleAssignmentScope` and
  `alterRoleFlags` rewrite grant data, and a lost grant or a widened scope is silent until someone is
  denied or wrongly allowed. Guard: `internal/storage` `FuzzUpgradeFromOldSchema`,
  `FuzzUpgradeInterrupted`, red-proved by `TestUpgradeOracles_RedProof/invariant2_*`. **Not covered**:
  machine identities, MFA and SSO state; each exec checks a stride of the generated probes (at most
  about 150), while the source release's recorded verdicts are always all checked.
