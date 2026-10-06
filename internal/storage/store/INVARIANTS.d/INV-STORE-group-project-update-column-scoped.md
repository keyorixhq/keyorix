- **INV-STORE-group-project-update-column-scoped** `groups` and `projects` have no
  full-row writer. A group is edited only by `UpdateGroupFields` (the non-nil subset of
  name/name_folded/description, `WHERE id = ? AND deleted_at IS NULL`) and a project only
  by `UpdateProjectFields` (name/description, plus `require_mfa` **only** when its
  `requireMFA` pointer is non-nil, same soft-delete scoping); both report no-match rather
  than writing, and both callers fail closed on it and re-read the committed row. Why:
  #2697 — a bare GORM `Save` of a struct read earlier upserted with `deleted_at = NULL`,
  so a rename landing after `DeleteGroup`/`DeprovisionSCIMGroup` brought the group back
  **with its retained role grants and memberships live** (DeleteGroup keeps them on
  purpose, for `RestoreGroup`), a rename after `DeleteProject` resurrected the project row
  alone, and a rename that merely passed `requireMFA=nil` reverted an ADR-037 per-project
  MFA requirement an admin had just enabled — with no audit event, since
  `core.UpdateProject` audits only when its own argument changes the value it read. Note
  the rename paths (`core.UpdateGroup`, `ReplaceSCIMGroup`, `PatchSCIMGroup`,
  `core.UpdateProject`) hold none of the locks their delete counterparts do, so the
  write's own shape is the whole guarantee. Guard: `internal/core`
  `TestUpdateGroupAndProject_AreColumnScoped` (structural, all four entry points) and
  `TestCTAReview_UpdateGroup_vs_DeleteGroup_CrossReplicaPostgres`,
  `TestCTAReview_UpdateProject_vs_SetRequireMFA_CrossReplicaPostgres`,
  `TestCTAReview_UpdateProject_vs_DeleteProject_CrossReplicaPostgres` (pg-gated, one per
  consequence).
