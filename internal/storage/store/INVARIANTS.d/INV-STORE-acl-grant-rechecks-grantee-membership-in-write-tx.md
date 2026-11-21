- **INV-STORE-acl-grant-rechecks-grantee-membership-in-write-tx** `CreateOrUpdateSecretACL`
  commits an ACL row only for a grantee who is a member of the node's project AT COMMIT. In
  one transaction it reads the node's project, takes `SELECT ... FOR SHARE` on the grantee's
  live direct `user_roles` rows at that project (`lockDirectProjectGrants`, Postgres only),
  upserts, re-reads the node with `lockLiveParent` (refusing if its project changed), and
  then re-asks the one membership question (`isProjectMemberOn`, the body of
  `IsProjectMember`: live direct or group grant at the project, global grants excluded),
  rolling back with `storage.ErrSecretACLGranteeNotMember` when the answer is no. Lock the
  membership rows, write, check: `RemoveProjectMember` DELETEs those rows
  (`RemoveAllProjectRoleGrants`) before it clears owned secrets and runs its CWE-284 cascade
  (`DeleteSecretACLsByUserAndProject`), so under READ COMMITTED either the removal waits for
  the grant to commit and its cascade sweeps it, or the grant waits for the removal to
  commit and the check refuses (the INV-STORE-21 argument with the membership rows as the
  parent). The lock comes BEFORE the write so both transactions take `user_roles` first:
  taken after the write, a re-grant (holding the existing ACL row) or a grant to the
  secret's owner (holding the node `FOR SHARE`) waited for `user_roles` while the removal
  held them and waited for that row, and Postgres aborted one side with 40P01, the removal
  included (REVIEW-4557-DEEP-1 MEDIUM-1). The check stays after the write: a check before
  it misses a removal that runs entirely between the two. Why: #4533 (the second variant
  #2649 names): a removal committing between core's membership pre-check and the upsert left
  an ACL row for a removed member, listed to them through the ACL listing source and live
  again on re-add. Guard: (pg-gated, two replicas)
  `TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres`,
  `TestCTAReview_GrantSecretACL_RemoveProjectMemberAfterUpsert_CrossReplicaPostgres`,
  `TestCTAReview_ReGrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres`,
  `TestCTAReview_GrantSecretACLToOwner_vs_RemoveProjectMember_CrossReplicaPostgres`,
  `TestLivenessRace_GrantSecretACL_vs_RemoveProjectMember_Postgres`,
  `TestLivenessRace_ReGrantSecretACL_vs_RemoveProjectMember_Postgres`; single process:
  `TestLocalACL_RefusesNonMemberGrantee`, `TestLocalACL_AcceptsGroupOnlyMemberGrantee`,
  `internal/core` `TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow`.
  **Not covered**: a grantee who is a member only through a group (no row of theirs is
  locked; `RemoveProjectMember` refuses them as not a member, and a group-membership removal
  has no ACL cascade at all, a separate gap), and the `child_parent_liveness_registry_test.go`
  guard, which derives parents from soft-deletable models and does not know membership rows
  as a parent, so a second ACL insert site without this re-check would not be flagged by it.
