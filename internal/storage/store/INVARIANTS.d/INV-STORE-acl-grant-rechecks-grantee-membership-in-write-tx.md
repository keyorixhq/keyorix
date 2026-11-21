- **INV-STORE-acl-grant-rechecks-grantee-membership-in-write-tx** `CreateOrUpdateSecretACL`
  commits an ACL row only for a grantee who is a member of the node's project AT COMMIT: after
  the upsert and the `lockLiveParent` re-read of the node, the same transaction takes
  `SELECT ... FOR SHARE` on the grantee's direct `user_roles` rows at that project
  (`lockDirectProjectGrants`, Postgres only) and re-asks the one membership question
  (`isProjectMemberOn`, the body of `IsProjectMember`: live direct or group grant at the
  project, global grants excluded), rolling back with `storage.ErrSecretACLGranteeNotMember`
  when the answer is no. Write first, then lock-and-check: `RemoveProjectMember` DELETEs those
  rows (`RemoveAllProjectRoleGrants`) before its CWE-284 cascade
  (`DeleteSecretACLsByUserAndProject`), so under READ COMMITTED the cascade either sees the
  committed grant and sweeps it, or the grant sees the committed removal and fails closed
  (the INV-STORE-21 argument with the membership rows as the parent). Why: #4533 (the
  second variant #2649 names): a removal committing between core's membership pre-check and
  the upsert left an ACL row for a removed member, listed to them through the ACL listing
  source and live again on re-add. Guard (pg-gated, two replicas):
  `TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres`,
  `TestCTAReview_GrantSecretACL_RemoveProjectMemberAfterUpsert_CrossReplicaPostgres`,
  `TestLivenessRace_GrantSecretACL_vs_RemoveProjectMember_Postgres`; single process:
  `TestLocalACL_RefusesNonMemberGrantee`, `TestLocalACL_AcceptsGroupOnlyMemberGrantee`,
  `internal/core` `TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow`.
  **Not covered**: a grantee who is a member only through a group (no row of theirs is
  locked; `RemoveProjectMember` refuses them as not a member, and a group-membership removal
  has no ACL cascade at all, a separate gap), and the `child_parent_liveness_registry_test.go`
  guard, which derives parents from soft-deletable models and does not know membership rows
  as a parent, so a second ACL insert site without this re-check would not be flagged by it.
