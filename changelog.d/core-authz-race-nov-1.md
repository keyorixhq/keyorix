### Security
- **A per-secret ACL grant can no longer survive the grantee's removal from the project when
  the two race across replicas (#4533).** `GrantSecretACL` checked membership before writing the
  grant; a `RemoveProjectMember` committing in between had already run its ACL clean-up without
  seeing the grant, which then committed for a removed member: it still listed the secret's
  metadata to them and became live again when an admin re-added them. The storage upsert now
  locks the grantee's live direct project grants `FOR SHARE` on PostgreSQL before the write
  (the same lock order as the removal, so a concurrent re-grant cannot deadlock and abort the
  removal), re-checks membership after the write in the same transaction, and rolls the grant
  back with the same "not a member" refusal a serial remove-then-grant gets. No client-visible change for a
  member grantee. Guards: `TestCTAReview_GrantSecretACL_vs_RemoveProjectMember_CrossReplicaPostgres`
  and the race loop (PostgreSQL), `TestGrantSecretACL_MembershipRemovedBeforeUpsert_RefusedWithoutARow`
  (SQLite, every CI run).
