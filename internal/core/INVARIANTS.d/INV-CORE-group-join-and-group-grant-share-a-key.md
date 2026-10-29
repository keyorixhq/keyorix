- **INV-CORE-group-join-and-group-grant-share-a-key** A user joining a group
  (`AddUserToGroup`) and a role granted to that group (`AssignRoleToGroup`,
  `AssignGroupRoleWithExpiry`) can each complete one half of a separation-of-duties pair,
  and their named locks do not overlap (the join holds the user's key, the grant the group
  key and the keys of the members it listed, which cannot include a user still joining).
  Both write transactions therefore take `sodGrantLockKey("group", groupID)` with
  `LockNamedKeyInTx` as their first statement, and each re-reads the other side's state
  through `tx` after it: the join the group's grants, the grant the group's members
  (`sodGroupGrantFence` re-lists them, row-locks each, then checks). A grant fence that
  checks only the member snapshot taken before its transaction breaks this.
  Why: NAMEDLOCK-FENCE-1 (found by NAMEDLOCK-OVERLAP-2). On main a join and a grant, one
  inside the other's section, both committed and left the user holding a toxic pair.
  Guard: `TestNamedLockOverlap_SoD_GroupJoinVsGroupGrant_NoToxicPair` (fake lock backend,
  both orders); `TestNamedLockOverlap_SoDGroupJoinVsGroupGrant_ConcurrentWriteTransactions_Postgres`
  (pg-gated, both write transactions open at once). Not covered: SCIM group writes and SSO
  group reconcile add members without a separation-of-duties check, by design, and take no
  group key.
<!-- section: Atomicity / transactions -->
