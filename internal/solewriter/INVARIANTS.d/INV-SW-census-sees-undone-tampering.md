- **INV-SW-census-sees-undone-tampering** The census fingerprint changes on any change to a fence
  trigger or function, or to the function any other trigger on a covered table executes (the store's
  migration triggers' included), even one undone before the next poll (toggled off and back on in one
  transaction or across two, dropped and re-created identically, replaced with the same body or
  settings), on any inheritance or partition link with a fenced (or the holder/epoch) table on either
  side, on any change to such a table's columns (ALTER COLUMN TYPE ... USING, RENAME COLUMN), and on
  any rule or row-level security policy on a covered table (created, altered, disabled or dropped, by
  row version) or its row-level security switch (by value);
  InstallFence refuses to start when such a link already exists. It does so by including the
  pg_trigger, pg_proc, pg_attribute, pg_rewrite and pg_policy rows' `xmin`, `relrowsecurity`/`relforcerowsecurity`, the functions' `proconfig` and the `pg_inherits`
  links. Routine maintenance (VACUUM FREEZE of the catalogs, ANALYZE, CREATE INDEX, VACUUM FULL and
  CLUSTER of a fenced table; VACUUM FULL of the catalogs checked by hand) does not change it. Superuser access below SQL is the stated residual, reported by the posture check. Why:
  REVIEW-SINGLE-WRITER-1 F1, REVIEW-SINGLE-WRITER-2 N2, REVIEW-SOLEWRITER-1 F1. Guard: `TestPoll_FenceTamperingLeavesAuthoritativeForGood` (the
  undone-tampering cases red without `xmin`, the child case red without `pg_inherits`, the rule,
  policy and row-level-security cases red without `pg_rewrite`/`pg_policy`/`relrowsecurity`),
  `TestFence_FencedTableAsAChild` (the "becomes a child/partition" cases red without both the
  `inhrelid` direction and `pg_attribute`, the column cases red without `pg_attribute`),
  `TestInstallFence_RefusesAFencedTableWithAChild`, `TestInstallFence_RefusesAFencedTableThatIsAChild`, `TestPoll_CatalogMaintenanceKeepsAuthoritative`,
  `TestInspectFence_ReportsARoleThatReachesBelowSQL`,
  `TestPoll_MigrationTriggerFunctionReplacedLeavesAuthoritative` (every migration trigger's
  function re-created identically; red without the trigger-function part of the fingerprint).
  Sequences are deliberately not in the census (REVIEW-SOLEWRITER-1 census question, decided by
  STARTUP-GUARD-TAILS-1): `setval`/`ALTER SEQUENCE` on a fenced table's id sequence changes no
  row, so no cache derived from a fenced row can go stale through it. A rewound sequence only
  makes a later INSERT reuse an id, and every INSERT, UPDATE and DELETE row and every TRUNCATE of a
  fenced table runs the guard trigger whatever id it carries (`triggerSpecs`): a foreign writer's
  insert is refused, and the holder's own insert bumps the epoch, which flushes every
  authoritative cache, so an entry for the id's previous row cannot answer for the new one. An
  insert the sequence would refuse (an id still in use) fails on the primary key, which is a
  denial of service the role owning the sequence can cause anyway. The fence's own holder and
  epoch tables have no sequence (`id = 1`). Guarded by the fence's own row-trigger coverage
  (`TestFence_RefusesEveryForeignWriteWhileHolderLives`, `TestTriggerSpecs_EveryDMLGuardIsPerRow`)
  and INV-SW-in-process-writes-seen (`TestTracker_EveryEpochMoveIsAWriteTheTrackerSaw`); revisit if a cache ever keys on an id across a delete without
  the epoch (for example a negative-lookup cache that survives epoch bumps).
