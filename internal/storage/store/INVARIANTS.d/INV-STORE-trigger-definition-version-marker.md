- **INV-STORE-trigger-definition-version-marker** Each trigger function the periodic integrity
  check watches (`rolePermGenerationDef`, `secretNodeCacheEpochDef`) carries this release's
  version marker as its `COMMENT`: `keyorix-trigger-def <function> v<N> sha256:<digest>`
  (`pgTriggerDef.marker`), where the digest (`triggerDefDigest`) covers the function's language,
  `proconfig`, `prosecdef` and body and each checked trigger's table, name and shape. The installers
  write it only when it differs. A checker or installer treats a definition as follows
  (`pgTriggerDef.newerThan`): exactly its own definition and marker is good; a marker at most
  `triggerDefMaxNewerSkew` (1) versions ahead whose digest matches the catalog, with every checked
  trigger present on one function, is a newer release's definition and is left in place (the
  checker logs a non-`SECURITY` line, counts `reason="newer_definition"`, invalidates once and
  re-warns hourly; the installer only restores `ENABLE ALWAYS`) for at most
  `triggerDefNewerAcceptBound` (24 h), counted per checker from its first reading of a newer
  definition with no reading of its own since (`triggerIntegrityChecker.boundNewer`); after that
  it is logged `SECURITY:`, counted `reason="tamper"` and restored, the repair removing the expired
  marker first (`expireNewerTriggerDef`) so `leaveNewerTriggerDef` does not protect it; everything else (no marker, a
  malformed one, an equal or older version that is not exactly its own, a version further ahead,
  a digest mismatch) is tampering and is restored to its own definition (`reason="tamper"`). A
  release that changes a body, its settings or the trigger shape must bump that definition's
  `version`; it must not change the set of trigger names a target checks. Why: #3717. Without
  versions, two releases with different definitions re-installed their own every tick during a
  rolling upgrade (alarms and fleet-wide flushes on both sides, ACCESS EXCLUSIVE churn, and the
  older side undoing a security fix part of the time). Residual risk, stated: the digest is not a
  signature; the owner of the function can forge a self-consistent marker one version ahead, which
  older replicas leave in place (warning, `newer_definition` moving) for the bound (ask
  3841-forged-marker-acceptance-bound, option a: before it, until a release at that version);
  the clock is in memory, so a replica restart starts it again; a rolling upgrade that skips a
  definition version ping-pongs as before, and one that outlasts the bound costs one restore per
  older replica per bound.
  Guard: `TestTriggerDefMarker_OwnMarkersParse`, `_TestReleaseLiterals`, `_NewerThan` (default CI);
  (pg-gated) `TestRolePermGenerationIntegrity_NewerReleaseDefinitionIsLeftInPlace_Postgres`,
  `TestSecretNodeCacheEpochIntegrity_NewerReleaseDefinitionIsLeftInPlace_Postgres` (red on the
  base by behaviour), `TestTriggerIntegrityVersions_TwoReleasesTickAlternately_Postgres`,
  `_ForgedMarkersAreTampering_Postgres`, `_CacheEpochTwoReleasesTickAlternately_Postgres`,
  `_CatalogDigestMatchesTheInstaller_Postgres`;
  `TestTriggerIntegrityNewerBound_ForgedMarkerRestoredAfterBound_Postgres`,
  `_CacheEpochForgedMarkerRestoredAfterBound_Postgres`,
  `_RebootDoesNotProtectExpiredMarker_Postgres` (the bound, red on the base by behaviour).
