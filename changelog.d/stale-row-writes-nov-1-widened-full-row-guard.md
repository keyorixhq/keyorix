### Testing
- **The stale full-row write guard now sees past store and core.** A new sibling,
  `TestFullRowWriteGuard_WidenedScanNoStaleFullRowWrite` (internal/storage/store), applies
  the #2704 rule to every production package whose files import gorm or the models
  package (derived, not listed) and also reports `UpdateColumns(struct)` and
  `CreateInBatches` under an `UpdateAll` upsert. It is report-only until its first green
  nightly on main. It finds nothing today. A planted `Save(*models.User)` in
  internal/encryption and an `UpdateColumns(u)` in store, both missed by the original
  guard, fail it.
