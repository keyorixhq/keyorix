### Fixed
- **`audit verify` no longer reads NOT PROVEN for a day after a v0.96.x upgrade.** v0.96.x left
  a fresh signed checkpoint but no record of a full re-walk, and the new server held its first
  verification tick back until that checkpoint was 24 h old. The first tick now runs at start
  whenever no full verification is on record, so a chain of up to 100,000 events reads `VALID`
  within seconds of the first start (the log says `first tick in 0s`). A longer chain is still
  re-walked over 7 daily ticks; `keyorix audit verify --full` proves it at once. What `VALID`,
  `NOT PROVEN` and `BROKEN` mean is unchanged. Upgrade note:
  `docs/upgrading.d/audit-verify-after-v096-upgrade.md` (#3743).
