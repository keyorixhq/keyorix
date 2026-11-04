### Security
- **The audit high-water mark and the signed verification state survive a lost checkpoint lock.**
  Both were written with a last-write-wins upsert whose "only ever advances" held only while
  `WithAuditCheckpointLock` was exclusive. After a silent lock loss (a connection pooler dropping
  the advisory lock), a slower replica could write a lower high-water mark after a faster one, so a
  truncation of the newest events went unseen, or save an older verification state over one that
  had just recorded a sticky failure. They are now written with a compare-and-set on the value
  read (new storage method `CompareAndSetSystemMetadata`); a lost write re-reads and skips or
  retries once. `docs/design/pooler-lock-loss.md` row 15 is now covered.

### Changed
- **`keyorix-server admin verify-audit` prints a seal's unpinned spans.** The surviving rows before an
  accepted gap that no signed artifact pinned when the loss was accepted were shown only in the
  seal record and the accept-loss plan; the report now names them under each seal, and the JSON
  report carries them as a new `unpinned` field on each seal (no field removed or renamed).
