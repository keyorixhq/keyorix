- **INV-RESTOREJOURNAL-torn-journal-never-silently-absent** An EXISTING restore journal that
  is truncated, garbled, or a wrong `Version` is surfaced by `Read` as an error, never
  `found=false` ("no restore to recover") and never `found=true` with a usable zero-value
  journal — a half-installed restore must never look recoverable-as-nothing. A `Write` then
  `Read` round-trips the journal and its per-entry SHA-256. The recovery install-gate building
  block `HashFile(staged) == Entry.SHA256` detects a tampered or truncated staged file and
  errors on a missing one, so a torn staged file is never mistaken for the recorded content
  (Entry.SHA256 doc: "Recovery installs a staged file only if it still hashes to this"). Why:
  `journal.go` `Read`/`Entry.SHA256` doc comments. Does NOT cover the install/undo decision in
  `server/admin/restore.go` (needs a full server config + DB) — this guards the journal layer
  that decision rests on. Guard: `FuzzRestoreJournalCrashReplay`
  (journal_crash_replay_fuzz_test.go).
