### Testing
- **Hostile-server fuzzing of mongo-driver/v2 wire parsing
  (`fuzz/thirdparty/mongodb` `FuzzMongoReply`).** A fake server completes the
  MongoDB connect handshake (OP_QUERY/OP_MSG `hello`) and then streams a
  fuzz-controlled command-reply wire message to a marker `RunCommand`, driving
  the v2.9.2 driver's `wiremessage`/OP_MSG/OP_COMPRESSED parser and cursor-batch
  decode (the `createUser`/`dropUser` reply path `internal/dynamic` uses).
  Oracles: no panic/hang, bounded alloc (reply capped at 64 KiB, OP_COMPRESSED
  uncompressedSize clamped), canary, truncation — each pinned red/green. No new
  defect observed (the driver returns `malformed wire message` errors on bad
  section/length shapes); no Keyorix production code changed.
