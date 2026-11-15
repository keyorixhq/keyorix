- **INV-FUZZCLOUD-db-msglevel-parity-no-mixing** For the message-level DB harnesses, two
  decode properties hold against a structure-aware hostile server: (a) decoding parity —
  for a coherent single-row result the value the driver surfaces equals, byte-for-byte, the
  value the harness encoded into the wire (pgx `rows.RawValues()` vs the generated DataRow;
  go-sql-driver `Scan` into `sql.RawBytes` vs the length-encoded text field); and (b) no
  response mixing — a hostile reply to statement A never contaminates statement B's decoded
  row on the same connection (B must return a fixed sentinel or nothing). Why: Keyorix reads
  bytea/text/jsonb/timestamptz/integer values back from these drivers and runs multiple
  statements per connection; a mis-framed value or cross-statement bleed would corrupt a
  rotated password or a dynamic-credential readback. Guard: `FuzzPgxMessageLevel` /
  `FuzzMySQLMessageLevel` (parity), `FuzzPgxResponseMixing` / `FuzzMySQLResponseMixing`
  (mixing); each oracle is red-proven (parity: corrupt the expected bytes; mixing: have the
  server send a non-sentinel B row) with a committed coherent seed that actually reaches the
  oracle. Does NOT assert type-aware decode correctness (it compares raw bytes, not Go-typed
  values), and the mixing oracle only fires when B's query succeeds — a poisoned connection
  that fails B is treated as no contamination.
