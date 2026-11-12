### Testing
- **Hostile-server fuzzing of go-sql-driver/mysql past the handshake
  (`fuzz/thirdparty/mysql` `FuzzMySQLHostileQuery`).** A fake loopback server
  completes a fixed valid handshake + auth, then drives the driver's text and
  binary result-set parsers (incl. the `COM_STMT_PREPARE`/`COM_STMT_EXECUTE`
  prepared-statement path that `internal/dynamic` `killUserConnections` reaches
  on a dynamic-secret revoke) through the `database/sql` public API with
  fuzz-controlled response packets. Documents seven confirmed v1.10.1 library
  panic sites (one root cause: no length validation before slicing
  server-controlled result-set packets — `readPrepareResultPacket`,
  `binaryRows.readRow` NULL bitmap, `handleOkPacket`, `readColumns`,
  `readLengthEncodedInteger`, `textRows.readRow`, `handleErrorPacket`), each with
  a deterministic reproducer and an allowlist red/green test. Library-attributable
  (upstream-reportable), reachable in Keyorix only from a hostile/compromised
  target MySQL; no Keyorix production code changed.
