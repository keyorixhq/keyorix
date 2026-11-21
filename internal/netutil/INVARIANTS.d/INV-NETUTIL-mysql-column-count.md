- **INV-NETUTIL-mysql-column-count** A MySQL connection built for an operator-supplied endpoint
  (`internal/dynamic` `openMySQLConfig`, `internal/rotation` `MySQLExecutor.conn`) dials through
  `MySQLGuardDialer`, which refuses, before the driver reads it, a result set header that announces
  more than `DefaultMySQLMaxColumns` (65536) columns in the first packet of a command's response,
  and refuses a client that negotiates the compressed protocol (its framing is not tracked).
  Why: go-sql-driver/mysql up to v1.10.1 sizes its column slice from the announced count before it
  reads a column packet, so a hostile or intercepted server could make the client allocate hundreds
  of megabytes (or panic on an out-of-range count) with a reply of a few bytes (fuzz-found,
  KFZ-2026-005); the driver's own fix is a separate upstream change and does not make this guard
  redundant until the pin includes it. Guard: `internal/netutil` `TestMySQLScannerVerdicts`
  (accept/reject vectors, every chunking), `TestMySQLScannerMatchesReference` (20k random
  dialogues against a structural reference) and `FuzzMySQLScannerChunking` (verdict independent of
  how the stream is split), `TestMySQLGuardConn*` (violating chunk withheld, connection closed,
  sticky error, compression refused, TLS pass-through); end to end `internal/dynamic`
  `TestOpenMySQLRejectsHostileColumnCount` and `internal/rotation`
  `TestMySQLRotateRejectsHostileColumnCount` (red without the guard: a large allocation, or a panic).
  **Not covered**: connections that negotiate TLS (the driver layers TLS over the connection it
  dials, so the guard sees ciphertext and steps aside after the SSLRequest packet); later result
  sets of a multi-statement reply; other announced sizes (row and packet lengths); the guard bounds
  an announced count, not traffic or time. A TLS endpoint is protected only by the driver fix.
