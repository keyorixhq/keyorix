- **INV-NETUTIL-mysql-column-count** A MySQL connection built for an operator-supplied endpoint
  (`internal/dynamic` `openMySQLConfig`, `internal/rotation` `MySQLExecutor.conn`) dials through
  `MySQLGuardDialer`, which refuses, before the driver reads it, every packet the driver reads as
  a response head that would make it size a column slice above `DefaultMySQLMaxColumns` (65536)
  or panic: the first packet of each command's response, and the packet after an OK whose status
  has SERVER_MORE_RESULTS_EXISTS or after a LOCAL INFILE request (the driver reads that one as
  the next result set header inside Query itself, and a hostile server sets the bit on its own,
  with no multi-statement setting). Refused shapes: an announced count above the bound; a
  truncated length-encoded count (including a short `0xfe`, which the driver never reads as
  EOF); an OK packet too short for its two lengths and status (the driver panics, or reads the
  status from the bytes after the packet); a short ERR or prepare response; a column count
  without its metadata byte when MariaDB cache metadata is negotiated. It also refuses a client
  that negotiates the compressed protocol (its framing is not tracked), so a `compress=true` DSN
  fails to connect. Packets of 0xffffff bytes and their continuations are one logical packet,
  and only the first client packet with sequence 1 is read as capability flags.
  Why: go-sql-driver/mysql up to v1.10.1 sizes its column slice from the announced count before it
  reads a column packet, so a hostile or intercepted server could make the client allocate hundreds
  of megabytes (or panic) with a reply of a few bytes (fuzz-found, KFZ-2026-005; the MORE_RESULTS
  path and the short heads found in review of #4567); the driver's own fix is a separate upstream
  change (go-sql-driver/mysql#1866) and does not make this guard redundant until the pin includes
  it. Guard: `internal/netutil` `TestMySQLGuardAgreesWithDriver` (the pinned driver itself behind
  the guard: no panic and no large allocation for any reply the guard passes; the named harmful
  replies are first shown to misbehave unguarded), `TestMySQLScannerVerdicts` and
  `TestMySQLScannerContinuationPackets` (accept/reject vectors, every chunking),
  `TestMySQLScannerMatchesReference` (20k random dialogues against a reference built from the
  driver's own decoding, not from the scanner's rules), `FuzzMySQLScannerChunking` (verdict
  independent of how the stream is split), `TestMySQLGuardConn*` (violating chunk withheld,
  connection closed, sticky error, compression refused, TLS pass-through); end to end
  `internal/dynamic` `TestOpenMySQLRejectsHostileColumnCount` (text, interpolated and prepared
  revoke queries; red without the guard: a large allocation or a panic) and `internal/rotation`
  `TestMySQLRotateRejectsHostileColumnCount` (rotation runs ExecContext, which skips columns
  without allocating, so red there is a stall; both assert the guard's reason on the driver log).
  **Not covered**: connections that negotiate TLS (the driver layers TLS over the connection it
  dials, so the guard sees ciphertext and steps aside after the SSLRequest packet), which includes
  `tls=skip-verify` (an interceptor can terminate TLS) and `tls=preferred` when TLS is offered;
  result sets after a non-empty result set (read only by an explicit `rows.NextResultSet`, which
  no caller in the repository makes, and otherwise skipped without allocation); other announced
  sizes (row and packet lengths) and malformed column definitions; the guard bounds what the
  driver allocates from a head, not traffic or time. Wire-order dependency: a head the server
  sends before the client's command is not inspected, which is safe only because the driver
  refuses a new command while it holds unread bytes (`ErrBusyBuffer`). A TLS endpoint is
  protected only by the driver fix.
