- **INV-NETUTIL-resp-declared-length** A Redis client built for an operator-supplied endpoint
  (`internal/dynamic` `connectRedis`, `internal/rotation` `RedisExecutor`) dials through
  `RESPGuardDialer`, which rejects, before the client's parser sees it, any RESP reply whose
  announced sizes (bulk bytes, element counts, map/attribute pairs) add up to more than
  `DefaultRESPMaxDeclaredBytes` (64 MiB) per command window, any non-length line over
  `DefaultRESPMaxLineBytes` (1 MiB), any length header whose number has more than 19 digits
  (the digits of max int64; this is what bounds a length-header line, which the line cap does
  not cover, so `$000…0` cannot stream an unbounded line into go-redis' line buffer), and any
  malformed length header or unknown type byte (fail closed). Why: go-redis sizes its buffers from the announced length before any body
  byte arrives and has no option to cap it, so a hostile or intercepted server could make the
  client allocate gigabytes, hang waiting for the body, or panic on an out-of-range length with
  a reply of a few bytes; the read timeout only fires after the allocation has succeeded
  (fuzz-found, LF3-F3). Guard: `internal/netutil` `TestRESPScannerVerdicts` (accept/reject
  vectors, also byte-at-a-time), `TestRESPScannerMatchesReference` and `FuzzRESPScannerChunking`
  (verdict independent of how the stream is split across reads, and equal to a whole-buffer
  reference), `TestRESPGuardConn*` (violating chunk withheld, connection closed, window reset
  on write); end to end `internal/dynamic` `TestConnectRedisRejectsHostileDeclaredLengths` and
  `internal/rotation` `TestRedisRotateRejectsHostileDeclaredLengths` (red without the guard:
  the client hangs on a 1 GB announcement). **Not covered**: a legitimate reply larger than the
  budget is also refused (none exists for the ACL/AUTH/PING commands keyorix issues); the guard
  bounds announced size, not actual traffic or time: bytes of non-length lines are not charged to
  the budget, so an in-budget array of up to 4M elements of up to 1 MiB each is accepted (its cost
  tracks bytes on the wire and is bounded by the read timeout); the window resets only on a client
  write, so a long push/pubsub stream with no writes would eventually be refused (keyorix issues no
  pubsub); big-number lines up to the line cap reach go-redis' `big.Int.SetString`, superlinear in
  CPU but bounded; it does not apply to other Redis clients added later unless they dial through
  `RESPGuardDialer`.
