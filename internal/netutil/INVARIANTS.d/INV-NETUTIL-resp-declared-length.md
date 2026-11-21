- **INV-NETUTIL-resp-declared-length** A Redis client built for an operator-supplied endpoint
  (`internal/dynamic` `connectRedis`, `internal/rotation` `RedisExecutor`) dials through
  `RESPGuardDialer`, which rejects, before the client's parser sees it, any RESP reply whose
  announced sizes (bulk bytes, element counts, map/attribute pairs) add up to more than
  `DefaultRESPMaxDeclaredBytes` (64 MiB) per command window, any non-length line over
  `DefaultRESPMaxLineBytes` (1 MiB), and any malformed length header or unknown type byte
  (fail closed). Why: go-redis sizes its buffers from the announced length before any body
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
  bounds announced size, not actual traffic or time; it does not apply to other Redis clients
  added later unless they dial through `RESPGuardDialer`.
