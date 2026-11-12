### Testing
- **Hostile-server fuzzing of redis/go-redis/v9 reply parsing
  (`fuzz/thirdparty/redis` `FuzzRedisReply`).** A fake server satisfies the
  connect handshake and then streams a fuzz-controlled command-reply byte stream
  to the client's generic `Do`, driving go-redis v9.23.0's `internal/proto`
  RESP3 reply parser (the `ACL SETUSER`/`ACL DELUSER` reply path
  `internal/dynamic` uses). Oracles: no panic/hang, bounded alloc, canary,
  truncation — each pinned red/green. Characterises **REDIS-1**: the RESP3
  aggregate parser (`readSlice`/`readMap`) recurses once per nesting level with
  no depth guard, a stack-exhaustion DoS at attacker-chosen nesting depth
  (library-attributable, reachable only from a hostile/compromised target
  Redis). No Keyorix production code changed.
