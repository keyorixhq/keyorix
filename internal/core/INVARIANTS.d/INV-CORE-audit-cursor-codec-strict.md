- **INV-CORE-audit-cursor-codec-strict** The audit-list keyset cursor codec
  (`audit_page.go`) is symmetric and strictly, safely parsed. `EncodeAuditCursor`/
  `DecodeAuditCursor` round-trip an event's id and nanosecond `EventTime` for ids in
  `[1, 2^32-1]`. `DecodeAuditCursor` — fed the `cursor=` query parameter of GET /audit/logs
  and GET /audit/search and the gRPC page token, i.e. directly attacker-controlled input —
  never panics, rejects anything over 64 bytes or not base64, requires the `v1` version and a
  non-zero id, and only ever accepts a cursor it could itself have issued (an accepted cursor
  re-encodes to one that decodes back identically). The cursor is deliberately UNSIGNED: it
  has no authority and only bounds where a page starts in a result set the caller may already
  read, so a forged-but-well-formed cursor is a correct parse — strict, crash-free parsing is
  the whole guarantee. Why: it is a request-path parser with no signature; a crash or a lax
  accept would be reachable by any client. Guard: `FuzzAuditCursorRoundTrip`,
  `FuzzDecodeAuditCursor` (core, I7 small-parser sweep).
