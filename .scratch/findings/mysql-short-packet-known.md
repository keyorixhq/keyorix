# KNOWN upstream — go-sql-driver/mysql v1.10.1 short-packet underread panics

Classification: EXPECTED (known, already-registered: KFZ-2026-005 / 076 / 079).
NOT re-reported. Reproducer bytes kept here only (never in committed seeds/comments).

Threat model note: a hostile target server returns a truncated packet whose declared
header length is honored but whose body is shorter than the parser assumes, so the
driver indexes past the slice → runtime panic (index/slice bounds out of range). This is
a crash (DoS) in the driver's parse path, caught by the H6 panic oracle and classified
known.

Reproducers (as the hostile server's raw reply bytes; `frame(seq,payload)` = 3-byte LE
len + seq + payload):

1. Handshake path — truncated greeting (protocol byte only):
   frame(0, {0x0a})  =>  04 00 00 00 0a   (len=1)
   panic: slice bounds out of range [:13] with capacity 1   (readHandshakePacket)

2. COM_QUERY response — short EOF / under-length status packet:
   frame(1, {0xfe})  =>  01 00 00 01 fe
   panic: index out of range [7] with length 0

3. COM_STMT_PREPARE response — truncated prepare-OK:
   frame(1, {0x00})  =>  01 00 00 01 00
   panic: slice bounds out of range [:5] with capacity 1   (readPrepareResultPacket)

All three reproduce deterministically on a clean checkout of v1.10.1 via the public
database/sql API (PingContext / ExecContext / QueryContext) — i.e. they pass the
DISCLOSURE-TRIAGE feasibility gate as library defects, but are already known.

Keyorix exposure: reachable (dynamic/mysql.go PingContext/ExecContext/QueryContext against
an operator-configured target), but a crash here is a localized panic recovered by the
dynamic-secrets engine's own call boundary; it is a DoS of the single mint/revoke/rotate
operation, not memory disclosure. Already tracked upstream-known; no new action.
