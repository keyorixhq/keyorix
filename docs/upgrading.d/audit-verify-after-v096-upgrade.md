## `audit verify` right after a v0.96.x upgrade

Plain `keyorix audit verify` (and `GET /api/v1/audit/verify`) reports `VALID` only when a full
re-walk of the audit chain has completed recently. v0.96.x kept no record of one, so the first
answer after the upgrade is `NOT PROVEN` with `no full verification has completed yet` (exit code
1). That is the fail-closed answer, not damage to the chain: a break reads `BROKEN` and names the
first bad event.

What changed (#3743): before, the new server waited behind the checkpoint v0.96.x had just
written and ran its first re-walk up to 24 hours after the start, so `audit verify` said
`NOT PROVEN` all that time. Now the server runs the first re-walk at once when no full verification
is on record. The start log says `Audit-checkpoint scheduler enabled ... first tick in 0s`.

- A chain of up to 100,000 audit events is re-walked in that first tick: plain `audit verify`
  reads `VALID` within seconds of the start.
- A longer chain is re-walked in 7 segments, one per daily tick, so plain `audit verify` stays
  `NOT PROVEN` for up to a week. To prove it now, run `keyorix audit verify --full` once. It runs
  the whole walk as a background job on the server and prints `Audit chain: VALID`, and later plain
  calls are `VALID` too.

A post-upgrade check script should call `keyorix audit verify --full`: it gives the same answer
for every chain length.
