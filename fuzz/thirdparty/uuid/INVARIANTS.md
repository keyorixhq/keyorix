# fuzz/thirdparty/uuid invariants

Read this before changing the google/uuid robustness fuzz harness. This package is
test-only (`uuidhostile`, imported from nothing). `google/uuid` is not imported by any
first-party package; it enters the build only through `go-webauthn/webauthn/protocol`
(reached from `internal/webauthnrp`), which turns the 16-byte AAGUID in attacker-supplied
attestation data into a uuid via `uuid.FromBytes` — the BYTE path, not the string path. So
the string parser fuzzed here is only indirectly reachable; the harness is a low-yield
robustness/round-trip tripwire, documented as such.

Format: `INV-FUZZUUID-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`
(`NN` is a placeholder — fragment IDs use a descriptive `-<slug>` suffix).

New invariants go in `INVARIANTS.d/INV-FUZZUUID-<kebab-slug>.md` (one per file).

## Oracles
