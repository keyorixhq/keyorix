# internal/pqwrap invariants

Read this before changing anything in `internal/pqwrap`: the hybrid X25519 + ML-KEM key-wrap
envelope (`pqwrap.go`) and the self-describing key file built on it, the keyset (`keyset.go`).
Design and decisions: [docs/design/pq-key-wrapping.md](../../docs/design/pq-key-wrapping.md)
(§4 construction, §5 envelope, §7 keyset, §12 rewrap, §13 legacy reader). The decisions in its
§15 are final; changing one of them is a new design decision, not a code change.

Format: `INV-PQWRAP-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

Every invariant is a slug-ID fragment in [INVARIANTS.d/](INVARIANTS.d/), one per file.

## Envelope

The combiner binds every KEM input, the suite registry is closed, and no suite is
classical-only.

## Keyset

Boot gets a DEK only from a keyset authenticated under the KEK. The slot set is bound to the
header. Hybrid slots are only ever rebuilt all together. The KCV is a consistency check, not an
authenticator.

## Legacy reader

A legacy-60 `dek.key` written by an older binary keeps loading, indefinitely (Q9).
