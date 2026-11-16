# fuzz/thirdparty/compress invariants

Read this before changing the decompression-amplification fuzz harness. This package
is test-only (`compresshostile`, imported from nothing). It drives the REAL sink the
MongoDB dynamic-secrets engine reaches — `go.mongodb.org/mongo-driver/v2`
`x/mongo/driver.DecompressPayload` (snappy / zlib / zstd branches), reached from
`internal/dynamic/mongodb.go connectMongo` when `adminDSN` negotiates compression and
the server sends `OP_COMPRESSED` — plus the klauspost/compress snappy block codec that
sits behind one branch. These are regression tripwires on third-party behaviour at the
Keyorix construction site, not proofs Keyorix owns the behaviour.

Format: `INV-FUZZCOMPRESS-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`
(`NN` is a placeholder — fragment IDs use a descriptive `-<slug>` suffix).

New invariants go in `INVARIANTS.d/INV-FUZZCOMPRESS-<kebab-slug>.md` (one per file).

## Oracles
