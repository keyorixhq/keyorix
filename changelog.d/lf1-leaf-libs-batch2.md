### Testing
- **Leaf-library fuzz targets, batch 2 (compress decompression-amplification, uuid).** New
  test-only `fuzz/thirdparty/compress` (`compresshostile`) and `fuzz/thirdparty/uuid`
  (`uuidhostile`) harnesses. `FuzzMongoDecompressPayload` drives the real sink the MongoDB
  dynamic-secrets engine reaches — `go.mongodb.org/mongo-driver/v2`
  `driver.DecompressPayload` (snappy/zlib/zstd), which pre-allocates the attacker-controlled
  `OP_COMPRESSED` `UncompressedSize` before any integrity check — through a resguard
  per-byte-slope memory oracle (committed budget + red/green: a ~6-byte snappy frame
  declaring 64 MiB trips it; benign frames pass). `FuzzSnappyRoundTrip` pins the
  klauspost/compress snappy block round-trip and `DecodedLen` self-consistency.
  `FuzzUUIDParse`/`FuzzUUIDFromBytes` cover google/uuid parse round-trip, canonical-form
  superset differential, and the 16-byte AAGUID path. Reachability is traced and labelled
  honestly in each package's `INVARIANTS.md` (the compress path is non-default/conditional;
  the uuid path is weak/indirect). Seven of the eleven named libraries are not in the module
  graph and are skipped with that reason.
