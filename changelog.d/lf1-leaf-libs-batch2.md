### Testing
- **Leaf-library fuzz targets, batch 2 (compress decompression-amplification, uuid).** New
  test-only `fuzz/thirdparty/compress` (`compresshostile`) and `fuzz/thirdparty/uuid`
  (`uuidhostile`) harnesses. `FuzzMongoDecompressPayload` drives the real sink the MongoDB
  dynamic-secrets engine reaches — `go.mongodb.org/mongo-driver/v2`
  `driver.DecompressPayload` (snappy/zlib/zstd) — through a resguard memory oracle keyed to
  the genuine decompressed OUTPUT size (the size is derived from the frame, never fuzzed;
  committed budget + red/green: a planted 50×-output allocation at 1 MiB trips it; benign
  frames and a genuine high-ratio bomb pass). The oracle is a coarse tripwire (about a 17.5 MB
  absolute ceiling for small inputs) and does not cover the server-declared `UncompressedSize`
  the driver pre-allocates; that gap is unguarded here and tracked privately. `FuzzSnappyRoundTrip` pins the
  klauspost/compress snappy block round-trip and `DecodedLen` self-consistency.
  `FuzzUUIDParse`/`FuzzUUIDFromBytes` cover google/uuid parse round-trip, canonical-form
  superset differential, and the 16-byte AAGUID path. Reachability is traced and labelled
  honestly in each package's `INVARIANTS.md` (the compress path is reachable whenever the Mongo
  server is malicious; the uuid path is weak/indirect). Seven of the eleven named libraries are not in the module
  graph and are skipped with that reason.
