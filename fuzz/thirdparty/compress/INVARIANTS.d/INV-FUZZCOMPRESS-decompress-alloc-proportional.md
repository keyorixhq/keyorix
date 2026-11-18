- **INV-FUZZCOMPRESS-decompress-alloc-proportional** `driver.DecompressPayload`, driven for
  every codec branch (snappy/zlib/zstd) with an `UncompressedSize` DERIVED from the genuine
  decoded length of `in` (never fuzzed), allocates memory that stays PROPORTIONAL to the
  decompressed OUTPUT size — the resguard per-byte alloc/malloc slope is keyed to
  `sizeKey = max(len(in), decodedLen)` and calibrated on LARGE benign frames (marginal
  ratio ~1). A decode whose allocation is super-linear in its output (alloc ≫ output, or a
  per-byte allocation storm) trips; a legitimate high-compression-ratio frame (alloc ≈
  output) passes. The fuzzer never panics / hangs (`fuzzutil.Guard`). Why: the only sound
  library property here is "allocate the output you decompressed, nothing more" — keying to
  the compressed INPUT instead would flag ordinary high compression ratios as bombs, and
  feeding an arbitrary `UncompressedSize` just tests the caller's own contract. **Does NOT
  verify**: (1) an ABSOLUTE memory bound — a malicious Mongo server can still force an
  allocation up to the genuine output size (production ceiling is the driver's int32 ~2 GiB);
  that MISSING decompressed-size CAP in `DecompressPayload` is a HARDENING item recorded in
  the report, not a disproportion this oracle can trip, because allocating the output is
  correct; (2) ordinary compression ratios (not a defect); (3) decode correctness
  (`FuzzSnappyRoundTrip`); (4) wire framing (`FuzzMongoReply`); (5) `live_heap`/drift —
  deliberately excluded because the pooled zstd decoder keeps large internal buffers live
  across inputs, making absolute live-heap a non-signal (only the per-input alloc DELTA is
  fatal). Reachable from `internal/dynamic/mongodb.go connectMongo` only when `adminDSN` opts
  into compression and the server is malicious (non-default; trust-boundary crossing). Guard:
  `FuzzMongoDecompressPayload`, `TestResguardCompressRedGreen` (committed red/green: a planted
  50×-output allocation trips at 2.2×; every benign sample AND a genuine high-ratio zstd bomb
  pass), `TestResguardCompressCalibrate` (`fuzz/thirdparty/compress`).
