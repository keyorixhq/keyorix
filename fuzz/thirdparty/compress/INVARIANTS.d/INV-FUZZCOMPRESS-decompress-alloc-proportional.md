- **INV-FUZZCOMPRESS-decompress-alloc-proportional** `driver.DecompressPayload`, driven for
  every codec branch (snappy/zlib/zstd) with an `UncompressedSize` DERIVED from the genuine
  decoded length of `in` (never fuzzed), allocates memory that stays within a ceiling
  keyed to the decompressed OUTPUT size — the resguard per-byte alloc/malloc slope is keyed to
  `sizeKey = max(len(in), decodedLen)` and calibrated on LARGE benign frames (marginal
  ratio ~1). A decode whose allocation is far above its output trips; a legitimate
  high-compression-ratio frame (alloc ≈ output) passes. The fuzzer never panics / hangs
  (`fuzzutil.Guard`). Why: the only sound library property here is "allocate the output you
  decompressed, nothing more" — keying to the compressed INPUT instead would flag ordinary
  high compression ratios as bombs, and feeding an arbitrary `UncompressedSize` just tests
  the caller's own contract. **Sensitivity**: the fatal ceiling is `factor·(floor +
  per_byte·out)` ≈ 17.5 MB + 6.9·out (`testdata/resguard.json`); the floor is the p99 of the
  largest calibration allocations, so for small inputs this is effectively an absolute
  ~17.5 MB ceiling. Measured: a planted over-allocation of 20× output at 1 MiB, and of 3000×
  at 4 KiB, does NOT trip it; the committed RED uses 50× at 1 MiB. It is a coarse tripwire,
  not a tight proportionality check. **Does NOT verify**: (1) an ABSOLUTE memory bound — a
  malicious Mongo server can still force an allocation up to the genuine output size
  (production ceiling is the driver's int32 ~2 GiB); the missing decompressed-size CAP in
  `DecompressPayload` is not a disproportion this oracle can trip, because allocating the
  output is correct; (2) the server-declared `UncompressedSize` the driver pre-allocates
  before reading the body: UNGUARDED (keyorix-private, id pending) — no test in the repo
  covers it; (3) ordinary compression ratios (not a defect); (4) decode correctness
  (`FuzzSnappyRoundTrip`); (5) wire framing — no test models OP_COMPRESSED (`FuzzMongoReply`
  cannot emit it); (6) `live_heap`/drift — deliberately excluded because the pooled zstd
  decoder keeps large internal buffers live across inputs, making absolute live-heap a
  non-signal (only the per-input alloc DELTA is fatal). Reachable from
  `internal/dynamic/mongodb.go connectMongo` by default whenever the Mongo server is
  malicious or compromised: the driver decompresses any OP_COMPRESSED reply without
  compression having been negotiated (trust-boundary crossing). Guard:
  `FuzzMongoDecompressPayload`, `TestResguardCompressRedGreen` (committed red/green: a planted
  50×-output allocation at 1 MiB trips; every benign sample AND a genuine high-ratio zstd
  bomb pass), `TestResguardCompressCalibrate` (`fuzz/thirdparty/compress`).
