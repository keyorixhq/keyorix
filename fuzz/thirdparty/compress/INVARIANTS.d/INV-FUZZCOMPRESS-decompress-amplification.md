- **INV-FUZZCOMPRESS-decompress-amplification** `driver.DecompressPayload`, driven directly
  with `(codec, UncompressedSize, in)` for every codec branch (snappy/zlib/zstd), allocates
  memory that stays within a per-input-byte SLOPE budget calibrated on a benign corpus of
  realistic (compression-ratio ~1–6×) frames. An allocation wildly out of proportion to the
  compressed input it was driven with — the decompression-bomb / `UncompressedSize`
  pre-allocation shape — trips the budget. The harness CLAMPS every driven `UncompressedSize`
  to 64 MiB so the fuzzer cannot OOM itself; the real driver has no such clamp (int32, up to
  ~2 GiB), which is the hardening gap this records. Why: `DecompressPayload` does
  `make([]byte, opts.UncompressedSize)` (zlib), `make([]byte, UncompressedSize)` after a
  `DecodedLen==UncompressedSize` check (snappy), and `make([]byte, 0, UncompressedSize)`
  (zstd) BEFORE the payload is validated, and `UncompressedSize`+`in` are attacker-controlled
  on an `OP_COMPRESSED` reply. Reachable from `internal/dynamic/mongodb.go connectMongo` only
  when `adminDSN` opts into compression and the server is malicious (non-default; trust-
  boundary crossing). **Does NOT verify**: absolute memory bound (a legit multi-MiB reply is
  allowed — the model is slope, chosen because legit Mongo replies reach ~48 MiB so an
  absolute ceiling would false-positive); resistance to a bomb that PADS its input to buy
  slope budget; decode correctness (round-trip owns that); wire framing (`FuzzMongoReply`
  owns that). The slope's sensitivity is set by `testdata/resguard.json`'s corpus ratio.
  Guard: `FuzzMongoDecompressPayload`, `TestResguardCompressRedGreen` (committed red/green:
  a ~6-byte snappy frame declaring 64 MiB trips the alloc budget at 15×; every benign sample
  passes), `TestResguardCompressCalibrate` (`fuzz/thirdparty/compress`).
- **INV-FUZZCOMPRESS-snappy-roundtrip** For any `src`, `snappy.Decode(snappy.Encode(nil, src))
  == src` and `snappy.DecodedLen(snappy.Encode(nil, src)) == len(src)` — the self-consistency
  the driver's `DecodedLen==UncompressedSize` check relies on. Why: the snappy branch trusts
  the frame's own declared length to size its allocation; a mismatch between what Encode
  writes and what DecodedLen reports would be a codec defect. **Does NOT verify**: the snappy
  STREAM format (mongo uses the block format); decode of adversarial frames (that is the
  amplification oracle, and a crafted header declaring a length the body does not satisfy is
  NOT a round-trip violation); no second-implementation differential (golang/snappy is not in
  the build). Guard: `FuzzSnappyRoundTrip` (`fuzz/thirdparty/compress`).
