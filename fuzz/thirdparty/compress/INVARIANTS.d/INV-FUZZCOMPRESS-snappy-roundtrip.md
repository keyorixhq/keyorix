- **INV-FUZZCOMPRESS-snappy-roundtrip** For any `src`, `snappy.Decode(snappy.Encode(nil, src))
  == src` and `snappy.DecodedLen(snappy.Encode(nil, src)) == len(src)` — the self-consistency
  the driver's `DecodedLen==UncompressedSize` check relies on. Why: the snappy branch trusts
  the frame's own declared length to size its allocation; a mismatch between what Encode
  writes and what DecodedLen reports would be a codec defect. **Does NOT verify**: the snappy
  STREAM format (mongo uses the block format); decode of adversarial frames (that is the
  amplification oracle); no second-implementation differential (golang/snappy is not in the
  build). Guard: `FuzzSnappyRoundTrip` (`fuzz/thirdparty/compress`).
