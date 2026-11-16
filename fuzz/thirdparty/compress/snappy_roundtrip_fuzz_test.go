package compresshostile

import (
	"bytes"
	"testing"

	"github.com/klauspost/compress/snappy"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzSnappyRoundTrip is the library-level oracle for the klauspost/compress
// snappy BLOCK codec (the codec behind DecompressPayload's snappy branch and
// mongo-driver request compression). For any input src:
//
//   - Encode never panics, and Decode(Encode(src)) == src (round-trip identity);
//   - snappy.DecodedLen(Encode(src)) == len(src) (the header the driver trusts
//     to size its make([]byte, …) is self-consistent with the encoder);
//   - Decode(Encode(src)) never panics and is bounded (len == len(src)).
//
// What this does NOT verify: (1) it does not exercise the snappy STREAM format
// (Encode/Decode here are the block format, which is what mongo uses); (2) it
// does not test decode of ADVERSARIAL frames for amplification — that is
// FuzzMongoDecompressPayload's job (and a crafted header can legitimately
// declare a length the body does not satisfy, which is NOT a round-trip
// violation); (3) it does not compare against another snappy implementation
// (golang/snappy is not in the build), so it is a self-consistency oracle, not
// a differential one.
func FuzzSnappyRoundTrip(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("hello world"))
	f.Add(bytes.Repeat([]byte("ab"), 1000)) // highly compressible
	f.Add(lcg(4096))                         // low compressibility
	f.Fuzz(func(t *testing.T, src []byte) {
		var enc []byte
		fuzzutil.Guard(t.Fatalf, "snappy.Encode", func() {
			enc = snappy.Encode(nil, src)
		})

		gotLen, err := snappy.DecodedLen(enc)
		if err != nil {
			t.Fatalf("DecodedLen on self-encoded frame failed: %v (src=%d bytes)", err, len(src))
		}
		if gotLen != len(src) {
			t.Fatalf("DecodedLen mismatch: header says %d, src is %d bytes", gotLen, len(src))
		}

		var dec []byte
		var derr error
		fuzzutil.Guard(t.Fatalf, "snappy.Decode", func() {
			dec, derr = snappy.Decode(nil, enc)
		})
		if derr != nil {
			t.Fatalf("Decode of self-encoded frame failed: %v (src=%d bytes)", derr, len(src))
		}
		if !bytes.Equal(dec, src) {
			t.Fatalf("round-trip mismatch: %d bytes in, %d bytes out", len(src), len(dec))
		}
	})
}
