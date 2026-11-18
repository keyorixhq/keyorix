package compresshostile

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	driver "go.mongodb.org/mongo-driver/v2/x/mongo/driver"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/wiremessage"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// ---- benign corpus (realistic compression ratios) ---------------------------

// lcg produces n deterministic low-compressibility bytes (ratio ~1:1 under any
// codec), so a sample built from it is a genuine large-but-honest reply, not a
// hidden amplifier.
func lcg(n int) []byte {
	out := make([]byte, n)
	var x uint32 = 0x9e3779b9
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = byte(x >> 24)
	}
	return out
}

// moderate produces n bytes of moderately-compressible content (English-ish
// repetition with embedded entropy) so a codec shrinks it ~2–5x — the realistic
// shape of a BSON reply, not the pathological all-zeros ratio that would blunt
// the slope oracle.
func moderate(n int) []byte {
	words := []string{"alice", "bob", "secret", "rotate", "version", "scope", "project", "kx_dyn_"}
	var b bytes.Buffer
	i := 0
	for b.Len() < n {
		w := words[i%len(words)]
		fmt.Fprintf(&b, "%s%d ", w, i*2654435761&0xffff)
		i++
	}
	return b.Bytes()[:n]
}

// encodeFor returns a VALID compressed frame for id plus the honest
// UncompressedSize, as a benign server would send it.
func encodeFor(tb testing.TB, id wiremessage.CompressorID, src []byte) ([]byte, int32) {
	tb.Helper()
	switch id {
	case wiremessage.CompressorSnappy:
		return snappy.Encode(nil, src), int32(len(src))
	case wiremessage.CompressorZLib:
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(src); err != nil {
			tb.Fatalf("zlib write: %v", err)
		}
		if err := w.Close(); err != nil {
			tb.Fatalf("zlib close: %v", err)
		}
		return buf.Bytes(), int32(len(src))
	case wiremessage.CompressorZstd:
		w, err := zstd.NewWriter(nil)
		if err != nil {
			tb.Fatalf("zstd writer: %v", err)
		}
		out := w.EncodeAll(src, nil)
		_ = w.Close()
		return out, int32(len(src))
	default:
		tb.Fatalf("unsupported codec %v", id)
		return nil, 0
	}
}

type sample struct {
	id driver.CompressionOpts
	in []byte
}

// benignSamples is the deterministic benign corpus used for calibration and as
// the GREEN cases: every codec over several realistic sizes, plus one
// legitimately-large low-compressibility reply per codec. Every UncompressedSize
// is the HONEST decoded length of its frame.
func benignSamples(tb testing.TB) []sample {
	tb.Helper()
	var out []sample
	sizes := []int{64, 512, 4096, 64 << 10}
	for _, id := range mongoCompressors {
		for _, n := range sizes {
			in, us := encodeFor(tb, id, moderate(n))
			out = append(out, sample{driver.CompressionOpts{Compressor: id, UncompressedSize: us}, in})
		}
		// one legitimately-large (~1 MiB) low-compressibility reply
		in, us := encodeFor(tb, id, lcg(1<<20))
		out = append(out, sample{driver.CompressionOpts{Compressor: id, UncompressedSize: us}, in})
	}
	return out
}

// calibrationSamples is the corpus the BUDGET is derived from: LARGE frames
// only (256 KiB … 4 MiB), where a decompressor's marginal allocation is ≈ the
// output (ratio ~1), so the per-byte slope reflects the true marginal cost and
// is NOT inflated by the fixed decoder overhead that dominates tiny frames. The
// floor is the p99 of the ABSOLUTE allocations of these large frames (about
// 4.4 MB), so it is far above the fixed decoder overhead of a small frame: small
// inputs get a generous allowance (this is the sensitivity limit stated in
// decompress_fuzz_test.go). GREEN is still checked against the full benignSamples
// range (incl. tiny frames).
func calibrationSamples(tb testing.TB) []sample {
	tb.Helper()
	var out []sample
	sizes := []int{256 << 10, 1 << 20, 4 << 20}
	for _, id := range mongoCompressors {
		for _, n := range sizes {
			in, us := encodeFor(tb, id, moderate(n))
			out = append(out, sample{driver.CompressionOpts{Compressor: id, UncompressedSize: us}, in})
		}
		in, us := encodeFor(tb, id, lcg(1<<20)) // ratio ~1 anchor
		out = append(out, sample{driver.CompressionOpts{Compressor: id, UncompressedSize: us}, in})
	}
	return out
}

func measureDecompress(tb testing.TB, p *resguard.Probe, in []byte, opts driver.CompressionOpts) resguard.Cost {
	tb.Helper()
	return p.Measure(sizeKey(in, opts.UncompressedSize), func() {
		_, _ = driver.DecompressPayload(in, opts)
	})
}

// calibrateCompress derives a slope budget from the benign corpus. The alloc
// meters stay on the DEFAULT per-byte slope (NOT UseAbsolute): the bomb shape
// here is small-input/large-genuine-output, so alloc-per-input-byte is the right
// discriminator. See decompress_fuzz_test.go for what this does NOT verify.
func calibrateCompress(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, s := range calibrationSamples(tb) {
		for range 3 { // average GC/alloc noise into p99
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, measureDecompress(tb, p, s.in, s.id))
		}
	}
	b := resguard.Calibrate("mongo_decompress_payload", costs, resguard.DefaultFactor)
	// Keep ONLY the per-input delta memory meters as fatal. alloc_bytes/mallocs
	// are deltas of cumulative TotalAlloc, so they attribute this input's
	// allocation to this input. live_heap is the ABSOLUTE live heap after GC;
	// the klauspost/mongo zstd decoder pool retains large internal buffers that
	// stay live across inputs, so live_heap is contaminated by prior inputs and
	// would false-positive on an empty input that follows a bomb. The advisory
	// meters (wall/cpu) remain informational and never fatal. See
	// INV-FUZZCOMPRESS-decompress-amplification.
	b.KeepOnly("alloc_bytes", "mallocs")
	return b
}

// TestResguardCompressCalibrate regenerates the committed budget under
// RESGUARD_CALIBRATE=1; otherwise it asserts calibration produced an alloc
// budget. Deterministic (the corpus is deterministic).
func TestResguardCompressCalibrate(t *testing.T) {
	b := calibrateCompress(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(budgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", budgetPath, b.Summary())
	}
}

// genuineBomb returns a REAL decompression bomb for id: a tiny compressed frame
// that legitimately expands to `out` bytes (all zeros, so it compresses to a few
// bytes). Unlike a declared-size trick, driver.DecompressPayload actually
// produces the full `out` bytes here, so the large allocation is justified by
// genuine decoded output — exactly the zip-bomb a malicious server would send.
func genuineBomb(tb testing.TB, id wiremessage.CompressorID, out int) sample {
	tb.Helper()
	in, us := encodeFor(tb, id, make([]byte, out))
	return sample{driver.CompressionOpts{Compressor: id, UncompressedSize: us}, in}
}

// overAllocDecodeSink keeps a planted over-allocation live during measurement.
var overAllocDecodeSink []byte

// overAllocDecode models a HYPOTHETICAL super-linear decoder defect: it decodes
// the frame honestly, then allocates OUTPUT×mult extra bytes — the shape the
// oracle exists to catch (allocation disproportionate to the decompressed
// output). It is a HARNESS-SIDE plant (no production file is modified), used
// only by the red/green proof.
func overAllocDecode(in []byte, opts driver.CompressionOpts, mult int) {
	out, _ := driver.DecompressPayload(in, opts)
	overAllocDecodeSink = make([]byte, len(out)*mult)
}

// TestResguardCompressRedGreen is the committed red/green proof for the
// keyed-to-OUTPUT alloc oracle. GREEN: every benign sample passes, AND a genuine
// high-ratio zstd bomb (tiny frame -> ~60 MiB) ALSO passes — allocating the
// output you decompressed is correct, not a defect. RED: a planted super-linear
// decode (alloc = 50× output at 1 MiB) on a benign frame trips the budget, proving
// the oracle discriminates "alloc proportional to output" (fine) from "alloc far
// above output" (a real decoder defect). It does NOT prove finer sensitivity: a
// 20× plant at 1 MiB, or 3000× at 4 KiB, stays under the ceiling (see
// decompress_fuzz_test.go).
func TestResguardCompressRedGreen(t *testing.T) {
	b := calibrateCompress(t)

	// GREEN 1: no benign sample may trip the budget.
	for _, s := range benignSamples(t) {
		p := resguard.New(t, resguard.Options{SampleEvery: 1})
		c := measureDecompress(t, p, s.in, s.id)
		var fired bool
		b.Check(func(string, ...any) { fired = true }, c)
		if fired {
			t.Fatalf("benign %s (in=%d us=%d) tripped the budget: alloc=%d",
				s.id.Compressor, len(s.in), s.id.UncompressedSize, c.AllocBytes)
		}
	}

	// GREEN 2: a genuine high-ratio zstd bomb (tiny frame, ~60 MiB real output)
	// must PASS — the decompressor correctly allocates ~output, proportional to
	// the sizeKey. (The absolute 60 MiB is a HARDENING concern handled in prose,
	// not a disproportion this oracle flags.)
	const bombOut = 60 << 20
	bomb := genuineBomb(t, wiremessage.CompressorZstd, bombOut)
	if len(bomb.in) > bombOut/500 {
		t.Fatalf("expected the zstd bomb frame to be tiny relative to %d, got %d bytes", bombOut, len(bomb.in))
	}
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green2 := measureDecompress(t, pg, bomb.in, bomb.id)
	if b.Check(func(string, ...any) {}, green2) {
		t.Fatalf("genuine high-ratio bomb must PASS (alloc ~= output): alloc=%d out=%d", green2.AllocBytes, bombOut)
	}

	// RED: a planted 50×-output allocation on a ~1 MiB moderate frame must trip.
	rin, rus := encodeFor(t, wiremessage.CompressorZstd, moderate(1<<20))
	ropts := driver.CompressionOpts{Compressor: wiremessage.CompressorZstd, UncompressedSize: rus}
	pr := resguard.New(t, resguard.Options{SampleEvery: 1})
	rc := pr.Measure(sizeKey(rin, rus), func() {
		overAllocDecode(rin, ropts, 50)
	})
	overAllocDecodeSink = nil
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, rc)
	if !fired {
		t.Fatalf("planted 50x-output over-allocation (output key %d, alloc %d) did not trip the budget", sizeKey(rin, rus), rc.AllocBytes)
	}
	t.Logf("RED tripped as expected (50x-output plant, alloc %d): %s", rc.AllocBytes, msg)
}

// seedDecompress adds benign frames (one per codec/size) and the empty input.
// It deliberately does NOT seed a bomb frame: seeding an amplifier would assert
// "an amplifier must pass", contradicting the oracle.
func seedDecompress(f *testing.F) {
	f.Add(uint8(0), []byte(nil))
	f.Add(uint8(0), []byte("not compressed"))
	for i, id := range mongoCompressors {
		in, _ := encodeFor(f, id, moderate(256))
		f.Add(uint8(i), in)
	}
}
