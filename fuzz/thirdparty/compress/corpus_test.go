package compresshostile

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
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

// benignSamples is the deterministic benign corpus used for calibration and as
// the GREEN cases: every codec over several realistic sizes, plus one
// legitimately-large low-compressibility reply per codec.
func benignSamples(tb testing.TB) []struct {
	id driver.CompressionOpts
	in []byte
} {
	tb.Helper()
	type sample = struct {
		id driver.CompressionOpts
		in []byte
	}
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

func measureDecompress(tb testing.TB, p *resguard.Probe, in []byte, opts driver.CompressionOpts) resguard.Cost {
	tb.Helper()
	return p.Measure(len(in), func() {
		_, _ = driver.DecompressPayload(in, opts)
	})
}

// calibrateCompress derives a slope budget from the benign corpus. The alloc
// meters stay on the DEFAULT per-byte slope (NOT UseAbsolute): the bomb shape
// here is tiny-input/huge-output, so alloc-per-input-byte is the right
// discriminator (a real large reply carries a proportionally large compressed
// frame). See decompress_fuzz_test.go for what this does NOT verify.
func calibrateCompress(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, s := range benignSamples(tb) {
		// Measure each benign sample a few times to average GC/alloc noise into p99.
		for range 3 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, measureDecompress(tb, p, s.in, s.id))
		}
	}
	return resguard.Calibrate("mongo_decompress_payload", costs, resguard.DefaultFactor)
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

// snappyBombFrame hand-crafts a tiny snappy block whose header varint DECLARES
// declaredLen uncompressed bytes but carries only a few literal bytes — the
// decompression-bomb shape. driver.DecompressPayload reads snappy.DecodedLen
// (the header), make([]byte, declaredLen), THEN snappy.Decode (which errors on
// the short body) — so the big allocation already happened. Used as the RED case.
func snappyBombFrame(declaredLen int) []byte {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(declaredLen))
	// one literal tag for 1 byte: tag = (len-1)<<2 | 0x00 ; len=1 -> 0x00, then 1 data byte.
	return append(append([]byte{}, hdr[:n]...), 0x00, 'a')
}

// TestResguardCompressRedGreen is the committed red/green proof. GREEN: every
// benign sample passes the calibrated budget. RED: a ~6-byte snappy frame
// declaring safeMaxOut (64 MiB) uncompressed trips the alloc budget — the
// amplifier is attacker INPUT, so no production code is modified.
func TestResguardCompressRedGreen(t *testing.T) {
	b := calibrateCompress(t)

	// GREEN: no benign sample may trip the budget.
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

	// RED: the snappy header bomb.
	bomb := snappyBombFrame(safeMaxOut)
	opts, ok := buildOpts(wiremessage.CompressorSnappy, 0, bomb)
	if !ok {
		t.Fatalf("snappy bomb frame was not drivable (declaredLen must be <= safeMaxOut=%d)", safeMaxOut)
	}
	if opts.UncompressedSize != safeMaxOut {
		t.Fatalf("expected declared size %d, got %d", safeMaxOut, opts.UncompressedSize)
	}
	p := resguard.New(t, resguard.Options{SampleEvery: 1})
	red := measureDecompress(t, p, bomb, opts)
	if red.AllocBytes < 8<<20 {
		t.Fatalf("expected the snappy bomb to allocate megabytes, got alloc=%d (input %d bytes)", red.AllocBytes, len(bomb))
	}
	var msg string
	fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red)
	if !fired {
		t.Fatalf("snappy header bomb (input %d bytes -> alloc %d) did not trip the budget", len(bomb), red.AllocBytes)
	}
	t.Logf("RED tripped as expected (input %d bytes -> alloc %d): %s", len(bomb), red.AllocBytes, msg)
}

// seedDecompress adds benign frames (one per codec/size) and the empty input.
// It deliberately does NOT seed a bomb frame: seeding an amplifier would assert
// "an amplifier must pass", contradicting the oracle.
func seedDecompress(f *testing.F) {
	f.Add(uint8(0), int32(0), []byte(nil))
	f.Add(uint8(0), int32(0), []byte("not compressed"))
	for i, id := range mongoCompressors {
		in, us := encodeFor(f, id, moderate(256))
		f.Add(uint8(i), us, in)
	}
}
