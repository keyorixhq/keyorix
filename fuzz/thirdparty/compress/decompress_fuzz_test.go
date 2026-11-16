// Package compresshostile fuzzes the real decompression sink the MongoDB
// dynamic-secrets engine reaches: go.mongodb.org/mongo-driver/v2's
// driver.DecompressPayload, which pre-allocates opts.UncompressedSize bytes
// (int32, attacker-controlled when a server sends OP_COMPRESSED) BEFORE any
// integrity check completes, across all three compressor branches
// (snappy / zlib / zstd). This is the classic memory-amplification shape:
// a few-byte frame declaring a huge uncompressed size allocates that much up
// front. klauspost/compress/{zstd,s2,snappy} are the codecs behind two of
// those branches and are pulled into the build only through this driver.
//
// Reachability (traced, honest): internal/dynamic/mongodb.go connectMongo ->
// options.Client().ApplyURI(adminDSN) -> mongo.Connect. The driver calls
// DecompressPayload on a reply only when compression was negotiated, which the
// driver advertises only if adminDSN carries `compressors=`. So the path is
// reachable but CONDITIONAL on (a) a MongoDB dynamic-secrets engine, (b) its
// adminDSN opting into compression, (c) a malicious/compromised Mongo server.
// Non-default; a trust-boundary crossing. See lf1-REPORT.md.
package compresshostile

import (
	"testing"

	"github.com/klauspost/compress/snappy"
	driver "go.mongodb.org/mongo-driver/v2/x/mongo/driver"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/wiremessage"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// safeMaxOut clamps every UncompressedSize the harness actually drives into
// DecompressPayload so the FUZZER cannot OOM itself or the shared host (the
// mongodb target clamps declared lengths for the same reason). 64 MiB is still
// vastly out of proportion to the few-byte inputs that reach it, so the
// amplification oracle still fires; two -parallel workers cap transient use at
// ~128 MiB. The real driver has NO such clamp (int32, up to ~2 GiB) — that is
// the hardening gap this target documents, not a property of this ceiling.
const safeMaxOut = 1 << 26

const budgetPath = "testdata/resguard.json"

// mongoCompressors is the set of codec branches DecompressPayload implements.
var mongoCompressors = []wiremessage.CompressorID{
	wiremessage.CompressorSnappy,
	wiremessage.CompressorZLib,
	wiremessage.CompressorZstd,
}

// buildOpts constructs the CompressionOpts the harness drives for a given codec
// and raw fuzzer-chosen size, CLAMPED to safeMaxOut. For snappy the branch
// requires UncompressedSize == snappy.DecodedLen(in) or it errors before
// allocating, so the harness mirrors a real crafted frame by reading the
// block's own declared length; if that length is unreadable or over the clamp
// the input is undrivable for snappy (reported ok=false) — this never weakens
// the oracle, it only keeps the fuzzer bounded. For zlib/zstd the size is
// independent of `in`, exactly as the attacker controls it, so it is just
// clamped.
func buildOpts(id wiremessage.CompressorID, rawSize int32, in []byte) (driver.CompressionOpts, bool) {
	opts := driver.CompressionOpts{Compressor: id}
	switch id {
	case wiremessage.CompressorSnappy:
		l, err := snappy.DecodedLen(in)
		if err != nil || l < 0 || l > safeMaxOut {
			return opts, false
		}
		opts.UncompressedSize = int32(l)
	default: // zlib, zstd: size independent of input
		s := rawSize
		if s < 0 {
			s = -s // keep it non-negative; the driver rejects <0 itself
		}
		if s > safeMaxOut {
			s = safeMaxOut
		}
		opts.UncompressedSize = s
	}
	return opts, true
}

// FuzzMongoDecompressPayload meters every decode and fails one whose allocation
// is wildly disproportionate to the compressed input it was driven with — the
// decompression-bomb / UncompressedSize-preallocation shape. The alloc meters
// run on the DEFAULT per-byte slope (ModeSlope): the attack here is "tiny input,
// huge output", so alloc-per-input-byte is the discriminating signal (a real
// large reply has a proportionally large compressed frame; a bomb does not).
// A native panic inside the codec is caught by the fuzzer.
//
// What this oracle does NOT verify: (1) it does not bound ABSOLUTE memory — a
// legitimate multi-MiB reply is allowed; it flags only disproportion to input;
// (2) its sensitivity is set by the calibration corpus's compression ratio
// (testdata/resguard.json) — a corpus of highly-compressible seeds would raise
// PerByte and blunt it, so the corpus uses realistic (ratio ~1–6x) payloads;
// (3) it does not assert decode CORRECTNESS (round-trip owns that); (4) it does
// not model the OP_COMPRESSED wire framing (FuzzMongoReply owns wire parsing) —
// it drives the decompressor directly with (codec, size, bytes).
func FuzzMongoDecompressPayload(f *testing.F) {
	seedDecompress(f)

	budget, err := resguard.LoadBudget(budgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardCompressCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", budgetPath)
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, codecSel uint8, rawSize int32, in []byte) {
		id := mongoCompressors[int(codecSel)%len(mongoCompressors)]
		opts, ok := buildOpts(id, rawSize, in)
		if !ok {
			return
		}
		var out []byte
		var derr error
		c := p.Measure(len(in), func() {
			fuzzutil.Guard(t.Fatalf, "driver.DecompressPayload", func() {
				out, derr = driver.DecompressPayload(in, opts)
			})
		})
		_ = out
		_ = derr
		resguard.FeedCoverage(c)
		if haveBudget {
			budget.Check(t.Fatalf, c)
		}
		if r := p.CheckDrift(c); r != "" {
			t.Fatal(r)
		}
	})
}
