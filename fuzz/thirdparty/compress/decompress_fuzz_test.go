// Package compresshostile fuzzes the real decompression sink the MongoDB
// dynamic-secrets engine reaches: go.mongodb.org/mongo-driver/v2's
// driver.DecompressPayload (snappy / zlib / zstd branches). klauspost/compress/
// {zstd,s2,snappy} are the codecs behind two of those branches and are pulled
// into the build only through this driver.
//
// Reachability (traced, honest): internal/dynamic/mongodb.go connectMongo ->
// options.Client().ApplyURI(adminDSN) -> mongo.Connect. The driver calls
// DecompressPayload on a reply only when compression was negotiated, which the
// driver advertises only if adminDSN carries `compressors=`. So the path is
// reachable but CONDITIONAL on (a) a MongoDB dynamic-secrets engine, (b) its
// adminDSN opting into compression, (c) a malicious/compromised Mongo server.
// Non-default; a trust-boundary crossing. See lf1-REPORT.md.
//
// DESIGN NOTE — why UncompressedSize is derived, not fuzzed. DecompressPayload's
// documented contract is "allocate opts.UncompressedSize bytes": feeding it an
// arbitrary huge size and observing a huge allocation tests nothing about the
// library — it is the caller asking for that memory (that mismatch, i.e. the
// mongo driver reading UncompressedSize off the wire WITHOUT bounding it against
// the real message, is a wire-layer concern that FuzzMongoReply owns, and is
// written up as a HARDENING item in the report, not fuzzed here). To make a SOUND
// decompression-bomb oracle, the harness derives UncompressedSize from the
// GENUINE decoded length of `in` (bounded by safeMaxOut), so the only way an
// allocation becomes disproportionate to the compressed input is a real
// high-compression-ratio bomb intrinsic to the bytes — a small frame that
// legitimately expands to a large output, exactly the zip-bomb a malicious
// server would send.
package compresshostile

import (
	"bytes"
	"compress/zlib"
	"io"
	"testing"

	"github.com/klauspost/compress/snappy"
	"github.com/klauspost/compress/zstd"
	driver "go.mongodb.org/mongo-driver/v2/x/mongo/driver"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/wiremessage"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// safeMaxOut clamps the GENUINE decoded size the harness will drive into
// DecompressPayload so the FUZZER cannot OOM itself or the shared host. 64 MiB
// is still vastly out of proportion to the few-byte inputs that reach it, so a
// real high-ratio bomb still trips the oracle; two -parallel workers cap
// transient use at a few hundred MiB. The real driver has NO such clamp
// (UncompressedSize is int32, up to ~2 GiB) — that larger ceiling is the
// hardening gap the report documents, not a property of this test ceiling.
const safeMaxOut = 1 << 26

const budgetPath = "testdata/resguard.json"

// mongoCompressors is the set of codec branches DecompressPayload implements.
var mongoCompressors = []wiremessage.CompressorID{
	wiremessage.CompressorSnappy,
	wiremessage.CompressorZLib,
	wiremessage.CompressorZstd,
}

// zstdDec is a shared stateless decoder with the memory ceiling the harness
// relies on, used only to learn the genuine decoded length of `in`.
var zstdDec = func() *zstd.Decoder {
	d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(safeMaxOut+1))
	if err != nil {
		panic(err)
	}
	return d
}()

// genuineDecodedLen decodes `in` with the matching codec OUTSIDE the measured
// region, bounded by safeMaxOut, and returns the TRUE decompressed length. ok is
// false when `in` is not a valid frame for the codec or decompresses to more
// than safeMaxOut (undrivable within the fuzzer's safety clamp) — neither
// weakens the oracle, it only keeps the fuzzer bounded. This is the honest size
// the driver's make([]byte, …) would legitimately need for this exact `in`.
func genuineDecodedLen(id wiremessage.CompressorID, in []byte) (int32, bool) {
	switch id {
	case wiremessage.CompressorSnappy:
		out, err := snappy.Decode(nil, in)
		if err != nil || len(out) > safeMaxOut {
			return 0, false
		}
		return int32(len(out)), true
	case wiremessage.CompressorZLib:
		r, err := zlib.NewReader(bytes.NewReader(in))
		if err != nil {
			return 0, false
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, safeMaxOut+1))
		_ = r.Close()
		if err != nil || n > safeMaxOut {
			return 0, false
		}
		return int32(n), true
	case wiremessage.CompressorZstd:
		out, err := zstdDec.DecodeAll(in, nil)
		if err != nil || len(out) > safeMaxOut {
			return 0, false
		}
		return int32(len(out)), true
	default:
		return 0, false
	}
}

// sizeKey is the "work" an input represents: the larger of the compressed input
// and the genuine decompressed output. The budget is keyed to THIS, not to the
// input length, because a decompressor is SUPPOSED to allocate ~output bytes —
// keying to input would flag every high-ratio frame (ordinary compression) as a
// bomb. Keyed to output, the oracle instead verifies the useful property: the
// decode's allocation and malloc COUNT stay PROPORTIONAL to the output, so a
// hidden super-linear blow-up (alloc ≫ output, or a per-byte allocation storm)
// trips while a legitimate high-ratio frame — alloc ≈ output — passes.
func sizeKey(in []byte, us int32) int {
	if int(us) > len(in) {
		return int(us)
	}
	return len(in)
}

// FuzzMongoDecompressPayload drives the real driver sink for each codec branch
// and asserts two things: it never panics / hangs (fuzzutil.Guard), and its
// allocation stays proportional to the genuine decompressed OUTPUT (the resguard
// alloc/malloc slope budget keyed to sizeKey). UncompressedSize is derived from
// the true decoded length of `in` (bounded by safeMaxOut), never fuzzed, so the
// only amplification an input can express is intrinsic to the bytes.
//
// What this oracle does NOT verify: (1) it does NOT bound ABSOLUTE memory — a
// malicious server CAN still force an allocation up to the genuine output size
// (up to the driver's int32 ceiling, ~2 GiB, in production); that absence of a
// decompressed-size CAP in driver.DecompressPayload is a real HARDENING item
// written up in the report, NOT something this target can "trip" because
// allocating the output you asked to decompress is the decompressor's correct
// contract. (2) It does not flag ordinary high compression ratios (that is not a
// defect). (3) It does not assert decode CORRECTNESS (FuzzSnappyRoundTrip owns
// that). (4) It does not model OP_COMPRESSED wire framing (FuzzMongoReply owns
// that). (5) live_heap/drift are deliberately excluded (pooled decoder buffers
// make absolute live-heap a non-signal here) — only the per-input alloc delta is
// fatal.
func FuzzMongoDecompressPayload(f *testing.F) {
	seedDecompress(f)

	budget, err := resguard.LoadBudget(budgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardCompressCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", budgetPath)
	}
	p := resguard.New(f, resguard.Options{SampleEvery: 16})

	f.Fuzz(func(t *testing.T, codecSel uint8, in []byte) {
		id := mongoCompressors[int(codecSel)%len(mongoCompressors)]
		us, ok := genuineDecodedLen(id, in)
		if !ok {
			return // not a valid frame for this codec, or over the safety clamp
		}
		opts := driver.CompressionOpts{Compressor: id, UncompressedSize: us}
		var out []byte
		var derr error
		c := p.Measure(sizeKey(in, us), func() {
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
		// NOTE: CheckDrift is deliberately NOT called here. It rides on the
		// absolute live heap, which the pooled zstd decoder keeps elevated across
		// inputs (large retained internal buffers) — a sustained-high reading that
		// is an artefact of pooling, not a per-input leak. The per-input alloc
		// delta budget above is the sound signal for this target.
	})
}
