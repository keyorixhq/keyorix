package libconformance

import (
	"runtime"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzCBORBoundedWork transfers the digitorus/pkcs7 BER length-bomb /
// memory-amplification bug class to fxamacker/cbor/v2 — the CBOR codec Keyorix
// reaches INDIRECT-ONLY: it has no direct Keyorix import, but go-webauthn
// CBOR-decodes the browser-supplied attestationObject / authenticatorData / COSE
// keys at the WebAuthn ceremony-finish endpoints (server/http/handlers/webauthn.go),
// pre-auth. CBOR is the format most exposed to this class: a major-type-4/5 head
// can declare an array/map of up to 2^64-1 elements, an indefinite-length chain
// can nest arbitrarily deep, and a tag-2/3 head can declare an arbitrarily large
// bignum — all in a handful of input bytes.
//
// Oracle (identical shape to FuzzDigitorusPKCS7BoundedWork, intentionally):
//   - fuzzutil.Guard bounds TIME (a hang / super-linear decode fails the target).
//     A panic inside Unmarshal propagates and is recorded by the fuzzer natively —
//     so this target is ALSO the never-panic oracle for cbor decode.
//   - the allocation check bounds MEMORY: TotalAlloc during Unmarshal must stay
//     within 64 MiB + 4 KiB·N of the input size. A naive decoder that did
//     make([]any, declaredCount) for a 9-byte "array of 2^64-1" head would blow
//     three orders of magnitude past this instantly.
//
// We decode with cbor.Unmarshal (the DEFAULT DecMode). go-webauthn does NOT use
// that mode: v0.18.2 decodes via webauthncbor.Unmarshal, whose ctap2CBORDecMode is
// stricter (MaxNestedLevels=5, indefinite length and tags forbidden,
// DupMapKeyEnforcedAPF). The default mode is therefore a conservative superset of
// the live one. It ships hard caps (MaxNestedLevels=32, MaxArrayElements=131072,
// MaxMapPairs=131072), so the EXPECTED result today is that this passes: the
// oracle confirms those caps hold, and only fires if a future bump removes them.
//
// What this does NOT verify:
//   - Nothing about the decoded VALUE — not that a valid COSE key / attestation
//     round-trips, not any WebAuthn semantic. Only the upper bound on work.
//   - It does not fuzz webauthncbor.Unmarshal (the live mode) directly; if
//     go-webauthn adopted a DecMode with raised limits, THIS target (default mode)
//     would still pass while the real path regressed. The claim is only "the live
//     mode is stricter than the default mode TODAY" — re-verify on a go-webauthn bump.
//   - It bounds per-input work only. It does NOT bound aggregate memory across
//     many concurrent requests (that is the server's connection/body-size limit's
//     job, not the codec's), and it does not model the streaming cbor.Decoder.
//   - The 64 MiB floor means a sub-threshold amplification (e.g. 10x on a 1 MiB
//     input) would pass; it catches catastrophic amplification, not constant
//     factors.
func FuzzCBORBoundedWork(f *testing.F) {
	// Length-bomb heads (should all be rejected cheaply by the default caps):
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // array, count 2^64-1
	f.Add([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // map, pairs 2^64-1
	f.Add([]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // byte string, len 2^64-1
	f.Add([]byte{0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // text string, len 2^64-1
	// Deep nesting via indefinite-length arrays (0x9f ... ), 40 deep (> cap 32):
	deep := make([]byte, 0, 80)
	for range 40 {
		deep = append(deep, 0x9f) // indefinite array start
	}
	for range 40 {
		deep = append(deep, 0xff) // break
	}
	f.Add(deep)
	// tag 2 (positive bignum) with a huge declared byte-string payload:
	f.Add([]byte{0xc2, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xa0})             // empty map
	f.Add([]byte{0x80})             // empty array
	f.Add([]byte{0xf9, 0x7e, 0x00}) // NaN (float16)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		fuzzutil.Guard(t.Fatalf, "cbor.Unmarshal(any)", func() {
			var v any
			_ = cbor.Unmarshal(data, &v) // result discarded; time+memory are the property
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(data))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: cbor.Unmarshal allocated %d bytes for a %d-byte input (limit %d) — length-bomb/amplification regression",
				alloc, len(data), limit)
		}
	})
}
