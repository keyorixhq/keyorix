package libconformance

import (
	"runtime"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzCOSEKeyBoundedWork transfers the length-bomb + OOB/never-panic classes to
// the COSE-key decode boundary in go-webauthn: webauthncose.ParsePublicKey. This
// is the CBOR→crypto-key seam — ParsePublicKey CBOR-decodes a raw COSE_Key map and
// then pulls fixed/length-prefixed coordinate byte strings (EC2 X/Y, RSA N/E,
// OKP X) out of it. It is reached whenever go-webauthn verifies an authenticator
// signature (webauthncose.VerifySignature → ParsePublicKey) during the WebAuthn
// ceremony-finish handlers (server/http/handlers/webauthn.go), on browser-supplied
// bytes, pre-auth. The ceremony-level parse is already fuzzed
// (webauthnparse.FuzzWebAuthnCredentialResponse / *Ceremony); this target drills
// DIRECTLY into the COSE decode so a panic/amplification there is attributed to
// the key decoder rather than buried in the whole verify.
//
// Oracle (same shape as the pkcs7 bounded-work targets):
//   - fuzzutil.Guard bounds TIME; a panic inside ParsePublicKey propagates and is
//     recorded natively — so this is ALSO the never-panic oracle for COSE decode.
//   - the allocation check bounds MEMORY: TotalAlloc must stay within
//     64 MiB + 4 KiB·N. The underlying CBOR decode inherits the default DecMode
//     caps, so the EXPECTED result is that this passes.
//
// What this does NOT verify:
//   - Nothing about key VALIDITY — not that a well-formed EC2/RSA/OKP key is
//     accepted, not any signature-verification property. Only bounded work +
//     no panic on the decode.
//   - ParsePublicKey is reached THROUGH go-webauthn's verify, which first routes
//     via the ceremony parser; this target calls it directly, so an input that
//     ParsePublicKey tolerates but the ceremony layer would reject earlier is
//     still exercised here (wider than the live path — a hit must be traced back
//     through VerifySignature before any Keyorix reachability claim).
//   - It does not cover ParseFIDOPublicKey (U2F/FIDO raw key) — a sibling decoder
//     on a different, non-CBOR wire shape; out of scope for the CBOR class.
func FuzzCOSEKeyBoundedWork(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa0}) // empty COSE map
	// A minimal-ish EC2 COSE key skeleton (kty=2, alg=-7, crv=1, x, y):
	f.Add([]byte{
		0xa5,
		0x01, 0x02, // kty: EC2
		0x03, 0x26, // alg: ES256
		0x20, 0x01, // crv: P-256
		0x21, 0x40, // x: empty bstr
		0x22, 0x40, // y: empty bstr
	})
	// Length-bomb heads smuggled as the COSE map itself:
	f.Add([]byte{0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})             // map, 2^64-1 pairs
	f.Add([]byte{0xa1, 0x21, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // x coord, bstr 2^64-1

	f.Fuzz(func(t *testing.T, data []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		fuzzutil.Guard(t.Fatalf, "webauthncose.ParsePublicKey", func() {
			_, _ = webauthncose.ParsePublicKey(data) // result discarded; time+memory are the property
		})

		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(64<<20) + uint64(4096)*uint64(len(data))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: webauthncose.ParsePublicKey allocated %d bytes for a %d-byte input (limit %d) — length-bomb/amplification regression",
				alloc, len(data), limit)
		}
	})
}
