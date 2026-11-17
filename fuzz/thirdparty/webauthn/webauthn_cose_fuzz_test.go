// Reachability-first fuzz harness for go-webauthn's COSE public-key parser, the
// path Keyorix uses to classify a WebAuthn credential's public key.
//
// Live caller (traced from reachgen, prov=request-body):
//   - internal/cryptoinventory/webauthn.go:47 ClassifyWebAuthnKey
//     -> webauthncose.ParsePublicKey(coseKey)
//     `coseKey` is a COSE-encoded (CBOR) public key that originated from a
//     WebAuthn registration ceremony (attacker-supplied at credential creation)
//     and is later re-parsed from storage for the crypto inventory. It is
//     untrusted, variable-length binary input to a CBOR decoder.
//
// Oracle (sound bounded-work + no-panic): ParsePublicKey on arbitrary bytes
//   - must not panic, and
//   - must return within a generous wall-clock bound (a CBOR decoder that
//     honoured a hostile "array of 2^53 elements" header without a limit would
//     blow this). CBOR limits in fxamacker/cbor should keep this green; the
//     oracle is here to notice if that ever regresses.
//
// What this oracle does NOT verify:
//   - NOT that a returned key is cryptographically valid or usable.
//   - NOT ParsePublicKey's ACCEPT/REJECT policy (which COSE types/curves are
//     allowed — ClassifyWebAuthnKey layers that on top, untested here).
//   - NOT allocation volume directly: it bounds TIME, not bytes allocated, so a
//     parser that allocates a lot but quickly would pass. True infinite hangs
//     are caught by `go test`'s own per-input fuzz timeout, not this assertion.
//   - NOT the surrounding AKP/ML-DSA branch in webauthn.go (that is Keyorix
//     code, not this third-party entry point).
package webauthnhostile

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// parseDeadline bounds a single parse. Generous on purpose: we are catching a
// pathological (seconds-long) decode, not microbenchmarking. The red-proof
// lowers this in a scratch copy to watch the bound fire on a normal input.
const parseDeadline = 2 * time.Second

func FuzzWebAuthnParsePublicKey(f *testing.F) {
	// Minimal CBOR maps as seeds (not valid COSE keys; parser rejects cleanly).
	f.Add([]byte{0xa0})             // empty CBOR map
	f.Add([]byte{0xa1, 0x01, 0x02}) // {1: 2}
	f.Add([]byte{})
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // array w/ huge declared length

	f.Fuzz(func(t *testing.T, data []byte) {
		// Cap input so a legitimately-large (but valid) buffer doesn't make the
		// parse slow for an uninteresting reason; real COSE keys are small.
		if len(data) > 1<<16 {
			data = data[:1<<16]
		}
		start := time.Now()
		_, _ = parseKey(data) // return ignored: reject is fine; we assert no panic + bounded time
		if elapsed, _ := fuzzutil.EffectiveElapsed(start); elapsed > parseDeadline {
			t.Fatalf("ParsePublicKey took %v (> %v) on %d bytes — unbounded work", elapsed, parseDeadline, len(data))
		}
	})
}

// parseKey is factored out so the red-proof can plant a defect here in a scratch
// copy (e.g. `time.Sleep(parseDeadline * 2)` for a marker input) and watch the
// bounded-work assertion fire while the unmodified path stays green.
func parseKey(data []byte) (any, error) {
	return webauthncose.ParsePublicKey(data)
}
