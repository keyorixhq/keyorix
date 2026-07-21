package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/keyorixhq/keyorix/internal/trust"
)

// FuzzBundleVerify feeds arbitrary byte streams into Verify. The goal is the
// streaming gzip+tar parse path, the manifest JSON unmarshaller, the signature
// check, and the per-component digest walk — all must return errors on corrupt
// input, never panic. A real key pair is registered so the verifier reaches the
// signature-check layer rather than bailing at registry setup; a tampered
// signature is expected to fail closed with ErrBadSignature.
func FuzzBundleVerify(f *testing.F) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	reg := trust.NewRegistry()
	if err := reg.Add(trust.PurposeUpdate, "fuzz-key-1", pub); err != nil {
		f.Fatal(err)
	}

	f.Add([]byte{})
	f.Add([]byte("not a gzip bundle"))
	// Minimal valid gzip stream (empty content) — lets the mutator start from a
	// structurally recognisable gzip frame rather than random bytes.
	f.Add([]byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic.
		_, _ = Verify(bytes.NewReader(data), reg)
	})
}
