package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParsePrivateKeyPEM fuzzes ParsePrivateKeyPEM, which turns PEM bytes into the
// ed25519 signing key used to sign air-gap bundles. The input is operator-supplied
// key material rather than a live attacker channel, but PEM/x509 (PKCS#8) parsing
// of malformed bytes is a classic panic/OOB surface, and a corrupt or truncated
// key file must fail cleanly at startup, not crash the signer.
//
// Invariants: (a) never panics; (b) on error the returned key is nil (never a
// usable-looking but wrong key); (c) on success the key is exactly
// ed25519.PrivateKeySize bytes, so a caller can sign with it without a length
// check. A valid generated key is seeded so the success path is exercised.
func FuzzParsePrivateKeyPEM(f *testing.F) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		f.Fatal(err)
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	seeds := [][]byte{
		nil,
		[]byte(""),
		[]byte("not pem at all"),
		[]byte("-----BEGIN PRIVATE KEY-----\nbm90IGJhc2U2NA==\n-----END PRIVATE KEY-----\n"), // PEM, garbage body
		[]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"),                   // empty body
		validPEM,                              // genuine ed25519 PKCS#8 key
		validPEM[:len(validPEM)-20],           // truncated valid key
		append([]byte("junk\n"), validPEM...), // leading junk before the block
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		var key ed25519.PrivateKey
		var perr error
		fuzzutil.Guard(t.Fatalf, "ParsePrivateKeyPEM", func() {
			key, perr = ParsePrivateKeyPEM(b)
		})
		if perr != nil {
			if key != nil {
				t.Fatalf("ParsePrivateKeyPEM returned an error but a non-nil key (len=%d) for %q: %v", len(key), b, perr)
			}
			return
		}
		if len(key) != ed25519.PrivateKeySize {
			t.Fatalf("ParsePrivateKeyPEM returned a key of length %d, want %d, for %q", len(key), ed25519.PrivateKeySize, b)
		}
	})
}
