package pqwrap

import (
	"bytes"
	"testing"
)

// TestDeriveWrapKey_BindsEveryComponent is the acceptance test for Andrei's
// Q2 condition (pq-key-wrapping.md §4): the wrap key depends on BOTH shared
// secrets, BOTH KEM ciphertexts, BOTH recipient public keys and the header.
// Changing any one input alone must change the derived key. If a ciphertext
// or a public key is ever dropped from the transcript, its row fails here.
func TestDeriveWrapKey_BindsEveryComponent(t *testing.T) {
	for _, s := range allSuites {
		t.Run(s.String(), func(t *testing.T) {
			pub := testKey(t, s, "bind").PublicKey()
			other := testKey(t, s, "bind-other").PublicKey()
			ctM := bytes.Repeat([]byte{0x11}, suites[s].ctSize)
			in := bindInputs{
				header: (&Envelope{Version: Version, Suite: s, Purpose: PurposeDEK, KeyID: pub.id}).header(),
				ctX:    bytes.Repeat([]byte{0x22}, x25519Size),
				ctM:    ctM,
				pub:    pub,
				ssM:    bytes.Repeat([]byte{0x33}, 32),
				ssX:    bytes.Repeat([]byte{0x44}, 32),
			}
			base := in.derive(t)

			flip := func(b []byte) []byte { c := bytes.Clone(b); c[len(c)-1] ^= 1; return c }
			flipAt := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }
			withX := *pub
			withX.x = other.x
			withEK := *pub
			withEK.mlkemEK = other.mlkemEK
			cases := map[string]func(bindInputs) bindInputs{
				"ML-KEM ciphertext":    func(b bindInputs) bindInputs { b.ctM = flip(b.ctM); return b },
				"X25519 ciphertext":    func(b bindInputs) bindInputs { b.ctX = flip(b.ctX); return b },
				"X25519 recipient key": func(b bindInputs) bindInputs { b.pub = &withX; return b },
				"ML-KEM recipient key": func(b bindInputs) bindInputs { b.pub = &withEK; return b },
				"ML-KEM shared secret": func(b bindInputs) bindInputs { b.ssM = flip(b.ssM); return b },
				"X25519 shared secret": func(b bindInputs) bindInputs { b.ssX = flip(b.ssX); return b },
				// One case per header field, each flipping a byte inside that field.
				"header (magic)":   func(b bindInputs) bindInputs { b.header = flipAt(b.header, 0); return b },
				"header (version)": func(b bindInputs) bindInputs { b.header = flipAt(b.header, offVersion); return b },
				"header (suite)":   func(b bindInputs) bindInputs { b.header = flipAt(b.header, offSuite+1); return b },
				"header (purpose)": func(b bindInputs) bindInputs { b.header = flipAt(b.header, offPurpose); return b },
				"header (key id)":  func(b bindInputs) bindInputs { b.header = flipAt(b.header, offKeyID); return b },
			}
			for name, mutate := range cases {
				if got := mutate(in).derive(t); bytes.Equal(got, base) {
					t.Errorf("changing the %s alone did not change the wrap key: it is not bound", name)
				}
			}
		})
	}
}

type bindInputs struct {
	header, ctX, ctM []byte
	pub              *PublicKey
	ssM, ssX         []byte
}

func (b bindInputs) derive(t *testing.T) []byte {
	t.Helper()
	wk, _, err := deriveWrapKey(b.header, b.ctX, b.ctM, b.pub, b.ssM, b.ssX)
	if err != nil {
		t.Fatal(err)
	}
	return wk
}
