package libconformance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"
)

// findCipherValue returns the first <CipherValue> descendant (namespace-agnostic).
func findCipherValue(el *etree.Element) *etree.Element {
	if el.Tag == "CipherValue" {
		return el
	}
	for _, c := range el.ChildElements() {
		if r := findCipherValue(c); r != nil {
			return r
		}
	}
	return nil
}

var wsStripper = strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "")

// FuzzXMLEncGCMIntegrity asserts the authentication-integrity property of crewjam/saml/xmlenc
// on its AUTHENTICATED cipher (AES-GCM), the one used for EncryptedAssertion in SAML SSO:
// a ciphertext that has been altered in any way must NEVER decrypt successfully. Any single
// byte flipped in the ciphertext must make Decrypt return an error, never plaintext — because
// GCM authenticates, and forging a valid tag is infeasible. A success here is an authenticated
// -encryption bypass: an attacker-tampered EncryptedAssertion accepted as genuine.
//
// This is deliberately scoped to GCM. The CBC path in xmlenc is UNauthenticated, so its
// padding behaviour is a padding oracle by construction (the mitigation is architectural — the
// outer XML-DSig signature — not a lib bug), and asserting "no padding oracle" on raw CBC
// Decrypt would false-positive on correct code. Soundness first: we assert only the direction
// that holds for a correct authenticated cipher — tampered ⇒ reject.
func FuzzXMLEncGCMIntegrity(f *testing.F) {
	key := []byte("abcdefghijklmnop") // AES-128
	nonce := []byte("0123456789ab")   // 12-byte GCM nonce
	plaintext := []byte("<x>top secret keyorix assertion</x>")

	// Reuse the lib's Encrypt for the correct element STRUCTURE (namespaces, algorithm URI,
	// CipherData/CipherValue), then overwrite CipherValue with a correctly-built ciphertext:
	// nonce‖Seal(...), which is what real IdP GCM assertions carry and what xmlenc.Decrypt
	// reads back (it takes the first NonceSize bytes as the nonce). crewjam v0.5.1's own
	// GCM.Encrypt is broken — it seals a zero buffer (discarding the plaintext) and prepends no
	// nonce — so its encrypt/decrypt don't round-trip; we don't rely on it for the ciphertext
	// bytes. (Reported upstream separately; keyorix only decrypts, so it's unaffected.)
	el, err := xmlenc.AES128GCM.Encrypt(key, plaintext, nonce)
	if err != nil {
		f.Fatalf("build fixture: encrypt (structure): %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Fatalf("build fixture: aes: %v", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		f.Fatalf("build fixture: gcm: %v", err)
	}
	sealed := aesgcm.Seal(nil, nonce, plaintext, nil)
	cipherBytes := append(append([]byte{}, nonce...), sealed...) // nonce ‖ ciphertext‖tag
	if cv := findCipherValue(el); cv != nil {
		cv.SetText(base64.StdEncoding.EncodeToString(cipherBytes))
	} else {
		f.Fatalf("build fixture: no CipherValue in encrypted element")
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	fixture, err := doc.WriteToBytes()
	if err != nil {
		f.Fatalf("build fixture: serialise: %v", err)
	}
	// Baseline sanity: the untampered fixture must decrypt back to the plaintext.
	{
		d := etree.NewDocument()
		if e := d.ReadFromBytes(fixture); e != nil {
			f.Fatalf("build fixture: reparse: %v", e)
		}
		got, e := xmlenc.Decrypt(key, d.Root())
		if e != nil || !bytes.Equal(got, plaintext) {
			f.Fatalf("build fixture: baseline decrypt mismatch (err=%v got=%q)", e, got)
		}
	}

	f.Add([]byte{0x01})
	f.Add([]byte{0x05, 0xff})

	f.Fuzz(func(t *testing.T, seed []byte) {
		if len(seed) == 0 {
			return
		}
		d := etree.NewDocument()
		if e := d.ReadFromBytes(fixture); e != nil {
			return
		}
		cv := findCipherValue(d.Root())
		if cv == nil {
			return
		}
		raw, e := base64.StdEncoding.DecodeString(wsStripper.Replace(cv.Text()))
		if e != nil || len(raw) == 0 {
			return
		}
		// A genuine single-byte change to the ciphertext, re-encoded as valid base64.
		i := int(seed[0]) % len(raw)
		raw[i] ^= seed[len(seed)-1] | 1 // XOR by a non-zero value => guaranteed change
		cv.SetText(base64.StdEncoding.EncodeToString(raw))

		if out, derr := xmlenc.Decrypt(key, d.Root()); derr == nil {
			t.Fatalf("GCM AUTH BYPASS: a tampered ciphertext decrypted successfully to %q", out)
		}
	})
}
