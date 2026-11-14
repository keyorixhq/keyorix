package libconformance

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	"filippo.io/age"
)

// This file pins the integrity contract of filippo.io/age — the library Keyorix uses to
// encrypt operator recovery keys (server/admin/recovery_key_encrypt.go: age.Encrypt to an
// X25519/hybrid/ssh recipient; decryption is the operator's `age -d`). age's binary format
// is fully authenticated: a header HMAC covers the recipient stanzas, and the payload is
// STREAM ChaCha20Poly1305. Every byte is therefore either structural (a flip makes the
// header unparseable) or authenticated (a flip makes an HMAC or AEAD tag mismatch). So no
// single-bit mutation of a valid age ciphertext may ever decrypt to *different* plaintext.
// A mutation that still yields the identical plaintext is semantically neutral (it landed
// on a non-significant base64 bit); anything else that decrypts is an integrity break.
//
// Lib-contract target: links only filippo.io/age, no keyorix code (see doc.go).

// Known-answer vector lifted from filippo.io/age@v1.3.2/testdata (offline, upstream):
// example.age decrypts to "Black lives matter." under the test identity below.
const ageExampleIdentity = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"
const ageExampleCiphertextB64 = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA4aHJsTStaQkczRGQ0ZkYyK2E1ODN6ZFRJV0RrOC9SNDFrQ1lac3Z3VFc0CnlPNFBZZGxNV0RKK0N4Z1VOUnFZNVowVC9tK2czRkNoNWpJeEdMYkNWWGMKLS0tIEkvaW1ldlp6eTgxMjBKU3ptSm5tbi9LTWszcDVBMTFWODNOazQxbTlOUEUKcMXlNiShUgdT+Sxa0Q7KsnO6TWEXgHcT6DggQXod8soIGCJyyPhchXc0oTEaO3XpjQ6v"
const ageExamplePlaintext = "Black lives matter."

func mustAgeExample(t testing.TB) []byte {
	ct, err := base64.StdEncoding.DecodeString(ageExampleCiphertextB64)
	if err != nil {
		t.Fatalf("decode embedded age vector: %v", err)
	}
	return ct
}

// TestAge_KnownAnswerVector is the conformance anchor: the upstream example ciphertext
// must decrypt to the exact expected plaintext under the matching identity.
func TestAge_KnownAnswerVector(t *testing.T) {
	id, err := age.ParseX25519Identity(ageExampleIdentity)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	r, err := age.Decrypt(bytes.NewReader(mustAgeExample(t)), id)
	if err != nil {
		t.Fatalf("decrypt known-answer vector: %v", err)
	}
	pt, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if string(pt) != ageExamplePlaintext {
		t.Fatalf("age KAT: got %q want %q (filippo.io/age diverges from its own test vector)", string(pt), ageExamplePlaintext)
	}
}

// TestAge_WrongIdentityRejected confirms the obvious baseline: a different identity cannot
// decrypt the vector (no-recipient-match must be an error, never a silent success).
func TestAge_WrongIdentityRejected(t *testing.T) {
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	if _, err := age.Decrypt(bytes.NewReader(mustAgeExample(t)), other); err == nil {
		t.Fatalf("age decrypted the vector under a NON-matching identity (no recipient should match)")
	}
}

// FuzzAgeCiphertextMutation is the fail-closed mutation oracle for the age integrity
// contract. For a fuzzer-chosen plaintext it: encrypts under a fixed X25519 identity,
// confirms the round-trip (baseline), then flips one bit of the ciphertext and asserts the
// result NEVER decrypts to different plaintext. A flip that still yields the identical
// plaintext (a non-significant base64 bit) is the only tolerated outcome besides rejection.
//
// Sound by construction: the one "must-succeed" assertion is the round-trip baseline; the
// mutation assertion is "must-not-decrypt-to-different-plaintext".
func FuzzAgeCiphertextMutation(f *testing.F) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		f.Fatalf("gen identity: %v", err)
	}
	recipient := id.Recipient()

	encrypt := func(pt []byte) ([]byte, bool) {
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, recipient)
		if err != nil {
			return nil, false
		}
		if _, err := w.Write(pt); err != nil {
			return nil, false
		}
		if err := w.Close(); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}

	f.Add([]byte("Black lives matter."), uint32(40), uint8(1))
	f.Add([]byte(""), uint32(10), uint8(0x80))
	f.Add(bytes.Repeat([]byte("A"), 70000), uint32(5000), uint8(0x01)) // crosses the 64KiB STREAM chunk boundary

	f.Fuzz(func(t *testing.T, pt []byte, mutPos uint32, mutXor uint8) {
		// Keep payloads bounded so a pathological length can't exhaust memory.
		if len(pt) > 200000 {
			pt = pt[:200000]
		}
		ct, ok := encrypt(pt)
		if !ok || len(ct) == 0 {
			return
		}

		// Baseline: the unmodified ciphertext must round-trip to the exact plaintext.
		r, err := age.Decrypt(bytes.NewReader(ct), id)
		if err != nil {
			t.Fatalf("BASELINE: a freshly-encrypted age ciphertext failed to decrypt: %v (ptLen=%d)", err, len(pt))
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("BASELINE: reading plaintext from a valid ciphertext failed: %v (ptLen=%d)", err, len(pt))
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("BASELINE: round-trip plaintext mismatch (ptLen=%d)", len(pt))
		}

		// Flip exactly one bit of the ciphertext.
		if mutXor == 0 {
			mutXor = 1
		}
		mutated := bytes.Clone(ct)
		pos := int(mutPos) % len(mutated)
		mutated[pos] ^= mutXor
		if bytes.Equal(mutated, ct) {
			return // no-op (defensive; mutXor != 0 guarantees a change)
		}

		// Fail-closed oracle.
		mr, err := age.Decrypt(bytes.NewReader(mutated), id)
		if err != nil {
			return // correct: a tampered ciphertext is rejected
		}
		out, err := io.ReadAll(mr)
		if err != nil {
			return // correct: authentication fails during payload read
		}
		if !bytes.Equal(out, pt) {
			t.Fatalf("AGE INTEGRITY BREAK: a single-bit-flipped ciphertext (pos=%d xor=%#x) decrypted to DIFFERENT plaintext (origLen=%d, gotLen=%d)",
				pos, mutXor, len(pt), len(out))
		}
		// else: decrypt succeeded with identical plaintext -> non-significant bit, neutral.
	})
}
