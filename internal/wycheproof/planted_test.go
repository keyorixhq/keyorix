package wycheproof

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/rules"
)

// Planted defects (RULES.md section 3). Each defective wrapper is run through
// the same suite as the real one and the suite must report failures; the
// control (the standard library primitive with the same scope) must report none.

// ---- AEAD ----

// ctrPlain decrypts the GCM ciphertext without looking at the tag.
func ctrPlain(key, nonce, ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := append(clone(nonce), 0, 0, 0, 2)
	out := make([]byte, len(ct))
	cipher.NewCTR(blk, iv).XORKeyStream(out, ct)
	return out, nil
}

// plantedNoTagCheck skips the tag check.
func plantedNoTagCheck(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return stdlibOpen(key, nonce, aad, ct, tag)
	}
	return ctrPlain(key, nonce, ct)
}

// plantedTruncatedTag compares only as many tag bytes as were supplied.
func plantedTruncatedTag(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 {
		return stdlibOpen(key, nonce, aad, ct, tag)
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	pt, err := ctrPlain(key, nonce, ct)
	if err != nil {
		return nil, err
	}
	want := g.Seal(nil, nonce, pt, aad)
	want = want[len(want)-16:]
	if len(tag) > 16 {
		return nil, errBad
	}
	if string(want[:len(tag)]) != string(tag) {
		return nil, errBad
	}
	return pt, nil
}

// plantedNonceLen ignores the nonce-length rule: it takes the first 12 bytes of
// a longer nonce and zero-pads a shorter one.
func plantedNonceLen(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	n := make([]byte, 12)
	copy(n, nonce)
	return stdlibOpen(key, n, aad, ct, tag)
}

type badErr struct{}

func (badErr) Error() string { return "bad" }

var errBad error = badErr{}

func TestPlantedDefectsAEAD(t *testing.T) {
	var f aesGCMFile
	loadVectors(t, "aes_gcm_test.json", &f)
	cases := []struct {
		name   string
		open   aeadOpen
		expect bool // true: suite must fail
	}{
		{"control/stdlib-gcm", stdlibOpen, false},
		{"planted/no-tag-check", plantedNoTagCheck, true},
		{"planted/truncated-tag", plantedTruncatedTag, true},
		{"planted/ignores-nonce-length", plantedNonceLen, true},
	}
	for _, c := range cases {
		r := newReport(c.name, false)
		aeadSuite(r, c.open, &f)
		t.Logf("%s: failures=%d %s", c.name, r.Failures(), r.Summary())
		if c.expect && r.Failures() == 0 {
			t.Errorf("%s: suite did not catch the planted defect", c.name)
		}
		if !c.expect && r.Failures() != 0 {
			r.Err(t)
		}
	}
}

// ---- Ed25519 ----

func plantedHighS(pub, msg, sig []byte) bool {
	if len(sig) != 64 {
		return stdlibEdVerify(pub, msg, sig)
	}
	s := new(big.Int).Mod(leToInt(sig[32:]), edL)
	return stdlibEdVerify(pub, msg, append(clone(sig[:32]), intToLE(s, 32)...))
}

func plantedTrailingBytes(pub, msg, sig []byte) bool {
	if len(sig) > 64 {
		sig = sig[:64]
	}
	return stdlibEdVerify(pub, msg, sig)
}

func TestPlantedDefectsEd25519(t *testing.T) {
	var f ed25519File
	loadVectors(t, "ed25519_test.json", &f)
	cases := []struct {
		name   string
		v      edVerify
		expect bool
	}{
		{"control/stdlib-ed25519", stdlibEdVerify, false},
		{"planted/accepts-high-S", plantedHighS, true},
		{"planted/trailing-bytes", plantedTrailingBytes, true},
	}
	for _, c := range cases {
		r := newReport(c.name, false)
		edSuite(r, c.v, &f, nil)
		t.Logf("%s: failures=%d %s", c.name, r.Failures(), r.Summary())
		if c.expect && r.Failures() == 0 {
			t.Errorf("%s: suite did not catch the planted defect", c.name)
		}
		if !c.expect && r.Failures() != 0 {
			r.Err(t)
		}
	}
}

// ---- RSA PKCS#1 v1.5 ----

func stdlibRS256(jwk rules.JWK, msg, sig []byte) bool {
	k, err := rules.ParseJWK(jwk)
	if err != nil {
		return false
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return false
	}
	h := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
}

// plantedRSAReduce accepts s+N by reducing the signature modulo N first.
func plantedRSAReduce(jwk rules.JWK, msg, sig []byte) bool {
	n := new(big.Int).SetBytes(mustB64(jwk.N))
	s := new(big.Int).Mod(new(big.Int).SetBytes(sig), n)
	return stdlibRS256(jwk, msg, s.FillBytes(make([]byte, (n.BitLen()+7)/8)))
}

func TestPlantedDefectsRSA(t *testing.T) {
	var f sigFile
	loadVectors(t, "rsa_signature_2048_sha256_test.json", &f)
	cases := []struct {
		name   string
		v      jwtVerify
		expect bool
	}{
		{"control/stdlib-rsa-pkcs1", stdlibRS256, false},
		{"planted/accepts-s-plus-N", plantedRSAReduce, true},
	}
	for _, c := range cases {
		r := newReport(c.name, false)
		sigSuite(r, c.v, refVerify("RS256"), &f, 0, true)
		t.Logf("%s: failures=%d %s", c.name, r.Failures(), r.Summary())
		if c.expect && r.Failures() == 0 {
			t.Errorf("%s: suite did not catch the planted defect", c.name)
		}
		if !c.expect && r.Failures() != 0 {
			r.Err(t)
		}
	}
}

// ---- MAC compared with == ----

func TestPlantedDefectMACEqualsOperator(t *testing.T) {
	bad := `package p
func verify(mac, want string) bool { return mac == want }
func verify2(a []byte, sig []byte) bool { return string(a) != string(sig) }
`
	badBytes := `package p
import "bytes"
func verify(tag, want []byte) bool { return bytes.Equal(tag, want) }
`
	good := `package p
import "crypto/hmac"
func verify(mac, want []byte) bool { return hmac.Equal(mac, want) }
func lenOK(mac []byte) bool { return len(mac) == 32 && mac != nil }
func empty(sig string) bool { return sig == "" }
`
	if n := len(findingsInSource(t, bad)); n != 2 {
		t.Errorf("== / != on MAC names: %d findings, want 2", n)
	}
	if n := len(findingsInSource(t, badBytes)); n != 1 {
		t.Errorf("bytes.Equal on a tag: %d findings, want 1", n)
	}
	if fs := findingsInSource(t, good); len(fs) != 0 {
		t.Errorf("control reported findings: %v", fs)
	}
	// Forms reached through an encoder or a slice expression.
	badWrapped := `package p
import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
)
func v1(mac []byte, want string) bool { return hex.EncodeToString(mac) == want }
func v2(sig [64]byte, want string) bool { return string(sig[:]) == want }
func v3(tag, want []byte) bool { return bytes.Equal(tag[:16], want) }
func v4(x struct{ Sig []byte }, want string) bool { return base64.RawURLEncoding.EncodeToString(x.Sig) != want }
`
	if fs := findingsInSource(t, badWrapped); len(fs) != 4 {
		t.Errorf("encoded / sliced MAC operands: %d findings %v, want 4", len(fs), fs)
	}
}

var _ = ed25519.PublicKeySize
