package pqwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsPath holds known-answer vectors. Regenerate with
// PQWRAP_WRITE_VECTORS=1 go test -run TestVectors ./internal/pqwrap
// and only when the construction changes on purpose (that is a format
// change: a new Version, never an edit of version-1 vectors).
const vectorsPath = "testdata/vectors.json"

type vector struct {
	Name            string `json:"name"`
	Suite           uint16 `json:"suite"`
	Purpose         uint8  `json:"purpose"`
	Seed            string `json:"seed"`
	MLKEMEncapsRand string `json:"mlkem_encaps_rand"`
	X25519EphSecret string `json:"x25519_eph_secret"`
	Nonce           string `json:"nonce"`
	Context         string `json:"context"`
	Key             string `json:"key"`
	PublicKey       string `json:"public_key"`
	SharedMLKEM     string `json:"ss_mlkem"`
	SharedX25519    string `json:"ss_x25519"`
	TranscriptHash  string `json:"transcript_hash"`
	WrapKey         string `json:"wrap_key"`
	Envelope        string `json:"envelope"`
}

type vectorFile struct {
	Comment string   `json:"comment"`
	Vectors []vector `json:"vectors"`
}

// fixedNonceGCM produces exactly the layout of cipher.NewGCMWithRandomNonce
// (nonce || ciphertext || tag) with a caller-chosen nonce, so a vector can
// pin every output byte. Test-only: production always draws the nonce.
type fixedNonceGCM struct {
	cipher.AEAD
	nonce []byte
}

func (f fixedNonceGCM) NonceSize() int { return 0 }
func (f fixedNonceGCM) Overhead() int  { return f.AEAD.NonceSize() + f.AEAD.Overhead() }
func (f fixedNonceGCM) Seal(dst, _, plaintext, aad []byte) []byte {
	dst = append(dst, f.nonce...)
	return f.AEAD.Seal(dst, f.nonce, plaintext, aad)
}

func fixedNonce(nonce []byte) func([]byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(b)
		if err != nil {
			return nil, err
		}
		return fixedNonceGCM{g, nonce}, nil
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// buildVector computes every field of v from its inputs (seed, encapsulation
// randomness, ephemeral secret, nonce, context, key) through the package's
// own seal path with deterministic randomness.
func buildVector(t *testing.T, v vector) vector {
	t.Helper()
	s := Suite(v.Suite)
	priv, err := NewPrivateKeyFromSeed(s, mustHex(t, v.Seed))
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	var ssM, ctM []byte
	switch s {
	case SuiteX25519MLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(pub.mlkemEK)
		if err != nil {
			t.Fatal(err)
		}
		ssM, ctM, err = mlkemtest.Encapsulate768(ek, mustHex(t, v.MLKEMEncapsRand))
		if err != nil {
			t.Fatal(err)
		}
	case SuiteX25519MLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(pub.mlkemEK)
		if err != nil {
			t.Fatal(err)
		}
		ssM, ctM, err = mlkemtest.Encapsulate1024(ek, mustHex(t, v.MLKEMEncapsRand))
		if err != nil {
			t.Fatal(err)
		}
	}
	xEph, err := ecdh.X25519().NewPrivateKey(mustHex(t, v.X25519EphSecret))
	if err != nil {
		t.Fatal(err)
	}
	env, ssX, th, wk, err := seal(pub, Purpose(v.Purpose), mustHex(t, v.Context), mustHex(t, v.Key),
		encapsulation{ssM: ssM, ctM: ctM, xEph: xEph}, fixedNonce(mustHex(t, v.Nonce)))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	v.PublicKey = hex.EncodeToString(pub.Bytes())
	v.SharedMLKEM = hex.EncodeToString(ssM)
	v.SharedX25519 = hex.EncodeToString(ssX)
	v.TranscriptHash = hex.EncodeToString(th)
	v.WrapKey = hex.EncodeToString(wk)
	v.Envelope = hex.EncodeToString(env)
	return v
}

func vectorInputs() []vector {
	h := func(label string, n int) string { return hex.EncodeToString(testSeed(label)[:n]) }
	return []vector{
		{Name: "768-dek-32", Suite: uint16(SuiteX25519MLKEM768), Purpose: uint8(PurposeDEK),
			Seed: h("v1", SeedSize), MLKEMEncapsRand: h("v1-m", 32), X25519EphSecret: h("v1-x", 32),
			Nonce: h("v1-n", 12), Context: hex.EncodeToString([]byte("keyorix:dek:install-1:epoch-1")), Key: h("v1-k", 32)},
		{Name: "768-backup-empty-context", Suite: uint16(SuiteX25519MLKEM768), Purpose: uint8(PurposeBackupKey),
			Seed: h("v2", SeedSize), MLKEMEncapsRand: h("v2-m", 32), X25519EphSecret: h("v2-x", 32),
			Nonce: h("v2-n", 12), Context: "", Key: h("v2-k", 32)},
		{Name: "1024-dek-32", Suite: uint16(SuiteX25519MLKEM1024), Purpose: uint8(PurposeDEK),
			Seed: h("v3", SeedSize), MLKEMEncapsRand: h("v3-m", 32), X25519EphSecret: h("v3-x", 32),
			Nonce: h("v3-n", 12), Context: hex.EncodeToString([]byte("keyorix:dek:install-1:epoch-1")), Key: h("v3-k", 32)},
		{Name: "1024-backup-64", Suite: uint16(SuiteX25519MLKEM1024), Purpose: uint8(PurposeBackupKey),
			Seed: h("v4", SeedSize), MLKEMEncapsRand: h("v4-m", 32), X25519EphSecret: h("v4-x", 32),
			Nonce: h("v4-n", 12), Context: hex.EncodeToString([]byte("keyorix:backup:archive-42")), Key: h("v4-k", 64)},
	}
}

// TestVectors checks the committed known-answer vectors two ways: the seal
// path with the vector's fixed randomness reproduces every byte, and the
// production Unwrap opens the envelope to the vector's key.
func TestVectors(t *testing.T) {
	if os.Getenv("PQWRAP_WRITE_VECTORS") == "1" {
		var vf vectorFile
		vf.Comment = "RD-PQWRAP-1 known-answer vectors for envelope version 1 (docs/design/pq-key-wrapping.md). " +
			"Generated by TestVectors; cross-checked by an independent implementation (see the PR description)."
		for _, in := range vectorInputs() {
			vf.Vectors = append(vf.Vectors, buildVector(t, in))
		}
		b, err := json.MarshalIndent(vf, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Clean(vectorsPath), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorsPath)
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) < 4 {
		t.Fatalf("only %d vectors", len(vf.Vectors))
	}
	for _, want := range vf.Vectors {
		t.Run(want.Name, func(t *testing.T) {
			got := buildVector(t, want)
			for field, pair := range map[string][2]string{
				"public_key": {got.PublicKey, want.PublicKey}, "ss_mlkem": {got.SharedMLKEM, want.SharedMLKEM},
				"ss_x25519": {got.SharedX25519, want.SharedX25519}, "transcript_hash": {got.TranscriptHash, want.TranscriptHash},
				"wrap_key": {got.WrapKey, want.WrapKey}, "envelope": {got.Envelope, want.Envelope},
			} {
				if pair[0] != pair[1] {
					t.Errorf("%s mismatch:\n got  %s\n want %s", field, pair[0], pair[1])
				}
			}
			priv, err := NewPrivateKeyFromSeed(Suite(want.Suite), mustHex(t, want.Seed))
			if err != nil {
				t.Fatal(err)
			}
			key, err := Unwrap(priv, Purpose(want.Purpose), mustHex(t, want.Context), mustHex(t, want.Envelope))
			if err != nil {
				t.Fatalf("Unwrap(vector): %v", err)
			}
			if !bytes.Equal(key, mustHex(t, want.Key)) {
				t.Fatalf("Unwrap(vector) = %x, want %s", key, want.Key)
			}
		})
	}
}
