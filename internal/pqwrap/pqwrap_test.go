package pqwrap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

var allSuites = []Suite{SuiteX25519MLKEM768, SuiteX25519MLKEM1024}

// testSeed returns a deterministic SeedSize-byte seed for label.
func testSeed(label string) []byte {
	var out []byte
	for i := 0; len(out) < SeedSize; i++ {
		sum := sha256.Sum256(fmt.Appendf(nil, "pqwrap-test-seed/%s/%d", label, i))
		out = append(out, sum[:]...)
	}
	return out[:SeedSize]
}

func testKey(t testing.TB, s Suite, label string) *PrivateKey {
	t.Helper()
	k, err := NewPrivateKeyFromSeed(s, testSeed(label))
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeed(%v): %v", s, err)
	}
	return k
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	for _, s := range allSuites {
		for _, p := range []Purpose{PurposeDEK, PurposeBackupKey} {
			for _, n := range []int{1, 16, 32, MaxKeySize} {
				t.Run(fmt.Sprintf("%v/%v/%d", s, p, n), func(t *testing.T) {
					priv := testKey(t, s, "rt")
					key := bytes.Repeat([]byte{0xA5}, n)
					ctx := []byte("keyorix:dek:install-1:epoch-7")
					env, err := Wrap(priv.PublicKey(), p, ctx, key)
					if err != nil {
						t.Fatalf("Wrap: %v", err)
					}
					if got, want := len(env), EnvelopeSize(s, n); got != want {
						t.Errorf("envelope size %d, EnvelopeSize says %d", got, want)
					}
					got, err := Unwrap(priv, p, ctx, env)
					if err != nil {
						t.Fatalf("Unwrap: %v", err)
					}
					if !bytes.Equal(got, key) {
						t.Fatalf("Unwrap returned %x, want %x", got, key)
					}
				})
			}
		}
	}
}

func TestWrap_IsRandomized(t *testing.T) {
	priv := testKey(t, SuiteX25519MLKEM768, "rand")
	key := make([]byte, 32)
	a, err := Wrap(priv.PublicKey(), PurposeDEK, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Wrap(priv.PublicKey(), PurposeDEK, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two wraps of the same key produced identical envelopes")
	}
}

func TestGenerateKey_RoundTrip(t *testing.T) {
	for _, s := range allSuites {
		priv, err := GenerateKey(s)
		if err != nil {
			t.Fatalf("GenerateKey(%v): %v", s, err)
		}
		env, err := Wrap(priv.PublicKey(), PurposeDEK, nil, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Unwrap(priv, PurposeDEK, nil, env); err != nil {
			t.Fatalf("Unwrap with generated key: %v", err)
		}
	}
}

func TestNewPrivateKeyFromSeed_DeterministicAndSeedChecked(t *testing.T) {
	for _, s := range allSuites {
		a := testKey(t, s, "det")
		b := testKey(t, s, "det")
		if !bytes.Equal(a.PublicKey().Bytes(), b.PublicKey().Bytes()) {
			t.Errorf("%v: same seed gave different public keys", s)
		}
		c := testKey(t, s, "other")
		if bytes.Equal(a.PublicKey().Bytes(), c.PublicKey().Bytes()) {
			t.Errorf("%v: different seeds gave the same public key", s)
		}
		for _, n := range []int{0, SeedSize - 1, SeedSize + 1} {
			if _, err := NewPrivateKeyFromSeed(s, make([]byte, n)); err == nil {
				t.Errorf("%v: seed of %d bytes accepted", s, n)
			}
		}
	}
	if _, err := NewPrivateKeyFromSeed(Suite(0x7777), testSeed("x")); err == nil {
		t.Error("unknown suite accepted")
	}
}

func TestPublicKey_ParseRoundTripAndKeyID(t *testing.T) {
	for _, s := range allSuites {
		priv := testKey(t, s, "pk")
		pub := priv.PublicKey()
		parsed, err := ParsePublicKey(pub.Bytes())
		if err != nil {
			t.Fatalf("ParsePublicKey: %v", err)
		}
		if !bytes.Equal(parsed.Bytes(), pub.Bytes()) {
			t.Fatal("public key encoding does not round-trip")
		}
		if parsed.KeyID() != pub.KeyID() || pub.KeyID() == ([16]byte{}) {
			t.Fatal("key id not stable or zero")
		}
		// A parsed public key wraps for the private key.
		env, err := Wrap(parsed, PurposeBackupKey, nil, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Unwrap(priv, PurposeBackupKey, nil, env); err != nil {
			t.Fatalf("Unwrap of envelope made from parsed public key: %v", err)
		}
		b := pub.Bytes()
		for _, bad := range [][]byte{nil, b[:len(b)-1], append(bytes.Clone(b), 0)} {
			if _, err := ParsePublicKey(bad); err == nil {
				t.Errorf("%v: malformed public key of %d bytes accepted", s, len(bad))
			}
		}
	}
	other := testKey(t, SuiteX25519MLKEM768, "pk").PublicKey().KeyID()
	if other == testKey(t, SuiteX25519MLKEM1024, "pk").PublicKey().KeyID() {
		t.Error("same seed under two suites produced the same key id")
	}
}

func TestDeriveSeed_DeterministicAndDomainSeparated(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveSeed(kek, SuiteX25519MLKEM768, "e1")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != SeedSize {
		t.Fatalf("seed length %d", len(a))
	}
	b, _ := DeriveSeed(kek, SuiteX25519MLKEM768, "e1")
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveSeed not deterministic")
	}
	for name, other := range map[string]func() ([]byte, error){
		"suite": func() ([]byte, error) { return DeriveSeed(kek, SuiteX25519MLKEM1024, "e1") },
		"epoch": func() ([]byte, error) { return DeriveSeed(kek, SuiteX25519MLKEM768, "e2") },
		"kek":   func() ([]byte, error) { return DeriveSeed(bytes.Repeat([]byte{8}, 32), SuiteX25519MLKEM768, "e1") },
	} {
		c, err := other()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, c) {
			t.Errorf("changing %s did not change the seed", name)
		}
	}
	if _, err := DeriveSeed(make([]byte, 31), SuiteX25519MLKEM768, "e1"); err == nil {
		t.Error("short KEK accepted")
	}
	if _, err := DeriveSeed(make([]byte, 32), SuiteX25519MLKEM768, "e1"); err == nil {
		t.Error("all-zero KEK accepted")
	}
}

// TestWrap_AnyPublicKeyHolderCanWrap_NoOriginAuthentication pins a property
// the design note relies on (pq-key-wrapping.md §6): a KEM-DEM envelope
// proves nothing about who wrote it. Anyone holding the public key makes an
// envelope that unwraps cleanly, so a reader that must know the key came from
// the KEK holder needs a separate authenticator. If this test ever fails, the
// envelope gained sender authentication and §6 must be revisited.
func TestWrap_AnyPublicKeyHolderCanWrap_NoOriginAuthentication(t *testing.T) {
	priv := testKey(t, SuiteX25519MLKEM768, "origin")
	attackerChosen := bytes.Repeat([]byte{0x41}, 32)
	pubOnly, err := ParsePublicKey(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	env, err := Wrap(pubOnly, PurposeDEK, []byte("ctx"), attackerChosen)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(priv, PurposeDEK, []byte("ctx"), env)
	if err != nil || !bytes.Equal(got, attackerChosen) {
		t.Fatalf("expected a public-key-only wrap to unwrap: got %x, %v", got, err)
	}
}

func TestWrap_RefusesBadInput(t *testing.T) {
	priv := testKey(t, SuiteX25519MLKEM768, "bad")
	pub := priv.PublicKey()
	for _, n := range []int{0, MaxKeySize + 1} {
		if _, err := Wrap(pub, PurposeDEK, nil, make([]byte, n)); err == nil {
			t.Errorf("wrap of a %d-byte key accepted", n)
		}
	}
	if _, err := Wrap(pub, Purpose(0), nil, make([]byte, 32)); err == nil {
		t.Error("purpose 0 accepted")
	}
	if _, err := Wrap(pub, Purpose(0x7f), nil, make([]byte, 32)); err == nil {
		t.Error("unknown purpose accepted")
	}
	if _, err := Wrap(nil, PurposeDEK, nil, make([]byte, 32)); err == nil {
		t.Error("nil public key accepted")
	}
	if _, err := Unwrap(nil, PurposeDEK, nil, make([]byte, 32)); err == nil {
		t.Error("nil private key accepted")
	}
}
