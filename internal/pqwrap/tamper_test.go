package pqwrap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func wrapFor(t *testing.T, s Suite, label string) (*PrivateKey, []byte, []byte) {
	t.Helper()
	priv := testKey(t, s, label)
	key := bytes.Repeat([]byte{0x5A}, 32)
	env, err := Wrap(priv.PublicKey(), PurposeDEK, []byte("ctx"), key)
	if err != nil {
		t.Fatal(err)
	}
	return priv, key, env
}

// Every single-bit change anywhere in the envelope must make Unwrap fail:
// header fields, the X25519 share, the ML-KEM ciphertext, the length field
// and the sealed key.
func TestUnwrap_EveryByteFlipFails(t *testing.T) {
	for _, s := range allSuites {
		priv, _, env := wrapFor(t, s, "flip")
		for i := range env {
			for _, bit := range []byte{0x01, 0x80} {
				bad := bytes.Clone(env)
				bad[i] ^= bit
				if _, err := Unwrap(priv, PurposeDEK, []byte("ctx"), bad); err == nil {
					t.Fatalf("%v: flipping bit %#x of byte %d still unwrapped", s, bit, i)
				}
			}
		}
	}
}

func TestUnwrap_TruncationAndTrailingBytesFail(t *testing.T) {
	for _, s := range allSuites {
		priv, _, env := wrapFor(t, s, "trunc")
		for n := range env {
			if _, err := Unwrap(priv, PurposeDEK, []byte("ctx"), env[:n]); err == nil {
				t.Fatalf("%v: envelope truncated to %d bytes unwrapped", s, n)
			}
			if _, err := ParseEnvelope(env[:n]); err == nil {
				t.Fatalf("%v: envelope truncated to %d bytes parsed", s, n)
			}
		}
		long := append(bytes.Clone(env), 0)
		if _, err := ParseEnvelope(long); err == nil {
			t.Fatalf("%v: trailing byte accepted by the parser", s)
		}
		if _, err := Unwrap(priv, PurposeDEK, []byte("ctx"), long); err == nil {
			t.Fatalf("%v: trailing byte accepted by Unwrap", s)
		}
	}
}

func TestUnwrap_WrongContextPurposeOrKeyFails(t *testing.T) {
	for _, s := range allSuites {
		priv, key, env := wrapFor(t, s, "ctx")
		if got, err := Unwrap(priv, PurposeDEK, []byte("ctx"), env); err != nil || !bytes.Equal(got, key) {
			t.Fatalf("%v: control unwrap failed: %v", s, err)
		}
		cases := map[string]func() ([]byte, error){
			"other context": func() ([]byte, error) { return Unwrap(priv, PurposeDEK, []byte("ctx2"), env) },
			"empty context": func() ([]byte, error) { return Unwrap(priv, PurposeDEK, nil, env) },
			"other purpose": func() ([]byte, error) { return Unwrap(priv, PurposeBackupKey, []byte("ctx"), env) },
			"other key":     func() ([]byte, error) { return Unwrap(testKey(t, s, "ctx-other"), PurposeDEK, []byte("ctx"), env) },
		}
		for name, f := range cases {
			if _, err := f(); err == nil {
				t.Errorf("%v: unwrap with %s succeeded", s, name)
			}
		}
	}
}

// An envelope made for one suite never opens under a key of the other suite,
// even when both keys come from the same seed (a downgrade or confusion
// attempt between parameter sets).
func TestUnwrap_SuiteConfusionFails(t *testing.T) {
	_, _, env768 := wrapFor(t, SuiteX25519MLKEM768, "confuse")
	priv1024 := testKey(t, SuiteX25519MLKEM1024, "confuse")
	if _, err := Unwrap(priv1024, PurposeDEK, []byte("ctx"), env768); err == nil {
		t.Fatal("768 envelope unwrapped with a 1024 key")
	}
	// Rewriting the suite id in the header is caught by the parser (the
	// ciphertext length no longer matches) or by the key binding.
	bad := bytes.Clone(env768)
	binary.BigEndian.PutUint16(bad[offSuite:], uint16(SuiteX25519MLKEM1024))
	if _, err := Unwrap(priv1024, PurposeDEK, []byte("ctx"), bad); err == nil {
		t.Fatal("suite-rewritten envelope unwrapped")
	}
}

// Header rewrites that keep the envelope well-formed: version, purpose and
// key id. The parser or the transcript binding must reject each one.
func TestUnwrap_HeaderRewritesFail(t *testing.T) {
	priv, _, env := wrapFor(t, SuiteX25519MLKEM768, "hdr")
	rewrites := map[string]func(b []byte){
		"version 0":       func(b []byte) { b[offVersion] = 0 },
		"version 2":       func(b []byte) { b[offVersion] = 2 },
		"purpose backup":  func(b []byte) { b[offPurpose] = byte(PurposeBackupKey) },
		"purpose unknown": func(b []byte) { b[offPurpose] = 0x7f },
		"magic":           func(b []byte) { b[0] = 'X' },
		"key id":          func(b []byte) { b[offKeyID] ^= 0xff },
		"suite unknown":   func(b []byte) { binary.BigEndian.PutUint16(b[offSuite:], 0x7777) },
	}
	for name, mutate := range rewrites {
		bad := bytes.Clone(env)
		mutate(bad)
		for _, p := range []Purpose{PurposeDEK, PurposeBackupKey} {
			if _, err := Unwrap(priv, p, []byte("ctx"), bad); err == nil {
				t.Errorf("%s: unwrapped as purpose %v", name, p)
			}
		}
	}
}

// The parser is strict about the sealed-key length: below the AEAD overhead
// plus one byte, or above the overhead plus MaxKeySize, is refused before any
// cryptography runs.
func TestParseEnvelope_SealedLengthBounds(t *testing.T) {
	_, _, env := wrapFor(t, SuiteX25519MLKEM768, "len")
	e, err := ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, aeadOverhead, aeadOverhead + MaxKeySize + 1} {
		bad := *e
		bad.Sealed = make([]byte, n)
		if _, err := ParseEnvelope(bad.encode()); err == nil {
			t.Errorf("sealed length %d accepted", n)
		}
	}
	got, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, env) {
		t.Fatal("parse/marshal does not round-trip a genuine envelope")
	}
}

// Marshal refuses exactly the sealed lengths ParseEnvelope refuses, instead of
// writing them (a length above 65535 would be truncated in the 2-byte field).
// Every length it accepts parses back.
func TestMarshal_RefusesOutOfBoundSealedLength(t *testing.T) {
	_, _, env := wrapFor(t, SuiteX25519MLKEM768, "marshal-len")
	e, err := ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, aeadOverhead, aeadOverhead + MaxKeySize + 1, 0xffff, 0x10000, 0x10000 + aeadOverhead + 1} {
		bad := *e
		bad.Sealed = make([]byte, n)
		if out, err := bad.Marshal(); err == nil {
			t.Errorf("sealed length %d: Marshal returned %d bytes, want an error", n, len(out))
		}
	}
	for n := aeadOverhead + 1; n <= aeadOverhead+MaxKeySize; n++ {
		ok := *e
		ok.Sealed = make([]byte, n)
		out, err := ok.Marshal()
		if err != nil {
			t.Fatalf("sealed length %d: %v", n, err)
		}
		if _, err := ParseEnvelope(out); err != nil {
			t.Errorf("sealed length %d: Marshal output does not parse: %v", n, err)
		}
	}
}

func TestEnvelopeSize_MatchesLayout(t *testing.T) {
	// Layout (pq-key-wrapping.md §5): 24-byte header, 32-byte X25519 share,
	// the ML-KEM ciphertext, a 2-byte length, then nonce || key || tag.
	for s, ctLen := range map[Suite]int{SuiteX25519MLKEM768: 1088, SuiteX25519MLKEM1024: 1568} {
		want := 24 + 32 + ctLen + 2 + 12 + 32 + 16
		if got := EnvelopeSize(s, 32); got != want {
			t.Errorf("%v: EnvelopeSize(32) = %d, want %d", s, got, want)
		}
	}
	if EnvelopeSize(Suite(0x7777), 32) != 0 {
		t.Error("EnvelopeSize of an unknown suite is not 0")
	}
}
