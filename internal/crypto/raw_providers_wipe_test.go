package crypto

// raw_providers_wipe_test.go (#4498): decodeKeyMaterial decodes from []byte so
// it makes no immutable string copy of an encoded KEK, and FileKeyProvider.KEK
// wipes its read buffer. These tests pin the contract the wipe relies on (an
// encoded KEK is returned in a new slice; the accepted formats are unchanged).
// That the copies are gone from process memory is measured by the
// memory-residue oracle (internal/encryption/memresidue_test.go, Linux).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeKeyMaterialViaStrings is decodeKeyMaterial as it was before #4498 (string
// decoders), the reference the []byte version must agree with.
func decodeKeyMaterialViaStrings(material []byte) ([]byte, bool) {
	if len(material) == KEKSize {
		return material, true
	}
	s := strings.TrimSpace(string(material))
	if b, err := hex.DecodeString(s); err == nil && len(b) == KEKSize {
		return b, true
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == KEKSize {
			return b, true
		}
	}
	return nil, false
}

func TestDecodeKeyMaterial_AcceptsExactlyWhatTheStringDecodersAccepted(t *testing.T) {
	kek := make([]byte, KEKSize)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	hx := hex.EncodeToString(kek)
	inputs := []string{
		hx, strings.ToUpper(hx), " " + hx + "\t\n", hx[:63], hx + "0", hx[:62] + "zz", hex.EncodeToString(kek[:20]),
		base64.StdEncoding.EncodeToString(kek), base64.RawStdEncoding.EncodeToString(kek),
		base64.URLEncoding.EncodeToString(kek), base64.RawURLEncoding.EncodeToString(kek),
		"\n" + base64.StdEncoding.EncodeToString(kek) + " \r\n", base64.StdEncoding.EncodeToString(kek)[:40],
		base64.StdEncoding.EncodeToString(make([]byte, 33)), base64.StdEncoding.EncodeToString(kek[:31]),
		"", " ", "not key material", strings.Repeat("=", 44),
	}
	for range 200 {
		n := 1 + int(kek[0])%80
		b := make([]byte, n)
		_, _ = rand.Read(b)
		_, _ = rand.Read(kek[:1])
		inputs = append(inputs, string(b), base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b))
	}
	for i, in := range inputs {
		want, wantOK := decodeKeyMaterialViaStrings([]byte(in))
		got, err := decodeKeyMaterial([]byte(in), "test")
		if wantOK && validateAllZero(want) {
			wantOK = false // validateKEK refuses it on both paths
		}
		if (err == nil) != wantOK || (wantOK && !bytes.Equal(got, want)) {
			t.Fatalf("input %d (len %d): []byte decoder disagrees with the string decoders: err=%v, want ok=%v", i, len(in), err, wantOK)
		}
	}
}

func validateAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestDecodeKeyMaterial_EncodedKEKIsANewSlice(t *testing.T) {
	kek := bytes.Repeat([]byte{0xA5}, KEKSize)
	for _, text := range []string{hex.EncodeToString(kek), base64.StdEncoding.EncodeToString(kek), base64.RawURLEncoding.EncodeToString(kek)} {
		material := []byte(text)
		got, err := decodeKeyMaterial(material, "test")
		if err != nil {
			t.Fatal(err)
		}
		WipeBytes(material) // what FileKeyProvider.KEK does with its read buffer
		if !bytes.Equal(got, kek) {
			t.Fatalf("wiping the encoded input changed the decoded KEK: the result aliases the input")
		}
	}
	raw := bytes.Clone(kek)
	got, err := decodeKeyMaterial(raw, "test")
	if err != nil || &got[0] != &raw[0] {
		t.Fatalf("raw KEK: want the input slice itself back (the caller wipes it), err=%v", err)
	}
}

func TestDecodeKEKInto_WipesAFailedAttempt(t *testing.T) {
	var scratch []byte
	partial := func(dst, _ []byte) (int, error) {
		scratch = dst
		for i := range dst {
			dst[i] = 0xFF
		}
		return len(dst) - 1, errors.New("corrupt input")
	}
	if _, ok := decodeKEKInto(nil, KEKSize, partial); ok {
		t.Fatal("a failed decode must not be accepted")
	}
	if !validateAllZero(scratch) {
		t.Fatal("decodeKEKInto left a failed attempt's partially decoded bytes in its buffer")
	}
	short := func(dst, _ []byte) (int, error) { scratch = dst; dst[0] = 0xFF; return 1, nil }
	if _, ok := decodeKEKInto(nil, KEKSize, short); ok || !validateAllZero(scratch) {
		t.Fatal("a decode of the wrong length must be refused and its buffer wiped")
	}
}

// TestFileKeyProvider_EncodedKEKFilesStillLoad: the read-buffer wipe must not
// touch the returned KEK for any accepted file shape.
func TestFileKeyProvider_EncodedKEKFilesStillLoad(t *testing.T) {
	kek := bytes.Repeat([]byte{0x3C}, KEKSize)
	files := map[string][]byte{
		"raw":            kek,
		"raw-newline":    append(bytes.Clone(kek), '\n'),
		"hex-newline":    []byte(hex.EncodeToString(kek) + "\n"),
		"base64-crlf":    []byte(base64.StdEncoding.EncodeToString(kek) + "\r\n"),
		"base64url-bare": []byte(base64.RawURLEncoding.EncodeToString(kek)),
	}
	for name, content := range files {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kek")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := NewFileKeyProvider(path).KEK()
			if err != nil || !bytes.Equal(got, kek) {
				t.Fatalf("err=%v, KEK mismatch=%v", err, !bytes.Equal(got, kek))
			}
		})
	}
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, []byte("not key material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileKeyProvider(path).KEK(); err == nil {
		t.Fatal("undecodable key material must be refused")
	}
}
