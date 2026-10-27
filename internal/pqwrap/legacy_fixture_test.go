package pqwrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// frozenLegacyFixtures pins each committed fixture's SHA-256, so a fixture
// cannot be regenerated to match a changed reader. A new fixture adds a row.
var frozenLegacyFixtures = map[string]string{
	"main-94f9d87d2": "f4f8bba511b3acb8b108486bbdd7c0ad15cad6d554a26cbb7dbe62e4c20fb862",
}

// TestLegacyKeyFileFixtures_StillLoad is the §13 guard: every committed
// legacy-60 key file written by an older binary must keep opening, to the
// same DEK, through the reader the server uses (OpenKeyFile). It fails if
// a fixture stops loading, if a fixture changes, or if the fixture set is
// empty (a guard over nothing would pass forever).
func TestLegacyKeyFileFixtures_StillLoad(t *testing.T) {
	root := filepath.Join("testdata", "legacy-60")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		seen++
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, name)
			raw, err := os.ReadFile(filepath.Join(dir, "wrapped-dek.bin"))
			if err != nil {
				t.Fatal(err)
			}
			want, ok := frozenLegacyFixtures[name]
			if !ok {
				t.Fatalf("fixture %s has no frozenLegacyFixtures row", name)
			}
			sum := sha256.Sum256(raw)
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Fatalf("fixture %s changed: sha256 %s, frozen %s. Never edit a fixture; add a new one", name, got, want)
			}
			kek := readHexFile(t, filepath.Join(dir, "kek.hex"))
			dek := readHexFile(t, filepath.Join(dir, "dek.hex"))
			if f := DetectFormat(raw); f != FormatLegacy60 {
				t.Fatalf("fixture detected as %v, want legacy-60", f)
			}
			ks, f, err := OpenKeyFile(raw, kek)
			if err != nil {
				t.Fatalf("legacy fixture %s no longer loads: %v", name, err)
			}
			if f != FormatLegacy60 || !bytes.Equal(ks.DEK, dek) {
				t.Fatalf("legacy fixture %s opened as %v to the wrong DEK", name, f)
			}
		})
	}
	if seen == 0 || seen != len(frozenLegacyFixtures) {
		t.Fatalf("found %d fixture directories, frozenLegacyFixtures has %d rows", seen, len(frozenLegacyFixtures))
	}
}

func readHexFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}
