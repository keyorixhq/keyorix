package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzCheckpointKeyFileParse fuzzes readCheckpointKeyFile against arbitrary
// bytes written to a real temp file under --checkpoint-key-file (the derived
// audit-checkpoint signing key, accepted as hex or base64 per
// readCheckpointKeyFile's own doc comment in audit_verify.go). Oracle,
// re-derived independently from that doc comment and the function's own
// two explicit refusal checks:
//
//  1. Never panics on any byte content.
//  2. Returns a non-nil error whenever the trimmed file content is empty,
//     OR is neither valid non-empty hex NOR valid non-empty base64.
//  3. Whenever it returns a non-nil error, the returned key is always nil
//     -- no partial or garbage key may leak through a refused read.
//  4. On success, the returned key exactly matches decoding the trimmed
//     content as hex (tried first) or, only if that fails, base64 --
//     re-deriving the function's own documented precedence independently.
func FuzzCheckpointKeyFileParse(f *testing.F) {
	seeds := [][]byte{
		[]byte("deadbeef"),
		[]byte("  deadbeef  \n"),
		[]byte(""),
		[]byte("   "),
		[]byte("not-hex-not-base64!!"),
		[]byte("YWJjZGVm"), // valid base64, not valid hex
		[]byte("00"),
		[]byte("\x00\x01\xff"),
		[]byte("0"), // odd-length hex -- invalid hex, also invalid base64
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "checkpoint.key")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skipf("could not write fixture file: %v", err)
		}

		var key []byte
		var err error
		fuzzutil.Guard(t.Fatalf, "readCheckpointKeyFile", func() {
			key, err = readCheckpointKeyFile(path)
		})

		trimmed := strings.TrimSpace(string(data))

		if err != nil {
			if key != nil {
				t.Fatalf("readCheckpointKeyFile(%q) returned an error (%v) but a non-nil key: %x", trimmed, err, key)
			}
			return
		}
		if len(key) == 0 {
			t.Fatalf("readCheckpointKeyFile(%q) succeeded with an empty key", trimmed)
		}

		if hexKey, hexErr := hex.DecodeString(trimmed); hexErr == nil && len(hexKey) > 0 {
			if !bytes.Equal(key, hexKey) {
				t.Fatalf("readCheckpointKeyFile(%q) = %x, want hex-decoded %x (hex tried first)", trimmed, key, hexKey)
			}
			return
		}
		if b64Key, b64Err := base64.StdEncoding.DecodeString(trimmed); b64Err == nil && len(b64Key) > 0 {
			if !bytes.Equal(key, b64Key) {
				t.Fatalf("readCheckpointKeyFile(%q) = %x, want base64-decoded %x (base64 fallback)", trimmed, key, b64Key)
			}
			return
		}
		t.Fatalf("readCheckpointKeyFile(%q) succeeded but trimmed content is neither valid hex nor valid base64", trimmed)
	})
}
