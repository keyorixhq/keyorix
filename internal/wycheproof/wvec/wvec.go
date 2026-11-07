// Package wvec loads the pinned Wycheproof test vectors for the tests in
// internal/wycheproof. The vector files are not stored in the repository:
// scripts/wycheproof/fetch.sh downloads them from a pinned commit of
// github.com/C2SP/wycheproof and checks them against SHA256SUMS. Load checks
// the same hashes again on every read, so a stale or edited file is an error.
package wvec

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Commit is the C2SP/wycheproof commit the vectors come from.
const Commit = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"

//go:embed SHA256SUMS
var sumsFile string

// ErrMissing means the vector file has not been downloaded.
var ErrMissing = errors.New("wycheproof vectors not downloaded (run scripts/wycheproof/fetch.sh)")

// Hex is a byte string encoded as hex in the JSON files.
type Hex []byte

// UnmarshalJSON decodes a hex JSON string.
func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = d
	return nil
}

// Sums returns file name -> expected SHA-256 (hex).
func Sums() map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(sumsFile, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			m[f[1]] = f[0]
		}
	}
	return m
}

// Dir is the directory holding the downloaded vectors (WYCHEPROOF_DIR overrides).
func Dir() string {
	if d := os.Getenv("WYCHEPROOF_DIR"); d != "" {
		return d
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", "vectors")
}

// Load reads name from Dir, verifies its SHA-256 against SHA256SUMS and
// unmarshals it into v.
func Load(name string, v any) error {
	want, ok := Sums()[name]
	if !ok {
		return fmt.Errorf("wvec: %s is not listed in SHA256SUMS", name)
	}
	b, err := os.ReadFile(filepath.Join(Dir(), name)) // #nosec G304 -- test vector path, fixed names
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrMissing, name)
		}
		return err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("wvec: %s sha256 %s, want %s", name, got, want)
	}
	return json.Unmarshal(b, v)
}
