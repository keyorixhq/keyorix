package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// #4217: the refusal for `--new-passphrase-file` named `--passphrase-file`. Every refusal
// and Describe must name the flag the operator typed, for the primary source and the
// "new-" one alike. The sources are filled through the real flag registration, so the
// test covers the wiring (RegisterPassphraseFlags -> PassphraseSource) as well as the text.
func TestPassphraseRefusalsNameTheFlagGiven(t *testing.T) {
	dir := t.TempDir()
	openFile := filepath.Join(dir, "open")
	if err := os.WriteFile(openFile, []byte("secret\n"), 0o644); err != nil { //nolint:gosec // deliberately too open
		t.Fatal(err)
	}
	if err := os.Chmod(openFile, 0o644); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	for _, prefix := range []string{"", "new-"} {
		pfx := "--" + prefix + "passphrase-"
		other := "--" + map[string]string{"": "new-", "new-": ""}[prefix] + "passphrase-"
		cases := []struct {
			name string
			args []string
			want string // text the error must contain
		}{
			{"file missing", []string{pfx + "file=" + missing}, pfx + "file"},
			{"file too open", []string{pfx + "file=" + openFile}, pfx + "file"},
			{"file empty", []string{pfx + "file=" + emptyFile}, pfx + "file"},
			{"fd unreadable", []string{pfx + "fd=987654"}, pfx + "fd"},
			{"nothing given", nil, pfx + "stdin"},
		}
		for _, tc := range cases {
			t.Run(prefix+tc.name, func(t *testing.T) {
				var src PassphraseSource
				fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
				RegisterPassphraseFlags(fs, &src, prefix, "master passphrase")
				if err := fs.Parse(tc.args); err != nil {
					t.Fatal(err)
				}
				t.Setenv("KEYORIX_TEST_PASSPHRASE_UNSET", "")
				_, err := ResolvePassphrase(src, "KEYORIX_TEST_PASSPHRASE_UNSET")
				if err == nil {
					t.Fatal("want a refusal, got none")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %q does not name %s", err, tc.want)
				}
				// A "new-" refusal must not name the primary flag, and the other way round.
				// (--new-passphrase-file contains --passphrase-file's tail, so match whole flags.)
				if prefix == "new-" && strings.Contains(strings.ReplaceAll(err.Error(), "--new-passphrase-", ""), "--passphrase-") {
					t.Errorf("error %q names a primary --passphrase-* flag", err)
				}
				if prefix == "" && strings.Contains(err.Error(), other) {
					t.Errorf("error %q names a --new-passphrase-* flag", err)
				}
				if len(tc.args) > 0 {
					if d := src.Describe("KEYORIX_TEST_PASSPHRASE_UNSET"); !strings.HasPrefix(d, tc.want) {
						t.Errorf("Describe() = %q, want it to start with %s", d, tc.want)
					}
				}
			})
		}
	}
}
