package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// #4217 through rotate-kek itself: a too-open passphrase file is refused (fail closed) and
// the refusal names the flag the operator typed and, with both files supplied, the one that
// is actually refused. The sources are filled by the real flag registration, as the admin
// command does.
func TestRotateKEK_RefusalNamesTheFlagAndFileGiven(t *testing.T) {
	dir := chdirTemp(t)
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("pw-for-the-test-0123456789\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	source := func(prefix, path string) crypto.PassphraseSource {
		var src crypto.PassphraseSource
		fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
		crypto.RegisterPassphraseFlags(fs, &src, prefix, "master passphrase")
		if err := fs.Parse([]string{"--" + prefix + "passphrase-file=" + path}); err != nil {
			t.Fatal(err)
		}
		return src
	}

	oldOK, oldOpen := write("old-ok", 0o600), write("old-open", 0o644)
	newOK, newOpen := write("new-ok", 0o600), write("new-open", 0o644)

	cases := []struct {
		name         string
		oldF, newF   string
		wantFlagFile string // the refused flag and file
		notFlag      string // a flag that must not be named
	}{
		{"only the new file is open", oldOK, newOpen, "--new-passphrase-file " + `"` + newOpen + `"`, ""},
		{"only the old file is open", oldOpen, newOK, "--passphrase-file " + `"` + oldOpen + `"`, "--new-passphrase-file"},
		{"both open: the old one is refused first", oldOpen, newOpen, "--passphrase-file " + `"` + oldOpen + `"`, "--new-passphrase-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(MasterPassphraseEnvVar, "")
			t.Setenv(NewMasterPassphraseEnvVar, "")
			err := RotateKEKWithConfig(testConfig(true), true, source("", tc.oldF), source("new-", tc.newF))
			if err == nil {
				t.Fatal("a group-/world-readable passphrase file must be refused")
			}
			msg := err.Error()
			if !strings.Contains(msg, "group- or world-readable") {
				t.Errorf("want the permission refusal, got %q", msg)
			}
			if !strings.Contains(msg, tc.wantFlagFile) {
				t.Errorf("error %q must name %s", msg, tc.wantFlagFile)
			}
			if tc.notFlag != "" && strings.Contains(msg, tc.notFlag) {
				t.Errorf("error %q must not name %s", msg, tc.notFlag)
			}
		})
	}
}
