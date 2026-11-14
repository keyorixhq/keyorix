package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/secretenv"
)

// #4217: every --passphrase-file refusal named "--passphrase-file", also when
// the operator gave --new-passphrase-file (admin encryption rotate-kek). The
// refusal itself must stay a refusal; only the flag it names follows the flag
// that was given.
func TestPassphraseFileRefusals_NameTheFlagGiven(t *testing.T) {
	arms := []struct {
		name  string
		setup func(t *testing.T) (path string, restore func())
		want  string // a fragment that identifies the arm
	}{
		{"missing", func(t *testing.T) (string, func()) {
			return filepath.Join(t.TempDir(), "absent"), func() {}
		}, "opening"},
		{"unreadable", func(t *testing.T) (string, func()) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode 0000 file")
			}
			p := filepath.Join(t.TempDir(), "mp")
			require.NoError(t, os.WriteFile(p, []byte("pw\n"), 0o600))
			require.NoError(t, os.Chmod(p, 0o000))
			return p, func() {}
		}, "opening"},
		{"mode 0644", func(t *testing.T) (string, func()) {
			p := filepath.Join(t.TempDir(), "mp")
			require.NoError(t, os.WriteFile(p, []byte("pw\n"), 0o600))
			require.NoError(t, os.Chmod(p, 0o644))
			return p, func() {}
		}, "group- or world-readable"},
		{"wrong owner", func(t *testing.T) (string, func()) {
			p := filepath.Join(t.TempDir(), "mp")
			require.NoError(t, os.WriteFile(p, []byte("pw\n"), 0o600))
			return p, secretenv.OverrideOwnershipForTest(1000, 1001)
		}, "uid 1000"},
		{"empty", func(t *testing.T) (string, func()) {
			p := filepath.Join(t.TempDir(), "mp")
			require.NoError(t, os.WriteFile(p, nil, 0o600))
			return p, func() {}
		}, "is empty"},
		{"read error (over the size cap)", func(t *testing.T) (string, func()) {
			p := filepath.Join(t.TempDir(), "mp")
			require.NoError(t, os.WriteFile(p, []byte(strings.Repeat("a", 2<<20)), 0o600))
			return p, func() {}
		}, "too large"},
	}
	for _, prefix := range []string{"", "new-"} {
		flag := "--" + prefix + "passphrase-file"
		for _, arm := range arms {
			t.Run(flag+"/"+arm.name, func(t *testing.T) {
				p, restore := arm.setup(t)
				defer restore()

				var src PassphraseSource
				fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
				RegisterPassphraseFlags(fs, &src, prefix, "master passphrase")
				require.NoError(t, fs.Parse([]string{flag, p}))

				got, err := ResolvePassphrase(src, "KX_UNUSED")
				require.Error(t, err, "the refusal itself is unchanged: fail closed")
				assert.Nil(t, got)
				msg := err.Error()
				assert.Contains(t, msg, arm.want)
				assert.Contains(t, msg, flag+" ", "names the flag that was given")
				assert.Contains(t, msg, p, "names the file")
				if prefix == "" {
					assert.NotContains(t, msg, "--new-", "a plain --passphrase-file must not name the new- flag")
				} else {
					assert.NotContains(t, msg, `--passphrase-file`, "must not name the flag that was not given")
				}
			})
		}
	}
}
