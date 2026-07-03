package user

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withStdin redirects os.Stdin to a pipe pre-loaded with input for the duration of fn.
func withStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	defer func() { os.Stdin = orig }()

	go func() {
		_, _ = w.WriteString(input)
		_ = w.Close()
	}()

	fn()
}

func TestConfirmYesNo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"explicit yes", "yes\n", true},
		{"short y", "y\n", true},
		{"explicit no", "no\n", false},
		{"short n", "n\n", false},
		// A destructive prompt must fail CLOSED: a blank line (accidental Enter) or any
		// unrecognized input must never be treated as confirmation.
		{"blank line does not confirm", "\n", false},
		{"garbage does not confirm", "sure whatever\n", false},
		{"mixed case yes still confirms", "YES\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got bool
			withStdin(t, c.input, func() {
				got = confirmYesNo("Delete user 42?")
			})
			assert.Equal(t, c.want, got)
		})
	}
}

func TestDeleteCmd_HasForceBypassFlag(t *testing.T) {
	f := deleteCmd.Flags().Lookup("force")
	require.NotNil(t, f, "delete must expose --force to bypass the confirmation prompt for scripted use")
	assert.Equal(t, "false", f.DefValue, "confirmation must be required by default")
}
