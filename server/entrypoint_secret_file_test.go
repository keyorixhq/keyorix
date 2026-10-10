package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolveSecretFunc returns the resolve_secret shell function exactly as
// shipped in entrypoint.sh (between its BEGIN/END markers), so the test runs the
// real code, not a copy.
func resolveSecretFunc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("entrypoint.sh")
	require.NoError(t, err)
	s := string(b)
	begin := strings.Index(s, "# --- BEGIN resolve_secret")
	end := strings.Index(s, "# --- END resolve_secret ---")
	require.True(t, begin >= 0 && end > begin, "resolve_secret markers missing from entrypoint.sh")
	return s[begin:end]
}

// runResolve runs resolve_secret NAME in sh with the given extra environment and
// prints "rc=<status> value=<NAME>|<exported copy seen by a child>".
func runResolve(t *testing.T, env ...string) (out, errOut string) {
	t.Helper()
	if err := exec.Command("stat", "-c", "%a", ".").Run(); err != nil {
		t.Skip("stat -c is not available on this host (the entrypoint targets alpine/busybox and runs in Linux CI)")
	}
	script := resolveSecretFunc(t) + `
resolve_secret KX_SECRET
rc=$?
printf 'rc=%s value=[%s] child=[%s]' "$rc" "$KX_SECRET" "$(sh -c 'printf %s "$KX_SECRET"')"
`
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	_ = cmd.Run()
	return so.String(), se.String()
}

func entrypointSecret(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s")
	require.NoError(t, os.WriteFile(p, []byte(content), mode))
	require.NoError(t, os.Chmod(p, mode))
	return p
}

func TestEntrypointResolveSecret(t *testing.T) {
	t.Run("file value, one newline stripped, not exported", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "pa ss\n\n", 0o600))
		assert.Equal(t, "rc=0 value=[pa ss\n] child=[]", out)
	})
	t.Run("CRLF stripped as one terminator", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "pass\r\n", 0o400))
		assert.Equal(t, "rc=0 value=[pass] child=[]", out)
	})
	t.Run("direct env value untouched", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET=direct")
		assert.Contains(t, out, "rc=0 value=[direct]")
	})
	t.Run("neither set", func(t *testing.T) {
		out, _ := runResolve(t)
		assert.Equal(t, "rc=0 value=[] child=[]", out)
	})
	t.Run("both set refuses", func(t *testing.T) {
		out, errOut := runResolve(t, "KX_SECRET=direct", "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", 0o600))
		assert.Contains(t, out, "rc=1")
		assert.Contains(t, errOut, "both KX_SECRET and KX_SECRET_FILE")
		assert.NotContains(t, out+errOut, "TOPSECRET")
	})
	t.Run("missing file refuses", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+filepath.Join(t.TempDir(), "nope"))
		assert.Contains(t, out, "rc=1")
	})
	t.Run("empty file refuses", func(t *testing.T) {
		out, _ := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "\n", 0o600))
		assert.Contains(t, out, "rc=1")
	})
	for _, mode := range []os.FileMode{0o644, 0o604, 0o660, 0o640, 0o440} {
		t.Run("too open "+mode.String(), func(t *testing.T) {
			out, errOut := runResolve(t, "KX_SECRET_FILE="+entrypointSecret(t, "TOPSECRET\n", mode))
			assert.Contains(t, out, "rc=1", "own-file group access and any other access are refused")
			assert.Contains(t, errOut, "refusing to trust")
			assert.NotContains(t, out+errOut, "TOPSECRET")
		})
	}
}
