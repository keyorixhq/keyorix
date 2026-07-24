// export_import_encrypt_coverage_test.go — coverage for the encrypted-export
// feature paths that are exercised through writeEncryptedJSON, runExport
// (encrypted-json branch), collectEntries (--decrypt-with branch), and
// parseJSONBytes.
package secret

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── writeEncryptedJSON ────────────────────────────────────────────────────────

// TestWriteEncryptedJSON_RoundTrip verifies that writeEncryptedJSON produces
// a valid encrypted envelope that can be decrypted back to the original secrets.
func TestWriteEncryptedJSON_RoundTrip(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	secrets := []exportedSecret{
		{ID: 1, Name: "DB_PASSWORD", Value: "s3cr3t"},
		{ID: 2, Name: "API_KEY", Value: "sk_live_abc"},
	}

	var buf bytes.Buffer
	require.NoError(t, writeEncryptedJSON(&buf, secrets, pubPath))

	// Decrypt and verify that both keys are present.
	plain, err := decryptExport(buf.Bytes(), privPath)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(plain, &m))

	assert.Equal(t, "s3cr3t", m["DB_PASSWORD"])
	assert.Equal(t, "sk_live_abc", m["API_KEY"])
}

// TestWriteEncryptedJSON_BadPubKey verifies that writeEncryptedJSON propagates
// errors from encryptExport (e.g. an unreadable public key path).
func TestWriteEncryptedJSON_BadPubKey(t *testing.T) {
	secrets := []exportedSecret{{ID: 1, Name: "K", Value: "V"}}
	var buf bytes.Buffer
	err := writeEncryptedJSON(&buf, secrets, filepath.Join(t.TempDir(), "missing.pem"))
	require.Error(t, err)
}

// TestWriteEncryptedJSON_WriterError verifies that writeEncryptedJSON
// propagates a write error when the underlying io.Writer fails.
func TestWriteEncryptedJSON_WriterError(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	secrets := []exportedSecret{{ID: 1, Name: "K", Value: "V"}}
	err := writeEncryptedJSON(&failWriter{}, secrets, pubPath)
	require.Error(t, err)
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (f *failWriter) Write(p []byte) (int, error) {
	return 0, bytes.ErrTooLarge
}

// ── runExport — encrypted-json branch ────────────────────────────────────────

// newExportTestServer returns a minimal HTTP test server that satisfies the
// three API calls runExport makes (projects, environments, secrets list, secret
// value fetch).
func newExportTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"default"}]}}`))
		case r.URL.Path == "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"production"}]}}`))
		case r.URL.Path == "/api/v1/secrets" || r.URL.Query().Get("project_id") != "":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":5,"name":"DB_PASSWORD"}]}}`))
		case r.URL.Path == "/api/v1/secrets/5":
			_, _ = w.Write([]byte(`{"data":{"value":"hunter2"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestRunExport_EncryptedJSONFormat exercises the encrypted-json branch of
// runExport: it sets --format encrypted-json and --encrypt-for and verifies
// that the output is a valid encrypted envelope rather than plaintext JSON.
func TestRunExport_EncryptedJSONFormat(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	srv := newExportTestServer(t)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "secrets.enc.json")

	// Save and restore global export flags.
	origFormat, origOutput, origEnv, origProject, origEncFor :=
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor
	exportFormat = "encrypted-json"
	exportOutput = outPath
	exportEnv = "production"
	exportProject = "default"
	exportEncryptFor = pubPath
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor =
			origFormat, origOutput, origEnv, origProject, origEncFor
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	require.NoError(t, runExport(cmd, nil))

	// The output file must be a valid encrypted envelope.
	data, err := os.ReadFile(outPath) // #nosec G304 -- test-controlled path
	require.NoError(t, err)

	plain, err := decryptExport(data, privPath)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(plain, &m))
	assert.Equal(t, "hunter2", m["DB_PASSWORD"])
}

// TestRunExport_EncryptForAutoSwitchesFormat verifies that when --encrypt-for
// is set but --format is not explicitly "encrypted-json", runExport
// auto-switches the format to encrypted-json.
func TestRunExport_EncryptForAutoSwitchesFormat(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	srv := newExportTestServer(t)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	dir := t.TempDir()
	outPath := filepath.Join(dir, "secrets_auto.enc.json")

	origFormat, origOutput, origEnv, origProject, origEncFor :=
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor
	// Use "json" (not "encrypted-json") to trigger the auto-switch code path.
	exportFormat = "json"
	exportOutput = outPath
	exportEnv = "production"
	exportProject = "default"
	exportEncryptFor = pubPath
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor =
			origFormat, origOutput, origEnv, origProject, origEncFor
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	require.NoError(t, runExport(cmd, nil))

	data, err := os.ReadFile(outPath) // #nosec G304 -- test-controlled path
	require.NoError(t, err)

	plain, err := decryptExport(data, privPath)
	require.NoError(t, err)

	var m map[string]string
	require.NoError(t, json.Unmarshal(plain, &m))
	assert.Equal(t, "hunter2", m["DB_PASSWORD"])
}

// TestRunExport_EncryptedJSON_ListSecretsError verifies that runExport returns
// an error when the secrets list API call fails (encrypted-json format path).
func TestRunExport_EncryptedJSON_ListSecretsError(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	// Server returns OK for projects/environments but 500 for the secrets list.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"default"}]}}`))
		case r.URL.Path == "/api/v1/environments":
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"production"}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origFormat, origOutput, origEnv, origProject, origEncFor :=
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor
	exportFormat = "encrypted-json"
	exportOutput = ""
	exportEnv = "production"
	exportProject = "default"
	exportEncryptFor = pubPath
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor =
			origFormat, origOutput, origEnv, origProject, origEncFor
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runExport(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list secrets")
}

// TestRunExport_EncryptedJSON_MissingEncryptFor verifies that runExport returns
// an error when the format is encrypted-json but --encrypt-for is empty.
func TestRunExport_EncryptedJSON_MissingEncryptFor(t *testing.T) {
	srv := newExportTestServer(t)
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origFormat, origOutput, origEnv, origProject, origEncFor :=
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor
	exportFormat = "encrypted-json"
	exportOutput = ""
	exportEnv = "production"
	exportProject = "default"
	exportEncryptFor = "" // intentionally empty
	defer func() {
		exportFormat, exportOutput, exportEnv, exportProject, exportEncryptFor =
			origFormat, origOutput, origEnv, origProject, origEncFor
	}()

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := runExport(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--encrypt-for")
}

// ── parseJSONBytes ────────────────────────────────────────────────────────────

// TestParseJSONBytes_HappyPath verifies that parseJSONBytes correctly parses a
// flat key-value JSON object from bytes.
func TestParseJSONBytes_HappyPath(t *testing.T) {
	data := []byte(`{"DB_PASSWORD":"hunter2","API_KEY":"sk_live_abc"}`)
	entries, err := parseJSONBytes(data)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	m := make(map[string]string)
	for _, e := range entries {
		m[e.Name] = e.Value
	}
	assert.Equal(t, "hunter2", m["DB_PASSWORD"])
	assert.Equal(t, "sk_live_abc", m["API_KEY"])
}

// TestParseJSONBytes_InvalidJSON verifies that parseJSONBytes returns an error
// for non-JSON input.
func TestParseJSONBytes_InvalidJSON(t *testing.T) {
	_, err := parseJSONBytes([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

// TestParseJSONBytes_SkipsEmptyKeyOrValue verifies that parseJSONBytes silently
// skips entries with an empty key or empty string value.
func TestParseJSONBytes_SkipsEmptyKeyOrValue(t *testing.T) {
	// "" key, and an entry whose stringified value is "".
	data := []byte(`{"":"empty_key","REAL_KEY":"real_value"}`)
	entries, err := parseJSONBytes(data)
	require.NoError(t, err)
	// Only REAL_KEY should be returned; the empty-key entry is skipped.
	require.Len(t, entries, 1)
	assert.Equal(t, "REAL_KEY", entries[0].Name)
}

// TestParseJSONBytes_RejectsControlCharInKey verifies that parseJSONBytes
// rejects a JSON object whose key contains an ANSI escape sequence.
func TestParseJSONBytes_RejectsControlCharInKey(t *testing.T) {
	data, err := json.Marshal(map[string]string{
		"DB_" + string(rune(0x1B)) + "[2KPASSWORD": "hunter2",
	})
	require.NoError(t, err)
	_, err = parseJSONBytes(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret name")
}

// TestParseJSONBytes_RejectsControlCharInValue verifies that parseJSONBytes
// rejects a JSON object whose value contains a dangerous control character.
func TestParseJSONBytes_RejectsControlCharInValue(t *testing.T) {
	data, err := json.Marshal(map[string]string{
		"API_KEY": "sk_live_" + string(rune(0x1B)) + "[2Kfake",
	})
	require.NoError(t, err)
	_, err = parseJSONBytes(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API_KEY")
}

// ── collectEntries — encrypted-json decrypt branch ────────────────────────────

// makeCompactEnvelope encrypts plainJSON and returns a compact (non-indented)
// JSON encoding of the envelope. This is needed because collectEntries uses a
// byte-prefix check for the compact form `{"format":"...` — the indented form
// produced by encryptExport (which uses MarshalIndent) does not start with
// that exact prefix, so the detection would fall through to parseFile instead.
func makeCompactEnvelope(t *testing.T, plainJSON []byte, pubPath string) []byte {
	t.Helper()
	indented, err := encryptExport(plainJSON, pubPath)
	if err != nil {
		t.Fatalf("encryptExport: %v", err)
	}
	// Re-encode as compact JSON so the prefix check fires.
	var env encryptedExportEnvelope
	if err := json.Unmarshal(indented, &env); err != nil {
		t.Fatalf("unmarshal envelope for compaction: %v", err)
	}
	compact, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("compact marshal: %v", err)
	}
	return compact
}

// TestCollectEntries_DecryptWithFlag exercises the collectEntries code path
// where --file is an encrypted-json envelope and --decrypt-with provides the
// private key path. The function should transparently decrypt and parse the
// inner JSON.
func TestCollectEntries_DecryptWithFlag(t *testing.T) {
	priv, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)
	privPath := writePKCS1PrivKey(t, priv)

	// Encrypt a small JSON payload into a compact envelope (matching what
	// collectEntries looks for with its byte-prefix check).
	plainJSON := []byte(`{"DB_PASSWORD":"hunter2","API_KEY":"sk_live_abc"}`)
	envelope := makeCompactEnvelope(t, plainJSON, pubPath)

	// Write the envelope to a temp file.
	encFile := filepath.Join(t.TempDir(), "secrets.enc.json")
	require.NoError(t, os.WriteFile(encFile, envelope, 0o600))

	// Wire the global import flags.
	origFile, origDecrypt, origSource :=
		importFile, importDecryptWith, importSource
	importFile = encFile
	importDecryptWith = privPath
	importSource = ""
	defer func() {
		importFile, importDecryptWith, importSource =
			origFile, origDecrypt, origSource
	}()

	entries, err := collectEntries(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 2)

	m := make(map[string]string)
	for _, e := range entries {
		m[e.Name] = e.Value
	}
	assert.Equal(t, "hunter2", m["DB_PASSWORD"])
	assert.Equal(t, "sk_live_abc", m["API_KEY"])
}

// TestCollectEntries_DecryptWithFlag_BadKey verifies that collectEntries
// returns an error when --decrypt-with points to the wrong RSA private key.
func TestCollectEntries_DecryptWithFlag_BadKey(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	pubPath := writePKCS1PubKey(t, pub)

	wrongPriv, _ := generateTestKeyPair(t)
	wrongPrivPath := writePKCS1PrivKey(t, wrongPriv)

	plainJSON := []byte(`{"K":"V"}`)
	envelope := makeCompactEnvelope(t, plainJSON, pubPath)

	encFile := filepath.Join(t.TempDir(), "secrets.enc.json")
	require.NoError(t, os.WriteFile(encFile, envelope, 0o600))

	origFile, origDecrypt, origSource :=
		importFile, importDecryptWith, importSource
	importFile = encFile
	importDecryptWith = wrongPrivPath
	importSource = ""
	defer func() {
		importFile, importDecryptWith, importSource =
			origFile, origDecrypt, origSource
	}()

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

// TestCollectEntries_DecryptWithFlag_NotEncryptedEnvelope verifies that when
// --decrypt-with is set but the file does not start with the encrypted envelope
// marker, collectEntries falls through to the standard parseFile path and
// successfully parses the plain file.
func TestCollectEntries_DecryptWithFlag_NotEncryptedEnvelope(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	privPath := writePKCS1PrivKey(t, priv)

	// Write a plain dotenv file — NOT an encrypted envelope.
	plainFile := filepath.Join(t.TempDir(), "plain.env")
	require.NoError(t, os.WriteFile(plainFile, []byte("DB_PASSWORD=hunter2\n"), 0o600))

	origFile, origDecrypt, origSource, origFmt :=
		importFile, importDecryptWith, importSource, importFormat
	importFile = plainFile
	importDecryptWith = privPath
	importSource = ""
	importFormat = "dotenv"
	defer func() {
		importFile, importDecryptWith, importSource, importFormat =
			origFile, origDecrypt, origSource, origFmt
	}()

	entries, err := collectEntries(context.Background())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "DB_PASSWORD", entries[0].Name)
	assert.Equal(t, "hunter2", entries[0].Value)
}

// TestCollectEntries_ParseFileError verifies that collectEntries returns an
// error when parseFile fails (e.g. unsupported format). This exercises the
// error branch at the end of the importFile case in collectEntries.
func TestCollectEntries_ParseFileError(t *testing.T) {
	plainFile := filepath.Join(t.TempDir(), "data.yml")
	require.NoError(t, os.WriteFile(plainFile, []byte("key: value\n"), 0o600))

	origFile, origDecrypt, origSource, origFmt :=
		importFile, importDecryptWith, importSource, importFormat
	importFile = plainFile
	importDecryptWith = "" // no decryption
	importSource = ""
	importFormat = "unsupported-xyz" // will cause parseFile to fail
	defer func() {
		importFile, importDecryptWith, importSource, importFormat =
			origFile, origDecrypt, origSource, origFmt
	}()

	_, err := collectEntries(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}
