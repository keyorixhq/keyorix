package encryption

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureProviderStatusOutput(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func TestPrintProviderStatus_Password(t *testing.T) {
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{Type: "password"})
	})
	assert.Contains(t, out, "Key Provider: password")
	assert.Contains(t, out, "passphrase-derived")
}

func TestPrintProviderStatus_EmptyTypeDefaultsToPassword(t *testing.T) {
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{})
	})
	assert.Contains(t, out, "Key Provider: password")
}

func TestPrintProviderStatus_FileExists(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "kek")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{Type: "file", FilePath: f.Name()})
	})
	assert.Contains(t, out, "Key Provider: file")
	assert.Contains(t, out, f.Name())
	assert.Contains(t, out, "accessible ✅")
}

func TestPrintProviderStatus_FileMissing(t *testing.T) {
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{Type: "file", FilePath: "/nonexistent/kek.key"})
	})
	assert.Contains(t, out, "not accessible ❌")
}

func TestPrintProviderStatus_EnvSet(t *testing.T) {
	t.Setenv("_TEST_KEYORIX_KEK", "val")
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{Type: "env", EnvVar: "_TEST_KEYORIX_KEK"})
	})
	assert.Contains(t, out, "Key Provider: env")
	assert.Contains(t, out, "set ✅")
}

func TestPrintProviderStatus_EnvNotSet(t *testing.T) {
	t.Setenv("_TEST_KEYORIX_KEK_MISSING", "")
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{Type: "env", EnvVar: "_TEST_KEYORIX_KEK_MISSING"})
	})
	assert.Contains(t, out, "not set ❌")
}

func TestPrintProviderStatus_AWSKMS(t *testing.T) {
	out := captureProviderStatusOutput(t, func() {
		printProviderStatus(config.KeyProviderConfig{
			Type:     "aws-kms",
			KMSKeyID: "arn:aws:kms:eu-west-1:123:key/abc",
		})
	})
	assert.Contains(t, out, "Key Provider: aws-kms")
	assert.Contains(t, out, "arn:aws:kms")
}
