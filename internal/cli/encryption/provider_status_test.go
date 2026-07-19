package encryption

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
)

func captureProviderStatusOutput(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r) //nolint:errcheck
	return buf.String()
}

func TestPrintProviderStatus_Password(t *testing.T) {
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{Type: "password"})
	})
	assert.Contains(t, out, "Key Provider: password")
	assert.Contains(t, out, "passphrase-derived")
}

func TestPrintProviderStatus_EmptyTypeDefaultsToPassword(t *testing.T) {
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{})
	})
	assert.Contains(t, out, "Key Provider: password")
}

func TestPrintProviderStatus_FileExists(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "kek")
	f.Close()
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{Type: "file", FilePath: f.Name()})
	})
	assert.Contains(t, out, "Key Provider: file")
	assert.Contains(t, out, f.Name())
	assert.Contains(t, out, "accessible ✅")
}

func TestPrintProviderStatus_FileMissing(t *testing.T) {
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{Type: "file", FilePath: "/nonexistent/kek.key"})
	})
	assert.Contains(t, out, "not accessible ❌")
}

func TestPrintProviderStatus_EnvSet(t *testing.T) {
	t.Setenv("_TEST_KEYORIX_KEK", "val")
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{Type: "env", EnvVar: "_TEST_KEYORIX_KEK"})
	})
	assert.Contains(t, out, "Key Provider: env")
	assert.Contains(t, out, "set ✅")
}

func TestPrintProviderStatus_EnvNotSet(t *testing.T) {
	os.Unsetenv("_TEST_KEYORIX_KEK_MISSING") //nolint:errcheck
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{Type: "env", EnvVar: "_TEST_KEYORIX_KEK_MISSING"})
	})
	assert.Contains(t, out, "not set ❌")
}

func TestPrintProviderStatus_AWSKMS(t *testing.T) {
	out := captureProviderStatusOutput(func() {
		printProviderStatus(config.KeyProviderConfig{
			Type:     "aws-kms",
			KMSKeyID: "arn:aws:kms:eu-west-1:123:key/abc",
		})
	})
	assert.Contains(t, out, "Key Provider: aws-kms")
	assert.Contains(t, out, "arn:aws:kms")
}
