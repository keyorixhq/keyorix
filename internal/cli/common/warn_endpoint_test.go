// warn_endpoint_test.go — #G74: verifies WarnIfInsecureEndpoint prints the
// established cleartext-transmission warning for a non-HTTPS, non-loopback
// server URL, and stays silent for https:// (and loopback) endpoints. This is
// the shared helper that 'auth login', 'config set-remote', and 'system init
// --server' must all call before persisting or transmitting a real credential
// against a user-supplied server URL.
package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWarnIfInsecureEndpoint(t *testing.T) {
	t.Run("warns for a plaintext HTTP endpoint", func(t *testing.T) {
		out := captureStderr(t, func() {
			warned := WarnIfInsecureEndpoint("http://keyorix.example.com")
			assert.True(t, warned)
		})
		assert.Contains(t, out, "not HTTPS")
		assert.Contains(t, out, "cleartext")
		assert.Contains(t, out, "MITM-capturable")
	})

	t.Run("stays silent for an https endpoint", func(t *testing.T) {
		out := captureStderr(t, func() {
			warned := WarnIfInsecureEndpoint("https://keyorix.example.com")
			assert.False(t, warned)
		})
		assert.Empty(t, out)
	})

	t.Run("stays silent for a loopback HTTP endpoint (local testing)", func(t *testing.T) {
		out := captureStderr(t, func() {
			warned := WarnIfInsecureEndpoint("http://127.0.0.1:8080")
			assert.False(t, warned)
		})
		assert.Empty(t, out)
	})

	t.Run("stays silent for an empty endpoint", func(t *testing.T) {
		out := captureStderr(t, func() {
			warned := WarnIfInsecureEndpoint("")
			assert.False(t, warned)
		})
		assert.Empty(t, out)
	})
}
