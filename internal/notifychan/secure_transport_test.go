package notifychan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateEndpoint_SSRFGuardIndependentOfInsecureSkipVerify is the fix under test:
// allowInsecure (InsecureSkipVerify at the WebhookConfig level) must relax ONLY the
// transport-security requirement (permit http / a self-signed cert) — it must NOT
// also relax the SSRF guard against private/link-local destination IPs. Previously
// both checks shared the same allowInsecure gate, so an operator setting
// insecure_skip_verify for a mundane self-signed-certificate reason would silently
// ALSO disable SSRF protection.
func TestValidateEndpoint_SSRFGuardIndependentOfInsecureSkipVerify(t *testing.T) {
	privateTargets := []string{
		"https://169.254.169.254/latest/meta-data/", // cloud metadata endpoint
		"https://10.0.0.5/hook",                     // RFC1918 private
		"https://192.168.1.10/hook",                 // RFC1918 private
		"https://172.16.0.1/hook",                   // RFC1918 private
	}

	for _, target := range privateTargets {
		// allowInsecure=false: rejected (already the pre-fix behavior).
		err := validateEndpoint(target, false)
		require.Error(t, err, target)
		assert.Contains(t, err.Error(), "private/link-local", target)

		// allowInsecure=true: THE FIX — must still be rejected. Before the fix, this
		// case incorrectly succeeded because allowInsecure gated the SSRF check too.
		err = validateEndpoint(target, true)
		require.Error(t, err, "%s must be rejected even with allowInsecure=true", target)
		assert.Contains(t, err.Error(), "private/link-local", target)
	}
}

// A loopback target is unaffected by the fix — it remains allowed regardless of
// allowInsecure, exactly as before (local testing).
func TestValidateEndpoint_LoopbackStillAllowed(t *testing.T) {
	assert.NoError(t, validateEndpoint("http://127.0.0.1:9000/hook", false))
	assert.NoError(t, validateEndpoint("http://127.0.0.1:9000/hook", true))
	assert.NoError(t, validateEndpoint("https://localhost:9000/hook", false))
}

// A public HTTPS endpoint is allowed either way — the fix does not narrow the
// legitimate, common case.
func TestValidateEndpoint_PublicHTTPSStillAllowed(t *testing.T) {
	assert.NoError(t, validateEndpoint("https://hooks.example.com/webhook", false))
	assert.NoError(t, validateEndpoint("https://hooks.example.com/webhook", true))
}

// allowInsecure still does its one legitimate job: permitting a non-loopback http
// (or, at the call site, a self-signed TLS cert) endpoint that is NOT on a
// private/link-local IP.
func TestValidateEndpoint_AllowInsecurePermitsHTTPForPublicHost(t *testing.T) {
	err := validateEndpoint("http://hooks.example.com/webhook", false)
	require.Error(t, err, "http to a public host requires the insecure opt-in")

	err = validateEndpoint("http://hooks.example.com/webhook", true)
	require.NoError(t, err, "the insecure opt-in still permits http for a public (non-private-IP) host")
}
