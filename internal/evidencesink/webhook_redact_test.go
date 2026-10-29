package evidencesink

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretEndpointFragments are the parts of the test endpoint that must never
// reach a log line or an error string; only scheme://host may.
var secretEndpointFragments = []string{"user", "tok3n", "/path", "key=secret", "secret"}

const secretEndpoint = "https://user:tok3n@evidence.example.test/path?key=secret"

func assertNoEndpointSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, frag := range secretEndpointFragments {
		assert.NotContains(t, s, frag, "%s leaks %q: %s", what, frag, s)
	}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

func TestWebhook_InsecureSkipVerifyWarningRedactsEndpoint(t *testing.T) {
	buf := captureLog(t)
	_, err := newWebhook(WebhookConfig{
		Endpoint:                  secretEndpoint,
		InsecureSkipVerify:        true,
		AllowPrivateNetworkTarget: true,
	}, time.Millisecond)
	require.NoError(t, err)
	out := buf.String()
	require.Contains(t, out, "TLS verification disabled", "the warning must still be logged")
	assert.Contains(t, out, "https://evidence.example.test")
	assertNoEndpointSecrets(t, "insecure-skip-verify warning", out)
}

func TestWebhook_ConstructionErrorsRedactEndpoint(t *testing.T) {
	cases := []struct {
		name string
		cfg  WebhookConfig
	}{
		{"unparsable", WebhookConfig{Endpoint: "https://user:tok3n@evidence.example.test:bad/path?key=secret"}},
		// url.Parse cuts the authority at the unescaped '/' and quotes the
		// password prefix as an invalid port in its inner error.
		{"unescaped slash in password", WebhookConfig{Endpoint: "https://user:tok3n/x@evidence.example.test/path?key=secret"}},
		{"plaintext http", WebhookConfig{Endpoint: "http://user:tok3n@evidence.example.test/path?key=secret"}},
		{"unsupported scheme", WebhookConfig{Endpoint: "ftp://user:tok3n@evidence.example.test/path?key=secret"}},
		{"private target", WebhookConfig{Endpoint: "https://user:tok3n@10.0.0.5/path?key=secret"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWebhook(tc.cfg)
			require.Error(t, err)
			assertNoEndpointSecrets(t, "construction error", err.Error())
			var ue *url.Error
			assert.False(t, errors.As(err, &ue), "error must not wrap a *url.Error (it quotes the full URL)")
		})
	}
}

func TestWebhook_DeliveryErrorsRedactEndpoint(t *testing.T) {
	// Port 1 on loopback refuses the connection, so client.Do returns a
	// *url.Error that embeds the full request URL.
	w, err := newWebhook(WebhookConfig{
		Endpoint:                  "http://user:tok3n@127.0.0.1:1/path?key=secret",
		AllowPrivateNetworkTarget: true,
	}, time.Millisecond)
	require.NoError(t, err)
	err = w.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), "")
	require.Error(t, err)
	assertNoEndpointSecrets(t, "delivery error", err.Error())
	var ue *url.Error
	assert.False(t, errors.As(err, &ue), "delivery error must not wrap a *url.Error")
	assert.True(t, strings.Contains(err.Error(), "127.0.0.1"), "host stays for diagnosis: %s", err)
}
