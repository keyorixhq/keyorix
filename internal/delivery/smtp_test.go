package delivery

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSMTPDelivery(t *testing.T) {
	t.Run("requires host and from", func(t *testing.T) {
		_, err := newSMTPDelivery(SMTPSettings{From: "k@acme.io"})
		require.Error(t, err)
		_, err = newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io"})
		require.Error(t, err)
	})

	t.Run("rejects an unknown tls mode", func(t *testing.T) {
		_, err := newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io", TLS: "ssl-maybe"})
		require.Error(t, err)
	})

	t.Run("accepts the documented tls modes", func(t *testing.T) {
		t.Setenv(EnvAllowInsecureSMTP, "true")
		for _, m := range []string{"", "starttls", "implicit", "none", "STARTTLS"} {
			_, err := newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io", TLS: m})
			require.NoError(t, err, "tls=%q", m)
		}
	})

	t.Run("tls=none refuses to activate without the explicit opt-in env var", func(t *testing.T) {
		t.Setenv(EnvAllowInsecureSMTP, "")
		_, err := newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io", TLS: "none"})
		require.Error(t, err, "cleartext SMTP must fail closed by default")
	})

	t.Run("tls=none succeeds once the operator opts in", func(t *testing.T) {
		t.Setenv(EnvAllowInsecureSMTP, "true")
		_, err := newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io", TLS: "none"})
		require.NoError(t, err)
	})
}

func TestRenderBody(t *testing.T) {
	req := SetupLinkRequest{
		RecipientEmail:    "new@acme.io",
		DisplayName:       "Dana",
		Link:              "https://keyorix.acme.internal/auth/setup/kx_setup_abc123",
		InstallName:       "Acme Keyorix",
		Message:           "welcome aboard",
		AssignmentSummary: "developer on mobile-app",
	}
	plain, htmlBody := renderBody(req)

	t.Run("both parts carry the single-use link and context", func(t *testing.T) {
		for _, body := range []string{plain, htmlBody} {
			assert.Contains(t, body, req.Link)
			assert.Contains(t, body, "Acme Keyorix")
			assert.Contains(t, body, "Dana")
			assert.Contains(t, body, "developer on mobile-app")
			assert.Contains(t, body, "welcome aboard")
		}
	})

	t.Run("html carries no remote resources or tracking", func(t *testing.T) {
		lower := strings.ToLower(htmlBody)
		assert.NotContains(t, lower, "<img", "no images / tracking pixels")
		assert.NotContains(t, lower, "http://", "no plaintext-http resources")
		assert.NotContains(t, lower, "<script", "no scripts")
		assert.NotContains(t, lower, "background:url", "no remote CSS resources")
		// Every https URL in the document is the trusted setup link (it appears twice:
		// once as the anchor href, once as the visible text — both the same link).
		assert.Equal(t, strings.Count(lower, strings.ToLower(req.Link)), strings.Count(lower, "https://"),
			"the setup link is the only URL in the document")
	})

	t.Run("never leaks a password or reusable credential", func(t *testing.T) {
		// Defensive: the request has no password field; assert the body has no such word
		// so a future field addition cannot silently start emailing one.
		assert.NotContains(t, strings.ToLower(plain), "password:")
		assert.NotContains(t, strings.ToLower(htmlBody), "password:")
	})
}

func TestRenderBodyDefaults(t *testing.T) {
	// Minimal request: no display name, install name, message, or summary.
	plain, htmlBody := renderBody(SetupLinkRequest{Link: "https://x/auth/setup/kx_setup_z"})
	assert.Contains(t, plain, "Hi there,")
	assert.Contains(t, plain, "Keyorix")
	assert.Contains(t, htmlBody, "Keyorix")
	assert.Contains(t, plain, "https://x/auth/setup/kx_setup_z")
}

func TestSubjectFor(t *testing.T) {
	assert.Equal(t, "Set up your Acme Keyorix access", subjectFor(SetupLinkRequest{InstallName: "Acme Keyorix"}))
	assert.Equal(t, "Set up your Keyorix access", subjectFor(SetupLinkRequest{}))
}

func TestSMTPDeliverDegradesOnSendFailure(t *testing.T) {
	// Point at a closed port on localhost: the dial fails fast (connection refused),
	// and delivery must degrade to manual relay rather than returning an error.
	t.Setenv(EnvAllowInsecureSMTP, "true")
	d, err := newSMTPDelivery(SMTPSettings{Host: "127.0.0.1", Port: 1, From: "k@acme.io", TLS: "none"})
	require.NoError(t, err)

	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{
		RecipientEmail: "new@acme.io",
		Link:           "https://keyorix.acme.internal/auth/setup/kx_setup_abc",
	})
	require.NoError(t, err, "send failure degrades gracefully, never errors")
	assert.Equal(t, ChannelSMTP, res.Channel)
	assert.False(t, res.Delivered)
	assert.Equal(t, "https://keyorix.acme.internal/auth/setup/kx_setup_abc", res.LinkForAdmin)
}

func TestSMTPDeliverRejectsEmptyInput(t *testing.T) {
	d, err := newSMTPDelivery(SMTPSettings{Host: "127.0.0.1", From: "k@acme.io"})
	require.NoError(t, err)
	_, err = d.DeliverSetupLink(context.Background(), SetupLinkRequest{RecipientEmail: "x@y.io"})
	require.Error(t, err, "empty link is a programming error, not a transient outage")
	_, err = d.DeliverSetupLink(context.Background(), SetupLinkRequest{Link: "https://x/y"})
	require.Error(t, err, "empty recipient is a programming error")
}
