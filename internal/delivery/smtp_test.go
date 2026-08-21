package delivery

import (
	"bufio"
	"context"
	"net"
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

// startFakeSMTPServer starts a minimal SMTP relay on an ephemeral localhost port
// that speaks just enough of the protocol (EHLO/MAIL FROM/RCPT TO/DATA/QUIT) to
// let go-mail complete a real send, letting us exercise DeliverSetupLink's
// success path (Delivered=true) without a live external relay. It serves exactly
// one connection and stops on its own once that connection closes or the test ends.
func startFakeSMTPServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		writeLine := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		writeLine("220 fake.smtp ESMTP ready")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				writeLine("250 fake.smtp")
			case strings.HasPrefix(cmd, "MAIL FROM"):
				writeLine("250 2.1.0 OK")
			case strings.HasPrefix(cmd, "RCPT TO"):
				writeLine("250 2.1.5 OK")
			case strings.EqualFold(cmd, "NOOP"):
				// go-mail's checkConn sends NOOP before every send to verify the
				// connection is still alive; it must succeed or the client reports
				// "not connected to SMTP server" and never attempts the real send.
				writeLine("250 2.0.0 OK")
			case strings.EqualFold(cmd, "DATA"):
				writeLine("354 End data with <CR><LF>.<CR><LF>")
				for {
					dline, derr := reader.ReadString('\n')
					if derr != nil {
						return
					}
					if strings.TrimSpace(dline) == "." {
						writeLine("250 2.0.0 OK: queued as fake-id")
						break
					}
				}
			case strings.EqualFold(cmd, "RSET"):
				// sendSingleMsg RSETs the session between messages; must succeed.
				writeLine("250 2.0.0 OK")
			case strings.EqualFold(cmd, "QUIT"):
				writeLine("221 2.0.0 Bye")
				return
			default:
				writeLine("500 5.5.2 unrecognized command")
			}
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func TestSMTPDeliverSucceeds(t *testing.T) {
	// End-to-end against the fake relay above: a real send that succeeds must
	// report Delivered=true with no LinkForAdmin fallback (the link only needs
	// manual relay when sending fails).
	t.Setenv(EnvAllowInsecureSMTP, "true")
	port := startFakeSMTPServer(t)
	d, err := newSMTPDelivery(SMTPSettings{Host: "127.0.0.1", Port: port, From: "k@acme.io", TLS: "none"})
	require.NoError(t, err)

	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{
		RecipientEmail: "new@acme.io",
		Link:           "https://keyorix.acme.internal/auth/setup/kx_setup_ok",
	})
	require.NoError(t, err)
	assert.Equal(t, ChannelSMTP, res.Channel)
	assert.True(t, res.Delivered, "a successful send must report Delivered=true")
	assert.Empty(t, res.LinkForAdmin, "no manual-relay fallback is needed on a successful send")
}

func TestSMTPDeliverDegradesOnClientInitFailure(t *testing.T) {
	// Bypass newSMTPDelivery's validation (which requires Host != "") to construct
	// an SMTPDelivery whose buildMessage succeeds (From/To don't touch Host) but
	// whose newClient fails (go-mail's NewClient rejects an empty host with
	// ErrNoHostname). DeliverSetupLink must still degrade to manual relay rather
	// than surfacing an error.
	d := &SMTPDelivery{cfg: SMTPSettings{From: "k@acme.io"}}
	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{
		RecipientEmail: "new@acme.io",
		Link:           "https://keyorix.acme.internal/auth/setup/kx_setup_noclient",
	})
	require.NoError(t, err, "client-init failure degrades gracefully, never errors")
	assert.Equal(t, ChannelSMTP, res.Channel)
	assert.False(t, res.Delivered)
	assert.Equal(t, "https://keyorix.acme.internal/auth/setup/kx_setup_noclient", res.LinkForAdmin)
}

func TestSMTPDeliverRejectsEmptyInput(t *testing.T) {
	d, err := newSMTPDelivery(SMTPSettings{Host: "127.0.0.1", From: "k@acme.io"})
	require.NoError(t, err)
	_, err = d.DeliverSetupLink(context.Background(), SetupLinkRequest{RecipientEmail: "x@y.io"})
	require.Error(t, err, "empty link is a programming error, not a transient outage")
	_, err = d.DeliverSetupLink(context.Background(), SetupLinkRequest{Link: "https://x/y"})
	require.Error(t, err, "empty recipient is a programming error")
}
