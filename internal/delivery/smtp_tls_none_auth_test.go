package delivery

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With smtp.tls=none, go-mail's SMTPAuthAutoDiscover never offers PLAIN or LOGIN
// (it refuses to send a password over an unencrypted connection), so relay
// credentials are NOT sent in cleartext — but a relay that offers only those two
// mechanisms can never be authenticated against. These tests pin both halves:
// the opt-in refusal must not overstate the exposure, and the send failure must
// name the actual cause instead of go-mail's generic autodiscover error.

const plainLoginNoTLSCause = "server offers only PLAIN/LOGIN and TLS is disabled"

func TestNewSMTPDelivery_TLSNoneRefusalWording(t *testing.T) {
	t.Setenv(EnvAllowInsecureSMTP, "")
	_, err := newSMTPDelivery(SMTPSettings{Host: "smtp.acme.io", From: "k@acme.io", TLS: "none"})
	require.Error(t, err)
	msg := err.Error()

	cases := []struct {
		name    string
		check   func() bool
		explain string
	}{
		{"does not claim relay credentials travel in cleartext", func() bool { return !strings.Contains(msg, "relay credentials") }, "go-mail never sends PLAIN/LOGIN without TLS"},
		{"says the message is sent unencrypted", func() bool { return strings.Contains(msg, "unencrypted") }, "the setup link itself does travel in cleartext"},
		{"names the PLAIN/LOGIN consequence", func() bool { return strings.Contains(msg, "PLAIN or LOGIN") }, "operators must learn why auth will fail"},
		{"still names the opt-in env var", func() bool { return strings.Contains(msg, EnvAllowInsecureSMTP) }, "the refusal must say how to opt in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, tc.check(), "%s; got: %q", tc.explain, msg)
		})
	}
}

// startPlainLoginOnlySMTPServer is a relay that advertises only AUTH PLAIN LOGIN
// and no STARTTLS — the common dev-relay shape that cannot be used with
// smtp.tls=none plus a username. It answers every connection until the test ends.
func startPlainLoginOnlySMTPServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
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
					case strings.HasPrefix(cmd, "EHLO"):
						writeLine("250-fake.smtp")
						writeLine("250 AUTH PLAIN LOGIN")
					case strings.HasPrefix(cmd, "AUTH"):
						// Reaching this would mean a password was offered over cleartext.
						writeLine("535 5.7.8 unexpected AUTH")
					case strings.EqualFold(cmd, "QUIT"):
						writeLine("221 2.0.0 Bye")
						return
					default:
						writeLine("250 OK")
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSMTPDeliver_TLSNonePlainLoginOnlyRelayLogsCause(t *testing.T) {
	t.Setenv(EnvAllowInsecureSMTP, "true")
	port := startPlainLoginOnlySMTPServer(t)
	d, err := newSMTPDelivery(SMTPSettings{
		Host: "127.0.0.1", Port: port, From: "k@acme.io", TLS: "none",
		Username: "relay-user", Password: "relay-pass-placeholder",
	})
	require.NoError(t, err)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	link := "https://keyorix.acme.internal/auth/setup/kx_setup_plainonly"
	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{RecipientEmail: "new@acme.io", Link: link})
	log.SetOutput(orig)

	require.NoError(t, err, "send failure degrades gracefully, never errors")
	assert.False(t, res.Delivered)
	assert.Equal(t, link, res.LinkForAdmin, "the admin must still get the link for manual relay")
	assert.Contains(t, buf.String(), plainLoginNoTLSCause, "the log must name the tls=none + PLAIN/LOGIN cause")
	assert.NotContains(t, buf.String(), "relay-pass-placeholder", "the log must never carry the password")
}

func TestSMTPDeliver_OtherSendFailuresKeepGenericLog(t *testing.T) {
	// Connection refused is not an auth-discovery failure: no PLAIN/LOGIN hint.
	t.Setenv(EnvAllowInsecureSMTP, "true")
	d, err := newSMTPDelivery(SMTPSettings{Host: "127.0.0.1", Port: 1, From: "k@acme.io", TLS: "none", Username: "relay-user"})
	require.NoError(t, err)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	res, err := d.DeliverSetupLink(context.Background(), SetupLinkRequest{RecipientEmail: "new@acme.io", Link: "https://x/auth/setup/kx_setup_r"})
	log.SetOutput(orig)

	require.NoError(t, err)
	assert.False(t, res.Delivered)
	assert.Contains(t, buf.String(), "degrading to manual relay")
	assert.NotContains(t, buf.String(), plainLoginNoTLSCause)
}
