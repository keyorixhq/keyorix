package notifychan

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/envflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mirror of internal/delivery's smtp_tls_none_auth_test.go for the notification
// email channel: with tls=none go-mail never offers PLAIN/LOGIN, so the opt-in
// refusal must not claim relay credentials travel in cleartext, and a relay that
// offers only PLAIN/LOGIN must fail with the actual cause named.

const plainLoginNoTLSCause = "server offers only PLAIN/LOGIN and TLS is disabled"

func TestNewEmail_TLSNoneRefusalWording(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "")
	_, err := NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "none"})
	require.Error(t, err)
	msg := err.Error()

	cases := []struct {
		name    string
		check   func() bool
		explain string
	}{
		{"does not claim relay credentials travel in cleartext", func() bool { return !strings.Contains(msg, "relay credentials") }, "go-mail never sends PLAIN/LOGIN without TLS"},
		{"says the message is sent unencrypted", func() bool { return strings.Contains(msg, "unencrypted") }, "the notification itself does travel in cleartext"},
		{"names the PLAIN/LOGIN consequence", func() bool { return strings.Contains(msg, "PLAIN or LOGIN") }, "operators must learn why auth will fail"},
		{"still names the opt-in env var", func() bool { return strings.Contains(msg, envflag.AllowInsecureSMTP) }, "the refusal must say how to opt in"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, tc.check(), "%s; got: %q", tc.explain, msg)
		})
	}
}

// plainLoginOnlySMTPServer advertises only AUTH PLAIN LOGIN and no STARTTLS, and
// answers every connection (the retry engine redials) until the test ends.
func plainLoginOnlySMTPServer(t *testing.T) int {
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
				r := bufio.NewReader(conn)
				writeLine := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				writeLine("220 fake.smtp ESMTP ready")
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(line)
					switch {
					case strings.HasPrefix(cmd, "EHLO"):
						writeLine("250-fake.smtp")
						writeLine("250 AUTH PLAIN LOGIN")
					case strings.HasPrefix(cmd, "AUTH"):
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

func TestEmailSink_Send_TLSNonePlainLoginOnlyRelayNamesCause(t *testing.T) {
	port := plainLoginOnlySMTPServer(t)
	s := &EmailSink{cfg: EmailConfig{
		Host: "127.0.0.1", Port: port, From: "ops@x.io", TLS: "none",
		Username: "relay-user", Password: "relay-pass-placeholder",
	}}
	retryable, err := s.send(context.Background(), core.NotificationEvent{Email: "ada@x.io", Title: "t", Message: "m"})
	require.Error(t, err)
	assert.True(t, retryable, "retry classification is unchanged by the clearer message")
	assert.Contains(t, err.Error(), plainLoginNoTLSCause)
	assert.NotContains(t, err.Error(), "relay-pass-placeholder")
}

func TestEmailSink_TLSNonePlainLoginOnlyRelayLogsCause(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "true")
	port := plainLoginOnlySMTPServer(t)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	sink, err := newEmail(EmailConfig{
		Host: "127.0.0.1", Port: port, From: "ops@x.io", TLS: "none",
		Username: "relay-user", Password: "relay-pass-placeholder",
	}, time.Millisecond)
	require.NoError(t, err)
	require.True(t, sink.Deliver(core.NotificationEvent{Email: "ada@x.io", Title: "t", Message: "m"}))
	sink.Close()
	log.SetOutput(orig)

	// Close may abort the retry backoff, so the line is either "delivery failed"
	// or "delivery abandoned on shutdown" — both carry the send error.
	assert.Contains(t, buf.String(), "notifychan: email delivery")
	assert.Contains(t, buf.String(), plainLoginNoTLSCause, "the delivery-failure log must name the tls=none + PLAIN/LOGIN cause")
	assert.NotContains(t, buf.String(), "relay-pass-placeholder")
}
