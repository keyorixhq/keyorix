package notifychan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/envflag"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emailOutcomeTotal sums every terminal outcome counter for the email channel.
func emailOutcomeTotal(t *testing.T) float64 {
	t.Helper()
	var sum float64
	for _, o := range []string{outcomeDelivered, outcomeFailed, outcomeDropped} {
		sum += testutil.ToFloat64(notifyDeliveries.WithLabelValues("email", o))
	}
	return sum
}

func TestRenderEmail(t *testing.T) {
	subject, body := renderEmail(core.NotificationEvent{
		Title: "Access recertification", Message: "Project Payments is due for review.", Link: "/projects/3",
	})
	assert.Equal(t, "Access recertification", subject)
	assert.Contains(t, body, "due for review")
	assert.Contains(t, body, "/projects/3")
}

func TestRenderEmail_DefaultsSubject(t *testing.T) {
	subject, _ := renderEmail(core.NotificationEvent{Message: "x"})
	assert.Equal(t, "Keyorix notification", subject)
}

func TestNewEmail_Validation(t *testing.T) {
	_, err := NewEmail(EmailConfig{From: "ops@x.io"}) // missing host
	require.Error(t, err)

	_, err = NewEmail(EmailConfig{Host: "smtp.x.io"}) // missing from
	require.Error(t, err)

	_, err = NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "bogus"})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "tls"))

	s, err := NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "starttls"})
	require.NoError(t, err)
	s.Close()
}

func TestNewEmail_TLSNoneRequiresExplicitOptIn(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "")
	_, err := NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "none"})
	require.Error(t, err, "cleartext SMTP must fail closed by default")

	t.Setenv(envflag.AllowInsecureSMTP, "true")
	s, err := NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "none"})
	require.NoError(t, err, "tls=none must succeed once the operator opts in")
	s.Close()
}

// TestEmailSink_BroadcastWithNoDestinationConfiguredIsDroppedAndCounted is a
// regression test for #221: an event with no per-user Email and no configured
// BroadcastTo (an email-only deployment with the compliance digest / rotation-
// failure alerts and nothing else configured) has genuinely nowhere to go. It must
// still be dropped before it ever enqueues (the worker never dials SMTP for it) —
// but unlike before the fix, the drop is no longer silent: Deliver reports it was
// NOT attempted, and it produces a "dropped" delivery outcome an operator can alert
// on, instead of leaving zero trace anywhere.
func TestEmailSink_BroadcastWithNoDestinationConfiguredIsDroppedAndCounted(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "true")
	before := emailOutcomeTotal(t)
	sink, err := NewEmail(EmailConfig{Host: "smtp.invalid", From: "ops@x.io", TLS: "none"})
	require.NoError(t, err)
	attempted := sink.Deliver(core.NotificationEvent{Type: "compliance.digest", Title: "no recipient, no broadcast_to", Message: "x"})
	sink.Close()
	assert.False(t, attempted, "no recipient and no broadcast_to means genuinely nowhere to send")
	assert.Equal(t, 1.0, emailOutcomeTotal(t)-before, "the drop must be counted, not silent (#221)")
}

// TestEmailSink_BroadcastRoutesToConfiguredDestination is a regression test for
// #221: a broadcast event (no per-user Email — compliance digest / rotation-failure
// alert) must be routed to the operator-configured BroadcastTo address rather than
// dropped, when email is the channel carrying it. The SMTP host here is an
// immediately-refusing closed port (mirrors internal/delivery's smtp_test.go
// pattern) so the send fails fast and deterministically; the point of this test is
// that delivery was ATTEMPTED (and the resulting failure counted), not that it
// succeeded.
// TestEmailSink_Send_InvalidFromAddressIsPermanentFailure proves an unparsable
// From address (email.go doesn't validate the format at construction, only that
// it's non-empty) fails send() immediately, before ever dialing SMTP, and is
// reported as a permanent (non-retryable) failure rather than a transient one —
// retrying a malformed address would never succeed.
func TestEmailSink_Send_InvalidFromAddressIsPermanentFailure(t *testing.T) {
	s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", From: "not-an-email", TLS: "starttls"}}
	retryable, err := s.send(context.Background(), core.NotificationEvent{Email: "ada@x.io"})
	require.Error(t, err)
	assert.False(t, retryable, "a malformed from address is a permanent misconfiguration, not worth retrying")
	assert.Contains(t, err.Error(), "not-an-email")
}

// TestEmailSink_Send_InvalidRecipientIsPermanentFailure is the mirror of the
// above for the recipient address (ev.Email, which callers resolve — never
// validated up front).
func TestEmailSink_Send_InvalidRecipientIsPermanentFailure(t *testing.T) {
	s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", From: "ops@x.io", TLS: "starttls"}}
	retryable, err := s.send(context.Background(), core.NotificationEvent{Email: "not-an-email"})
	require.Error(t, err)
	assert.False(t, retryable, "a malformed recipient address is a permanent misconfiguration, not worth retrying")
	assert.Contains(t, err.Error(), "not-an-email")
}

// TestEmailSink_Send_NewClientErrorIsPermanentFailure proves that a client-
// construction error (here, an out-of-range port passed straight through to
// go-mail's WithPort option) surfaces from send() as a permanent failure — it's
// a fixed misconfiguration, not a network blip retrying would fix.
func TestEmailSink_Send_NewClientErrorIsPermanentFailure(t *testing.T) {
	s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", Port: 99999, From: "ops@x.io", TLS: "starttls"}}
	retryable, err := s.send(context.Background(), core.NotificationEvent{Email: "ada@x.io"})
	require.Error(t, err)
	assert.False(t, retryable)
}

// TestEmailSink_NewClient_InvalidPort proves newClient itself surfaces go-mail's
// port validation error rather than swallowing it.
func TestEmailSink_NewClient_InvalidPort(t *testing.T) {
	s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", Port: -5, TLS: "starttls"}}
	// Port <= 0 is never forwarded to WithPort (see newClient), so an
	// out-of-range NEGATIVE port is silently ignored — client construction
	// still succeeds with the default port. This documents that behavior.
	c, err := s.newClient()
	require.NoError(t, err)
	assert.Equal(t, "smtp.example.com:25", c.ServerAddr(), "a non-positive configured port falls back to go-mail's default")

	s2 := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", Port: 99999, TLS: "starttls"}}
	_, err = s2.newClient()
	require.Error(t, err, "an out-of-range positive port must be rejected, not silently clamped")
}

// TestEmailSink_NewClient_TLSModes proves each documented tls setting selects
// the TLS policy go-mail will actually enforce when it dials — asserted via
// go-mail's own TLSPolicy() getter, not by re-implementing the switch.
func TestEmailSink_NewClient_TLSModes(t *testing.T) {
	cases := []struct {
		tls        string
		wantPolicy string
	}{
		{"", "TLSMandatory"},
		{"starttls", "TLSMandatory"},
		{"STARTTLS", "TLSMandatory"}, // case-insensitive
		{"implicit", "TLSMandatory"}, // WithSSL doesn't touch the STARTTLS policy field
		{"none", "NoTLS"},
	}
	for _, tc := range cases {
		t.Run(tc.tls, func(t *testing.T) {
			s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", Port: 2525, TLS: tc.tls}}
			c, err := s.newClient()
			require.NoError(t, err)
			assert.Equal(t, tc.wantPolicy, c.TLSPolicy())
			assert.Equal(t, "smtp.example.com:2525", c.ServerAddr())
		})
	}
}

// TestEmailSink_NewClient_UsernameConfiguresAuth proves a configured Username
// takes the SMTP-auth branch of newClient without erroring — it's a completely
// separate code path from the no-auth default (internal relays that authenticate
// by network, no Username set) exercised by every other test in this file.
func TestEmailSink_NewClient_UsernameConfiguresAuth(t *testing.T) {
	s := &EmailSink{cfg: EmailConfig{Host: "smtp.example.com", Username: "relay-user", Password: "relay-pass", TLS: "none"}}
	c, err := s.newClient()
	require.NoError(t, err)
	assert.Equal(t, "smtp.example.com:25", c.ServerAddr())
}

// fakeSMTPServer starts a minimal SMTP server on a loopback port that accepts
// exactly one message end-to-end (EHLO → MAIL FROM → RCPT TO → DATA → QUIT,
// "250 OK" at every step), so a test can drive email.go's send() all the way
// through a genuine successful DialAndSendWithContext — the one outcome no
// other test in this file reaches, since every other test points at a
// closed/refusing port to exercise the failure path instead.
func fakeSMTPServer(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return // listener closed by t.Cleanup
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		_, _ = fmt.Fprint(conn, "220 fake.smtp ESMTP ready\r\n")
		for {
			line, readErr := r.ReadString('\n')
			if readErr != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				_, _ = fmt.Fprint(conn, "250 fake.smtp Hello\r\n")
			case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
				_, _ = fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				_, _ = fmt.Fprint(conn, "354 Send data\r\n")
				for {
					dl, dataErr := r.ReadString('\n')
					if dataErr != nil {
						return
					}
					if strings.TrimRight(dl, "\r\n") == "." {
						break
					}
				}
				_, _ = fmt.Fprint(conn, "250 OK: queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = fmt.Fprint(conn, "221 Bye\r\n")
				return
			default:
				_, _ = fmt.Fprint(conn, "250 OK\r\n")
			}
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

// TestEmailSink_Send_DeliversAgainstFakeSMTPServer proves send() reports success
// (no error) when the SMTP relay actually accepts the message end-to-end —
// email.go:153's `return false, nil`, the terminal-success statement every other
// test in this file leaves uncovered because they all point send() at a
// refusing/closed port to exercise the failure path.
func TestEmailSink_Send_DeliversAgainstFakeSMTPServer(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "true")
	host, port := fakeSMTPServer(t)

	delivBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("email", outcomeDelivered))

	sink, err := newEmail(EmailConfig{Host: host, Port: port, From: "ops@x.io", TLS: "none"}, time.Millisecond)
	require.NoError(t, err)
	attempted := sink.Deliver(core.NotificationEvent{Email: "ada@x.io", Title: "hi", Message: "body"})
	require.True(t, attempted)
	sink.Close()

	assert.Equal(t, 1.0, testutil.ToFloat64(notifyDeliveries.WithLabelValues("email", outcomeDelivered))-delivBefore,
		"a genuine SMTP round-trip the server accepts must be counted as delivered, not failed")
}

func TestEmailSink_BroadcastRoutesToConfiguredDestination(t *testing.T) {
	t.Setenv(envflag.AllowInsecureSMTP, "true")
	before := emailOutcomeTotal(t)
	sink, err := NewEmail(EmailConfig{Host: "127.0.0.1", Port: 1, From: "ops@x.io", TLS: "none", BroadcastTo: "admin@x.io"})
	require.NoError(t, err)
	attempted := sink.Deliver(core.NotificationEvent{Type: "compliance.digest", Title: "digest", Message: "x"})
	assert.True(t, attempted, "a broadcast event must be routed to the configured destination, not dropped")
	sink.Close()
	assert.Equal(t, 1.0, emailOutcomeTotal(t)-before, "the attempted send (here, a failure) must be counted — not silent")
}
