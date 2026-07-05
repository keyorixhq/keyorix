package notifychan

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
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
	t.Setenv(envAllowInsecureSMTP, "")
	_, err := NewEmail(EmailConfig{Host: "smtp.x.io", From: "ops@x.io", TLS: "none"})
	require.Error(t, err, "cleartext SMTP must fail closed by default")

	t.Setenv(envAllowInsecureSMTP, "true")
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
	t.Setenv(envAllowInsecureSMTP, "true")
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
func TestEmailSink_BroadcastRoutesToConfiguredDestination(t *testing.T) {
	t.Setenv(envAllowInsecureSMTP, "true")
	before := emailOutcomeTotal(t)
	sink, err := NewEmail(EmailConfig{Host: "127.0.0.1", Port: 1, From: "ops@x.io", TLS: "none", BroadcastTo: "admin@x.io"})
	require.NoError(t, err)
	attempted := sink.Deliver(core.NotificationEvent{Type: "compliance.digest", Title: "digest", Message: "x"})
	assert.True(t, attempted, "a broadcast event must be routed to the configured destination, not dropped")
	sink.Close()
	assert.Equal(t, 1.0, emailOutcomeTotal(t)-before, "the attempted send (here, a failure) must be counted — not silent")
}
