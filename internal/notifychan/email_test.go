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

func TestEmailSink_SkipsEventsWithoutRecipient(t *testing.T) {
	before := emailOutcomeTotal(t)
	sink, err := NewEmail(EmailConfig{Host: "smtp.invalid", From: "ops@x.io", TLS: "none"})
	require.NoError(t, err)
	// Email == "" — nothing to send to. It must be dropped before it ever enqueues,
	// so the worker never dials SMTP and no delivery outcome is recorded.
	sink.Deliver(core.NotificationEvent{Title: "no recipient", Message: "x"})
	sink.Close()
	assert.Equal(t, 0.0, emailOutcomeTotal(t)-before, "recipient-less events must not produce a delivery outcome")
}
