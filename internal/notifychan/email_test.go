package notifychan

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
