package notifychan

import (
	"bytes"
	"fmt"
	"log"
	"net/url"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSanitizeDeliveryError_StripsTokenFromTransportError proves the #329 fix at
// the unit level: Go's *url.Error.Error() — exactly what http.Client returns on a
// transport-level failure (dial/timeout/TLS), the routine case a delivery-failure
// log line exists to report — embeds the full request URL, including a Slack/Teams
// incoming-webhook's bearer token (a URL path segment, not a header). The sanitized
// rendering must drop the token and path while keeping the host for diagnostics.
func TestSanitizeDeliveryError_StripsTokenFromTransportError(t *testing.T) {
	tokenURL := "https://hooks.slack.com/services/T000/B000/xoxb-super-secret-token"
	transportErr := &url.Error{Op: "Post", URL: tokenURL, Err: fmt.Errorf("dial tcp: connection refused")}

	got := sanitizeDeliveryError(transportErr)

	assert.NotContains(t, got, "xoxb-super-secret-token")
	assert.NotContains(t, got, "/services/T000/B000")
	assert.Contains(t, got, "hooks.slack.com", "host should be kept for diagnostic value")
	assert.Contains(t, got, "connection refused")
}

// TestSanitizeDeliveryError_PassesThroughURLFreeError proves the sanitizer is a
// no-op for an error that carries no embedded URL, so ordinary (non-webhook-URL)
// failure messages are unaffected.
func TestSanitizeDeliveryError_PassesThroughURLFreeError(t *testing.T) {
	err := fmt.Errorf("teams webhook returned 503 Service Unavailable")
	assert.Equal(t, err.Error(), sanitizeDeliveryError(err))
}

func TestSanitizeDeliveryError_NilErrReturnsEmptyString(t *testing.T) {
	assert.Equal(t, "", sanitizeDeliveryError(nil))
}

// TestChatSink_DeliveryFailureLogDoesNotLeakWebhookToken is the end-to-end
// regression for #329: a real transport failure (connection refused against a
// closed loopback port — no mocking of *url.Error) against a webhook URL carrying
// an embedded token must produce a log line that contains no trace of the token.
func TestChatSink_DeliveryFailureLogDoesNotLeakWebhookToken(t *testing.T) {
	const token = "xoxb-topsecret-1234567890"
	// Loopback http is allowed without insecure_skip_verify (see validateEndpoint);
	// port 1 is not listening, so every attempt fails fast with a genuine *url.Error.
	badURL := "http://127.0.0.1:1/services/T000/B000/" + token

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	sink, err := newChat(ChatConfig{Kind: ChatSlack, WebhookURL: badURL}, time.Millisecond)
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{Title: "x", Message: "y"})
	sink.Close() // blocks until the worker (incl. its log.Printf calls) has finished

	logged := buf.String()
	assert.Contains(t, logged, "notifychan:", "sanity: the failure path should still log something")
	assert.NotContains(t, logged, token, "the webhook's embedded bearer token must never reach the log stream")
	assert.NotContains(t, logged, "services/T000/B000", "the webhook's path (which carries the token) must never reach the log stream")
}
