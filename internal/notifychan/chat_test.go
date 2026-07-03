package notifychan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureChatServer(t *testing.T) (*httptest.Server, func() []byte) {
	t.Helper()
	var mu sync.Mutex
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []byte {
		mu.Lock()
		defer mu.Unlock()
		return body
	}
}

func TestChatSink_SlackPayload(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
	require.NoError(t, err)
	pid := uint(3)
	sink.Deliver(core.NotificationEvent{Title: "Secrets due for rotation", Message: "2 overdue in Payments.", ProjectID: &pid, Link: "/rotation-policies"})
	sink.Close()

	var payload map[string]string
	require.NoError(t, json.Unmarshal(get(), &payload))
	assert.Contains(t, payload["text"], "Secrets due for rotation")
	assert.Contains(t, payload["text"], "2 overdue in Payments.")
	assert.Contains(t, payload["text"], "/rotation-policies")
}

func TestChatSink_TeamsPayload(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatTeams, WebhookURL: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{Title: "Anomaly detected", Message: "off-hours access by ada."})
	sink.Close()

	var card map[string]interface{}
	require.NoError(t, json.Unmarshal(get(), &card))
	assert.Equal(t, "MessageCard", card["@type"])
	assert.Equal(t, "Anomaly detected", card["title"])
	assert.Equal(t, "off-hours access by ada.", card["text"])
}

// TestChatSink_EscapesMrkdwnInjectionFromSecretName proves the #328 exploit trace
// (an ordinary secret owner names a secret with Slack mrkdwn control syntax and
// shares it — no admin privilege required) is neutralized before it reaches either
// platform's JSON payload: no live `<!channel>` mass-ping token, no live
// `<url|label>` spoofed-link token, in the actual bytes posted to the destination.
func TestChatSink_EscapesMrkdwnInjectionFromSecretName(t *testing.T) {
	// Exactly the exploit trace from #328: a secret name crafted to trigger a
	// Slack mass-ping and a spoofed clickable link, delivered via the ordinary
	// "secret shared with you" notification (notifySecretShared in
	// internal/core/notifications.go embeds secret.Name verbatim into ev.Message).
	secretName := `<!channel> Password reset required: <https://evil.example/login|Reset Now>`
	message := `You were granted read access to secret "` + secretName + `".`

	t.Run("slack", func(t *testing.T) {
		srv, get := captureChatServer(t)
		sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
		require.NoError(t, err)
		sink.Deliver(core.NotificationEvent{Title: "Secret shared with you", Message: message})
		sink.Close()

		var payload map[string]string
		require.NoError(t, json.Unmarshal(get(), &payload))
		text := payload["text"]
		assert.NotContains(t, text, "<!channel>", "must not carry a live @channel mass-ping token")
		assert.NotContains(t, text, "<https://evil.example/login|Reset Now>", "must not carry a live spoofed-link token")
		// The content must still be present, just inert — nothing was silently dropped.
		assert.Contains(t, text, "&lt;!channel&gt;")
		assert.Contains(t, text, "&lt;https://evil.example/login|Reset Now&gt;")
	})

	t.Run("teams", func(t *testing.T) {
		srv, get := captureChatServer(t)
		sink, err := NewChat(ChatConfig{Kind: ChatTeams, WebhookURL: srv.URL})
		require.NoError(t, err)
		sink.Deliver(core.NotificationEvent{Title: "Secret shared with you", Message: message})
		sink.Close()

		var card map[string]interface{}
		require.NoError(t, json.Unmarshal(get(), &card))
		text, _ := card["text"].(string)
		assert.NotContains(t, text, "<!channel>", "must not carry a live @channel mass-ping token")
		assert.NotContains(t, text, "<https://evil.example/login|Reset Now>", "must not carry a live spoofed-link token")
		assert.Contains(t, text, "&lt;!channel&gt;")
		assert.Contains(t, text, "&lt;https://evil.example/login|Reset Now&gt;")
	})
}

// TestChatSink_EscapesMrkdwnInjectionInTitle covers the Title field (used verbatim
// by other admin/system-triggered notification paths, e.g. compliance_digest.go,
// rotation_executor.go) through the same choke point.
func TestChatSink_EscapesMrkdwnInjectionInTitle(t *testing.T) {
	srv, get := captureChatServer(t)
	sink, err := NewChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{Title: `<!here> urgent`, Message: "ok"})
	sink.Close()

	var payload map[string]string
	require.NoError(t, json.Unmarshal(get(), &payload))
	assert.NotContains(t, payload["text"], "<!here>")
	assert.Contains(t, payload["text"], "&lt;!here&gt;")
}

func TestNewChat_Validation(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: "irc", WebhookURL: "https://x"})
	require.Error(t, err)
	_, err = NewChat(ChatConfig{Kind: ChatSlack})
	require.Error(t, err)
}

func TestChatSink_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient — retried by the shared engine
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	delivBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeDelivered))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("slack"))

	sink, err := newChat(ChatConfig{Kind: ChatSlack, WebhookURL: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer sink.Close()
	sink.Deliver(core.NotificationEvent{Title: "x"})

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(notifyDeliveries.WithLabelValues("slack", outcomeDelivered))-delivBefore == 1
	}, 2*time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(3), hits.Load(), "should retry the two 503s then succeed")
	assert.Equal(t, 2.0, testutil.ToFloat64(notifyRetries.WithLabelValues("slack"))-retryBefore)
}
