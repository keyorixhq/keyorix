package notifychan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
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

func TestNewChat_Validation(t *testing.T) {
	_, err := NewChat(ChatConfig{Kind: "irc", WebhookURL: "https://x"})
	require.Error(t, err)
	_, err = NewChat(ChatConfig{Kind: ChatSlack})
	require.Error(t, err)
}
