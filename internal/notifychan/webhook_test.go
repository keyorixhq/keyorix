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

func TestWebhookSink_DeliversJSONWithBearerAuth(t *testing.T) {
	var (
		mu    sync.Mutex
		body  []byte
		auth  string
		ctype string
		hits  int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth, ctype, hits = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), hits+1
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, Token: "secret-tok"})
	require.NoError(t, err)

	pid := uint(3)
	sink.Deliver(core.NotificationEvent{
		UserID: 7, Email: "ada@x.io", Type: "access_request.approved",
		Title: "Approved", Message: "ok", ProjectID: &pid, Link: "/projects/3",
	})
	sink.Close() // drains the queue before returning

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, hits)
	assert.Equal(t, "Bearer secret-tok", auth)
	assert.Equal(t, "application/json", ctype)

	var ev core.NotificationEvent
	require.NoError(t, json.Unmarshal(body, &ev))
	assert.Equal(t, uint(7), ev.UserID)
	assert.Equal(t, "ada@x.io", ev.Email)
	assert.Equal(t, "access_request.approved", ev.Type)
	require.NotNil(t, ev.ProjectID)
	assert.Equal(t, uint(3), *ev.ProjectID)
}

func TestWebhookSink_NoTokenOmitsAuthHeader(t *testing.T) {
	var (
		mu   sync.Mutex
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL})
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close()

	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, auth)
}

func TestNewWebhook_RequiresEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}
