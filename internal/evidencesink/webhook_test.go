package evidencesink

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook_PostsEvidenceWithAuth(t *testing.T) {
	var (
		mu    sync.Mutex
		body  []byte
		auth  string
		ctype string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth, ctype = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, Token: "ev-tok"})
	require.NoError(t, err)
	require.NoError(t, wh.ForwardEvidence(context.Background(), []byte(`{"generated_at":"x"}`)))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, `{"generated_at":"x"}`, string(body))
	assert.Equal(t, "Bearer ev-tok", auth)
	assert.Equal(t, "application/json", ctype)
}

func TestWebhook_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh, err := NewWebhook(WebhookConfig{Endpoint: srv.URL})
	require.NoError(t, err)
	require.Error(t, wh.ForwardEvidence(context.Background(), []byte(`{}`)))
}

func TestNewWebhook_RequiresEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}
