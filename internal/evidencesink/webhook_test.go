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
		mu       sync.Mutex
		body     []byte
		auth     string
		ctype    string
		sig      string
		filename string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, auth, ctype = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		sig, filename = r.Header.Get("X-Keyorix-Evidence-Signature"), r.Header.Get("X-Keyorix-Evidence-Filename")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, Token: "ev-tok"})
	require.NoError(t, err)
	require.NoError(t, wh.ForwardEvidence(context.Background(), "keyorix-evidence-20260615T100000Z.json", []byte(`{"generated_at":"x"}`), "v1:abc"))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, `{"generated_at":"x"}`, string(body))
	assert.Equal(t, "Bearer ev-tok", auth)
	assert.Equal(t, "application/json", ctype)
	assert.Equal(t, "v1:abc", sig)
	assert.Equal(t, "keyorix-evidence-20260615T100000Z.json", filename)
	assert.Equal(t, "webhook", wh.Target())
}

func TestWebhook_ErrorsOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	wh, err := NewWebhook(WebhookConfig{Endpoint: srv.URL})
	require.NoError(t, err)
	require.Error(t, wh.ForwardEvidence(context.Background(), "pack.json", []byte(`{}`), ""))
}

func TestNewWebhook_RequiresEndpoint(t *testing.T) {
	_, err := NewWebhook(WebhookConfig{})
	require.Error(t, err)
}
