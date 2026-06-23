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

func TestWebhookSink_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient — should be retried
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	delivBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDelivered))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	defer sink.Close()
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})

	// Wait for the terminal "delivered" outcome before asserting — Close() would
	// abort an in-flight retry, so we must not race it against the backoff.
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDelivered))-delivBefore == 1
	}, 2*time.Second, 5*time.Millisecond)

	assert.Equal(t, int32(3), hits.Load(), "should have taken 2 retries (3 attempts)")
	assert.Equal(t, 2.0, testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))-retryBefore)
}

func TestWebhookSink_PermanentErrorNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 4xx — permanent, must not retry
	}))
	defer srv.Close()

	failedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))
	retryBefore := testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)
	sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	sink.Close() // no retry backoff for a permanent error, so Close cleanly drains it

	assert.Equal(t, int32(1), hits.Load(), "a 4xx must not be retried")
	assert.Equal(t, 1.0, testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeFailed))-failedBefore)
	assert.Equal(t, 0.0, testutil.ToFloat64(notifyRetries.WithLabelValues("webhook"))-retryBefore)
}

func TestWebhookSink_DropsAndCountsWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // wedge the worker so the queue backs up
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	droppedBefore := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDropped))

	sink, err := newWebhook(WebhookConfig{Endpoint: srv.URL}, time.Millisecond)
	require.NoError(t, err)

	// One event wedges the worker; the buffered queue holds webhookQueueSize more;
	// everything past that is dropped (and counted) rather than blocking the caller.
	for i := 0; i < webhookQueueSize+5; i++ {
		sink.Deliver(core.NotificationEvent{UserID: 1, Type: "x"})
	}
	dropped := testutil.ToFloat64(notifyDeliveries.WithLabelValues("webhook", outcomeDropped)) - droppedBefore
	assert.GreaterOrEqual(t, dropped, 1.0, "events past the queue capacity should be dropped and counted")

	close(release)
	sink.Close()
}
