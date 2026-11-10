package notifychan

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #3426: a failed delivery to a generic webhook whose URL carries its token in the
// path (https://host/path-token) must never write that token to the log: not in the
// error text, and not through the channel name. The chat sink has the same test
// (TestChatSink_DeliveryFailureLogDoesNotLeakWebhookToken); this one covers the
// generic WebhookSink, whose send() returns the raw *url.Error of http.Client.Do.
func TestWebhookSink_DeliveryFailureLogDoesNotLeakPathToken(t *testing.T) {
	const token = "path-token-3426-SUPERSECRET"

	receiver500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer receiver500.Close()
	receiver400 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer receiver400.Close()

	cases := []struct {
		name     string
		endpoint string
	}{
		// Port 1 is not listening: a genuine transport-level *url.Error.
		{"transport error", "http://127.0.0.1:1/services/T000/B000/" + token},
		{"receiver 5xx (retried)", receiver500.URL + "/services/T000/B000/" + token},
		{"receiver 4xx (permanent)", receiver400.URL + "/services/T000/B000/" + token},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			orig := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(orig)

			sink, err := newWebhook(WebhookConfig{Endpoint: tc.endpoint, AllowPrivateNetworkTarget: true}, time.Millisecond)
			require.NoError(t, err)

			// Premise: the raw error of this very request DOES carry the token, so the
			// assertions below can only pass because the log path sanitises it.
			if tc.name == "transport error" {
				req, rerr := http.NewRequest(http.MethodPost, tc.endpoint, strings.NewReader("{}"))
				require.NoError(t, rerr)
				_, derr := sink.client.Do(req)
				require.Error(t, derr)
				require.Contains(t, derr.Error(), token, "premise: the unsanitised transport error carries the path token")
			}

			require.True(t, sink.Deliver(core.NotificationEvent{Title: "x", Message: "y"}))
			sink.Close() // blocks until the worker, including its log.Printf calls, has finished

			logged := buf.String()
			// Close() abandons a retry backoff, so a retried failure logs the "abandoned on
			// shutdown" line and a permanent one "failed"; both go through sanitizeDeliveryError.
			assert.Contains(t, logged, "notifychan: webhook delivery ", "sanity: the failure path should still log something")
			assert.NotContains(t, logged, token, "the webhook's path token must never reach the log stream")
			assert.NotContains(t, logged, "services/T000/B000", "the webhook's path must never reach the log stream")
		})
	}
}
