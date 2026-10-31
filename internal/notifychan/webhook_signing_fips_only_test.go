package notifychan

import (
	"context"
	"crypto/fips140"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// FIPS-TAILS-2 item 2, red/green: under GODEBUG=fips140=only a signing secret
// under 14 bytes made crypto/hmac panic inside send, on the delivery worker
// (process-fatal). send now returns a permanent error and posts nothing.
func TestWebhookSend_UnderFIPS140Only_ShortSecretErrorsNotPanic(t *testing.T) {
	if !fips140.Enforced() {
		t.Skip("needs GODEBUG=fips140=only; TestCheckSigningSecretLen_* cover default mode")
	}
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sink, err := NewWebhook(WebhookConfig{Endpoint: srv.URL, SigningSecret: "shh"})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	defer sink.Close()

	var retryable bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("send panicked under fips140=only: %v", r)
			}
		}()
		retryable, err = sink.send(context.Background(), core.NotificationEvent{UserID: 1, Type: "x"})
	}()
	if err == nil || !strings.Contains(err.Error(), "at least 14") {
		t.Fatalf("want an error naming the 14-byte minimum, got %v", err)
	}
	if retryable {
		t.Error("a short secret is permanent; retrying cannot help")
	}
	if posts.Load() != 0 {
		t.Error("an unsigned notification must not be sent in place of a signed one")
	}
}
