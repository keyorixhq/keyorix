package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCompleteSSO_RefusesProviderWithoutExchangeClient pins the fail-closed half of
// INV-CORE-sso-exchange-on-guarded-client (#4738): a provider with no HTTPClient is
// refused before any request, never exchanged on x/oauth2's http.DefaultClient
// fallback. Asserted by effect: the token endpoint receives nothing. It does not
// verify which client a provider WITH a client uses (server's
// sso_exchange_egress_test.go does that through the real wiring).
func TestCompleteSSO_RefusesProviderWithoutExchangeClient(t *testing.T) {
	t.Parallel()
	c, store, _, p := ssoTestCore(t)
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer"}`))
	}))
	defer ts.Close()
	p.OAuth.Endpoint.TokenURL = ts.URL
	p.HTTPClient = nil

	store.On("ConsumeSSOLoginState", mock.Anything, "state-nil-client").Return(
		&models.SSOLoginState{Provider: "okta", Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)}, nil)

	_, _, _, err := c.CompleteSSO(context.Background(), "okta", "code", "state-nil-client", "ua", "203.0.113.9")
	if !errors.Is(err, errSSONoExchangeClient) {
		t.Fatalf("err = %v, want errSSONoExchangeClient", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("token endpoint received %d request(s) from a provider with no exchange client", n)
	}
}
