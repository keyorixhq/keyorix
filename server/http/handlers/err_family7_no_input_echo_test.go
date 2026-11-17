package handlers

// CORE-ERR-FAMILY-7 item 3 (#4059): three 400 responses quoted the caller's own rejected
// value back: the unknown SSO provider name (unauthenticated, from the path), the invalid
// notification channel type and the unsupported access-log export format. Each route now
// answers a fixed message. Each case sends a marker and asserts it is absent from the
// whole response, in any letter case (the export format was echoed lower-cased).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const errFamily7EchoMarker = "Zq7EchoMarker"

func requireNoMarkerEcho(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	body := strings.ToLower(w.Body.String())
	assert.NotContains(t, body, strings.ToLower(errFamily7EchoMarker), "the caller's rejected value must not be quoted back")
	for k, vs := range w.Header() {
		for _, v := range vs {
			assert.NotContains(t, strings.ToLower(v), strings.ToLower(errFamily7EchoMarker), "header %s", k)
		}
	}
}

func TestErrFamily7_SSOBeginUnknownProviderDoesNotEchoTheName(t *testing.T) {
	_, cs, _ := freshFolderFixture(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/auth/sso/"+errFamily7EchoMarker+"/login", nil)
	w := httptest.NewRecorder()
	h.BeginSSO(w, withChiParam(r, "provider", errFamily7EchoMarker))
	requireNoMarkerEcho(t, w)
	assert.Contains(t, w.Body.String(), "unknown SSO provider")
}

func TestErrFamily7_NotificationChannelInvalidTypeDoesNotEchoTheType(t *testing.T) {
	h, _ := newNotifChannelHandler(t)
	b, err := json.Marshal(map[string]any{"name": "echo", "type": errFamily7EchoMarker, "url": "https://example.com"})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.Create(w, withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/notification-channels", bytes.NewReader(b))))
	requireNoMarkerEcho(t, w)
	assert.Contains(t, w.Body.String(), "must be one of webhook, slack, teams, email")
}

func TestErrFamily7_AccessLogExportUnsupportedFormatDoesNotEchoTheFormat(t *testing.T) {
	svc, db := freshExportDB(t)
	secretID := seedSecretAndEvents(t, db)
	w, _ := doExportGet(t, svc, secretID, "format="+errFamily7EchoMarker)
	requireNoMarkerEcho(t, w)
	assert.Contains(t, w.Body.String(), "must be csv or json")
}
