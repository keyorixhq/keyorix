package handlers

// IDENTITY-INPUT-BOUNDS-1 item 3: POST /auth/tokens accepted an expires_at in the
// past and issued an already-expired token, shown once. It is now a 400 and no
// token row is written; an omitted expires_at still creates a non-expiring token.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePAT_ExpiresAtInPastIs400(t *testing.T) {
	for name, expiresAt := range map[string]string{
		"an hour ago": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
		"epoch":       "1970-01-01T00:00:00Z",
		"now":         time.Now().UTC().Format(time.RFC3339), // second precision: at or before now
	} {
		t.Run(name, func(t *testing.T) {
			c := freshCoreS12WithCredentialOwners(t, 1)
			h := NewPATHandler(c)
			body, _ := json.Marshal(map[string]any{"name": "stale", "expires_at": expiresAt})
			req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.CreatePAT(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.NotContains(t, w.Body.String(), "kx_pat_", "no token is shown")

			pats, err := c.Storage().ListPersonalAccessTokensByUser(context.Background(), 1)
			require.NoError(t, err)
			assert.Empty(t, pats, "a refused expiry must not write a token row")
		})
	}
}

func TestCreatePAT_FutureAndOmittedExpiryStillCreate(t *testing.T) {
	c := freshCoreS12WithCredentialOwners(t, 1)
	h := NewPATHandler(c)
	for _, b := range []map[string]any{
		{"name": "future", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		{"name": "forever"},
	} {
		body, _ := json.Marshal(b)
		req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.CreatePAT(w, req)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	}
	pats, err := c.Storage().ListPersonalAccessTokensByUser(context.Background(), 1)
	require.NoError(t, err)
	require.Len(t, pats, 2)
	for _, p := range pats {
		if p.Name == "forever" {
			assert.Nil(t, p.ExpiresAt, "omitted expires_at = never expires")
		} else {
			require.NotNil(t, p.ExpiresAt)
		}
	}
}
