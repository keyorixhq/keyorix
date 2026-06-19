package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretPolicyHandler(t *testing.T) {
	db := openTestDB(t)
	svc := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, svc.SetSecretNamePolicy(core.SecretNamePolicy{Enabled: true, Pattern: "^[A-Z_]+$", MaxLength: 32}))
	svc.SetSecretValuePolicy(core.SecretValuePolicy{Enabled: true, MinLength: 16, RejectCommon: true})
	h, err := NewSecretHandler(svc)
	require.NoError(t, err)

	t.Run("returns the active policies", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/policy", nil))
		w := httptest.NewRecorder()
		h.SecretPolicy(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Data core.SecretPolicyInfo `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.Data.Name.Enabled)
		assert.Equal(t, "^[A-Z_]+$", resp.Data.Name.Pattern)
		assert.Equal(t, 32, resp.Data.Name.MaxLength)
		assert.True(t, resp.Data.Value.Enabled)
		assert.Equal(t, 16, resp.Data.Value.MinLength)
		assert.True(t, resp.Data.Value.RejectCommon)
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/policy", nil)
		w := httptest.NewRecorder()
		h.SecretPolicy(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
