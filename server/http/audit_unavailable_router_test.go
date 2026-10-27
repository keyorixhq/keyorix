package http

// AUDIT-503-MAP-1: a security-relevant mutation whose audit row cannot be recorded
// (core.ErrMutationAuditUnavailable: the transaction rolled back, nothing changed)
// answers a retryable 503 with a Retry-After header and the stable code
// audit_unavailable, over the real router. Before, each handler fell through to its
// generic 500 (InternalError). The audit store is made to refuse rows by a trigger,
// so the real storage path fails exactly as an unavailable audit store would.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestAuditOutage_MutationsAnswerRetryable503_OverTheRouter(t *testing.T) {
	w := buildRefusalFamilyWorld(t)

	cases := []struct {
		name  string
		path  string
		body  map[string]any
		count func(t *testing.T) int64
	}{
		{"create group", "/api/v1/groups", map[string]any{"name": "outage-group"},
			func(t *testing.T) int64 { return countRows(t, w, &models.Group{}) }},
		{"create role", "/api/v1/roles", map[string]any{"name": "outage-role", "description": "d", "permissions": []string{"secrets.read"}},
			func(t *testing.T) int64 { return countRows(t, w, &models.Role{}) }},
		{"create project", "/api/v1/projects", map[string]any{"name": "outage-project"},
			func(t *testing.T) int64 { return countRows(t, w, &models.Project{}) }},
	}

	require.NoError(t, w.db.Exec(
		`CREATE TRIGGER refuse_all_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END`).Error)
	t.Cleanup(func() { require.NoError(t, w.db.Exec(`DROP TRIGGER IF EXISTS refuse_all_audit`).Error) })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.count(t)
			b, err := json.Marshal(tc.body)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(b))
			req.Header.Set("Authorization", "Bearer "+w.tokens["session"])
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			w.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
			assert.Equal(t, "5", rec.Header().Get("Retry-After"))
			var env struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
				Message string `json:"message"`
				Code    int    `json:"code"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
			assert.False(t, env.Success)
			assert.Equal(t, "audit_unavailable", env.Error)
			assert.Equal(t, http.StatusServiceUnavailable, env.Code)
			assert.Equal(t, "could not record the change in the audit log; nothing was changed, retry", env.Message, "the sentinel's fixed text, never the wrapped cause")
			assert.Equal(t, before, tc.count(t), "nothing was changed")
		})
	}
}

func countRows(t *testing.T, w *guardParityWorld, model any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, w.db.Model(model).Count(&n).Error)
	return n
}
