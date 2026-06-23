package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoStore_SetsHeader(t *testing.T) {
	h := NoStore(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // even an auth failure must carry it
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}
