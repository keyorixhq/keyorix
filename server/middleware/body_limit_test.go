package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readBody runs a request with the given body through MaxBodyBytes(limit) and reports
// what the handler read and whether the read errored.
func readBody(t *testing.T, limit int64, body string) (string, error) {
	t.Helper()
	var got []byte
	var readErr error
	h := MaxBodyBytes(limit)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, readErr = io.ReadAll(r.Body)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return string(got), readErr
}

func TestMaxBodyBytes_RejectsOversize(t *testing.T) {
	_, err := readBody(t, 10, strings.Repeat("x", 50)) // 50 bytes, cap 10
	require.Error(t, err, "reading past the cap fails")
	assert.Contains(t, err.Error(), "too large")
}

func TestMaxBodyBytes_AllowsUnderLimit(t *testing.T) {
	got, err := readBody(t, 100, "small payload")
	require.NoError(t, err)
	assert.Equal(t, "small payload", got)
}

func TestMaxBodyBytes_AtLimitOK(t *testing.T) {
	got, err := readBody(t, 5, "12345") // exactly at the cap
	require.NoError(t, err)
	assert.Equal(t, "12345", got)
}

func TestMaxBodyBytes_DisabledWhenNonPositive(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		got, err := readBody(t, limit, strings.Repeat("y", 1000))
		require.NoError(t, err, "limit %d disables the cap", limit)
		assert.Len(t, got, 1000)
	}
}
