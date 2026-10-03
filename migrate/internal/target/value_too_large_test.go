package target

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// serverTooLargeMessage is internal/core.SecretValueTooLargeError's exact wire message for a
// 100000-byte value against the default limit (server/http/handlers/secret_size_error.go).
const serverTooLargeMessage = "secret value is 100000 bytes, which exceeds the configured maximum of 65536 bytes"

func fakeSecretWriteServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/secrets") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestCreateAndUpdate_413IsValueTooLarge is #2544's target-side guard: the server's 413
// (secret value over max_secret_size) must surface as a ValueTooLargeError carrying the size
// and the server's own message naming the limit — not as the generic apiErr shape every other
// failure gets.
func TestCreateAndUpdate_413IsValueTooLarge(t *testing.T) {
	srv := fakeSecretWriteServer(t, http.StatusRequestEntityTooLarge,
		`{"error":"PayloadTooLarge","message":"`+serverTooLargeMessage+`","code":413}`)
	defer srv.Close()
	c := newTestClient(t, srv, 1, 1)
	value := strings.Repeat("x", 100000)

	_, createErr := c.Create(context.Background(), "big", value, nil)
	updateErr := c.UpdateValue(context.Background(), 7, value)
	for name, err := range map[string]error{"Create": createErr, "UpdateValue": updateErr} {
		if !IsValueTooLarge(err) {
			t.Errorf("%s: 413 error = %v, want a ValueTooLargeError", name, err)
			continue
		}
		msg := err.Error()
		for _, want := range []string{"100000 bytes", "max_secret_size", serverTooLargeMessage} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: error %q does not mention %q", name, msg, want)
			}
		}
		if strings.Contains(msg, value[:64]) {
			t.Errorf("%s: error message carries the value", name)
		}
	}
}

// TestCreate_OtherFailuresAreNotValueTooLarge is the other direction: a non-413 failure must
// not be misclassified as value-too-large.
func TestCreate_OtherFailuresAreNotValueTooLarge(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError} {
		srv := fakeSecretWriteServer(t, status, `{"error":"X","message":"something else","code":`+strconv.Itoa(status)+`}`)
		c := newTestClient(t, srv, 1, 1)
		_, err := c.Create(context.Background(), "n", "v", nil)
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d: Create returned no error", status)
		}
		if IsValueTooLarge(err) {
			t.Errorf("HTTP %d: misclassified as ValueTooLargeError: %v", status, err)
		}
	}
}

// TestSizeLimitsMatchServer pins DefaultMaxSecretSize / MaxSecretSizeHardCeiling to the
// Keyorix server's own source (this module cannot import it). It reads the server constants
// as text from the repository checkout; it does not cover a target server running a different
// Keyorix version than this checkout.
func TestSizeLimitsMatchServer(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	cases := []struct {
		file, pattern string
		want          int
	}{
		{filepath.Join(root, "internal", "core", "secret_size_policy.go"), `(?m)^const DefaultMaxSecretSize = (\d+)\s*$`, DefaultMaxSecretSize},
		{filepath.Join(root, "internal", "config", "config.go"), `(?m)^const MaxSecretSizeHardCeiling = 1 << (\d+)\b`, MaxSecretSizeHardCeiling},
	}
	for _, tc := range cases {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		m := regexp.MustCompile(tc.pattern).FindSubmatch(src)
		if m == nil {
			t.Fatalf("%s: pattern %q not found — the server constant moved or changed shape; update this test and the mirror in target.go", tc.file, tc.pattern)
		}
		n, _ := strconv.Atoi(string(m[1]))
		if strings.Contains(tc.pattern, "<<") {
			n = 1 << n
		}
		if n != tc.want {
			t.Errorf("%s: server value %d != migrate's mirror %d", tc.file, n, tc.want)
		}
	}
}
