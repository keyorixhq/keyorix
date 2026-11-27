package k8ssync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A duplicated environment name in the server's list is refused (fail closed), and the
// refusal must not echo the server-supplied name: server-controlled bytes never reach an
// error returned by Fetch (#4062). The echo came in with the duplicate-environment fix
// (#4568) and was found by FuzzKeyorixFetcherHostileServer oracle O7 (fuzz-corpus#193).
func TestKeyorixFetcher_DuplicateEnvironmentErrorDoesNotEchoServerName(t *testing.T) {
	const canary = "CANARY193"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":3,"Name":"` + canary + `"},{"ID":4,"Name":"` + canary + `"}]}}`))
	}))
	defer srv.Close()

	f := NewKeyorixFetcher(srv.URL, "tok", 1)
	_, err := f.Fetch(context.Background(), "prod/db")
	if err == nil {
		t.Fatalf("expected the duplicate environment list to be refused")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("server-controlled environment name reached the error: %v", err)
	}
}
