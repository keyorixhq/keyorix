package k8ssync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The server enforces a unique (project, name) for environments, so a list that
// names one environment twice is not an honest answer. Resolving it to either id
// would read a secret from an environment the operator may not have named, so the
// fetch must fail before it lists or reads any secret.
func TestFetcher_DuplicateEnvironmentNameFailsClosed(t *testing.T) {
	var secretCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":3,"Name":"production"},{"ID":4,"Name":"production"}]}}`))
		default:
			secretCalls.Add(1)
			_, _ = w.Write([]byte(okList))
		}
	}))
	t.Cleanup(srv.Close)

	v, err := NewKeyorixFetcher(srv.URL, "tok", 7).Fetch(context.Background(), "production/db")
	if err == nil {
		t.Fatalf("fetch succeeded with %q although the environment name is ambiguous", v)
	}
	if n := secretCalls.Load(); n != 0 {
		t.Fatalf("%d secret request(s) were made after an ambiguous environment list", n)
	}
}

// A list with distinct names still resolves, including a name that merely
// repeats another environment's id.
func TestFetcher_DistinctEnvironmentNamesStillResolve(t *testing.T) {
	v, err := fetchWith(t, failClosedServer{body: map[string]string{
		"envs":  `{"data":{"environments":[{"ID":2,"Name":"staging"},{"ID":3,"Name":"production"}]}}`,
		"list":  okList,
		"value": okValue,
	}})
	if err != nil || string(v) != "s3cr3t" {
		t.Fatalf("got %q, %v", v, err)
	}
}
