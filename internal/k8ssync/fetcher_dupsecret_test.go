package k8ssync

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// listPage is one page of the secrets list: each entry is (id, name). Entries are
// stamped with the project and environment the fetcher asked for, so the scope
// check cannot be what refuses a fetch; only the names can.
type listPage struct{ entries [][2]string }

// dupSecretServer answers the environment list with one environment (id 3), pages of
// the secret list from pages, and a value for whichever secret id is read. totalPages
// is what the server claims; 0 means len(pages). calls counts secret-list requests.
func dupSecretServer(t *testing.T, pages []listPage, totalPages int, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	if totalPages == 0 {
		totalPages = len(pages)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/environments"):
			_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":3,"Name":"production"}]}}`))
		case r.URL.Path == "/api/v1/secrets":
			calls.Add(1)
			var page int
			_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
			var items []string
			if page >= 1 && page <= len(pages) {
				for _, e := range pages[page-1].entries {
					items = append(items, fmt.Sprintf(`{"ID":%s,"Name":%q,"project_id":7,"environment_id":3}`, e[0], e[1]))
				}
			}
			_, _ = fmt.Fprintf(w, `{"data":{"secrets":[%s],"total_pages":%d}}`, strings.Join(items, ","), totalPages)
		default:
			_, _ = w.Write([]byte(`{"data":{"value":"s3cr3t","secret":{"id":9,"project_id":7,"environment_id":3}}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The server keeps (project, environment, name) unique among active secrets, so a
// list that names one secret twice is not an honest answer. Resolving it to the first
// entry would read a secret the operator may not have meant; the fetch must fail,
// whether the two entries share a page or sit on different ones.
func TestFetcher_DuplicateSecretNameFailsClosed(t *testing.T) {
	for name, pages := range map[string][]listPage{
		"same page":       {{[][2]string{{"9", "db"}, {"10", "db"}}}},
		"different pages": {{[][2]string{{"9", "db"}, {"11", "other"}}}, {[][2]string{{"10", "db"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			srv := dupSecretServer(t, pages, 0, &calls)
			v, err := NewKeyorixFetcher(srv.URL, "tok", 7).Fetch(context.Background(), "production/db")
			if err == nil {
				t.Fatalf("fetch succeeded with %q although the secret name is listed twice", v)
			}
			if errors.Is(err, ErrUpstreamGone) {
				t.Fatalf("a duplicate name must not read as a removed secret (the synced copy would be wiped): %v", err)
			}
		})
	}
}

// One match, wherever it is, still resolves; a differently cased or prefixed name is
// a different secret and is not a duplicate.
func TestFetcher_SingleSecretMatchStillResolves(t *testing.T) {
	for name, pages := range map[string][]listPage{
		"first page":      {{[][2]string{{"9", "db"}, {"11", "other"}}}},
		"second page":     {{[][2]string{{"11", "other"}}}, {[][2]string{{"9", "db"}}}},
		"near-miss names": {{[][2]string{{"9", "db"}, {"10", "DB"}, {"12", "db2"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			srv := dupSecretServer(t, pages, 0, &calls)
			v, err := NewKeyorixFetcher(srv.URL, "tok", 7).Fetch(context.Background(), "production/db")
			if err != nil || string(v) != "s3cr3t" {
				t.Fatalf("got %q, %v", v, err)
			}
		})
	}
}

// total_pages is the server's own claim. A server that keeps raising it must not make
// the lookup page forever, now that a match no longer ends the walk.
func TestFetcher_SecretListPageCountIsBounded(t *testing.T) {
	var calls atomic.Int32
	srv := dupSecretServer(t, []listPage{{[][2]string{{"9", "db"}}}}, 1_000_000, &calls)
	_, err := NewKeyorixFetcher(srv.URL, "tok", 7).Fetch(context.Background(), "production/db")
	if err == nil {
		t.Fatal("fetch succeeded although the server claims a million pages")
	}
	if errors.Is(err, ErrUpstreamGone) {
		t.Fatalf("an unbounded list must not read as a removed secret: %v", err)
	}
	if n := calls.Load(); n > maxSecretListPages {
		t.Fatalf("%d list requests, want at most %d", n, maxSecretListPages)
	}
}
