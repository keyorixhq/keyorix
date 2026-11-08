package http

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// sweepRoute is one (method, pattern) pair the live router registers.
type sweepRoute struct{ Method, Pattern string }

func (r sweepRoute) String() string { return r.Method + " " + r.Pattern }

// listSweepRoutes enumerates every route of the REAL router with chi.Walk, so
// the sweep covers whatever is registered today rather than a hand-kept list.
func listSweepRoutes(t testing.TB, h http.Handler) []sweepRoute {
	t.Helper()
	routes, ok := h.(chi.Routes)
	if !ok {
		t.Fatalf("router %T does not expose chi.Routes; cannot enumerate", h)
	}
	seen := map[string]bool{}
	var out []sweepRoute
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.ReplaceAll(route, "/*/", "/")
		k := method + " " + route
		if !seen[k] {
			seen[k] = true
			out = append(out, sweepRoute{method, route})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func TestCanarySweep_ListRoutes(t *testing.T) {
	c := core.NewKeyorixCore(store.NewLocalStorage(nil))
	r, err := NewRouter(&config.Config{}, c)
	if err != nil {
		t.Fatal(err)
	}
	rs := listSweepRoutes(t, r)
	if len(rs) < 100 {
		t.Fatalf("suspiciously few routes: %d", len(rs))
	}
	t.Logf("%d routes", len(rs))
	var sb strings.Builder
	for _, r := range rs {
		sb.WriteString(r.String() + "\n")
	}
	t.Log("\n" + sb.String())
}
