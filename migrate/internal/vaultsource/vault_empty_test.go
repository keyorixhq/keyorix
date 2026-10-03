package vaultsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKVv2 serves a minimal KV v2 mount "secret" holding the given leaves (path -> raw JSON of
// data.data). Listing the root returns every leaf; reads return version 1 of each.
func fakeKVv2(t *testing.T, leaves map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/v1/sys/internal/ui/mounts/"):
			_, _ = w.Write([]byte(`{"data":{"path":"secret/","options":{"version":"2"}}}`))
		case p == "/v1/secret/metadata" && r.URL.Query().Get("list") == "true":
			keys := make([]string, 0, len(leaves))
			for k := range leaves {
				keys = append(keys, `"`+k+`"`)
			}
			_, _ = w.Write([]byte(`{"data":{"keys":[` + strings.Join(keys, ",") + `]}}`))
		case strings.HasPrefix(p, "/v1/secret/metadata/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		case strings.HasPrefix(p, "/v1/secret/data/"):
			data, ok := leaves[strings.TrimPrefix(p, "/v1/secret/data/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"data":` + data + `,"metadata":{"version":1,"created_time":"2026-01-01T00:00:00Z"}}}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestWalk_EmptyValuesAreReportedAsSkips is #2543's guard: a KV field with an empty (or null)
// value, an empty field name, or a leaf with no fields at all must surface as a Skipped with a
// reason — never vanish from both entries and skipped. Every non-empty field still imports.
func TestWalk_EmptyValuesAreReportedAsSkips(t *testing.T) {
	srv := fakeKVv2(t, map[string]string{
		"empty-value":  `{"value":""}`,
		"null-value":   `{"value":null}`,
		"multi":        `{"user":"alice","password":""}`,
		"no-name":      `{"":"x","ok":"y"}`,
		"no-fields":    `{}`,
		"normal-value": `{"value":"v"}`,
	})
	defer srv.Close()

	c, err := New(context.Background(), Config{Addr: srv.URL, Mount: "secret", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, skipped, err := c.Walk(context.Background(), "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	gotSkips := map[string]string{}
	for _, s := range skipped {
		gotSkips[s.Path] = s.Reason
	}
	wantSkips := map[string]string{
		"empty-value":    emptyValueSkipReason,
		"null-value":     emptyValueSkipReason,
		"multi#password": emptyValueSkipReason,
		"no-name#":       emptyFieldNameSkipReason,
		"no-fields":      emptyLeafSkipReason,
	}
	for path, reason := range wantSkips {
		if got, ok := gotSkips[path]; !ok {
			t.Errorf("%q: not reported as skipped (silently dropped); skipped = %v", path, skipped)
		} else if got != reason {
			t.Errorf("%q: skip reason = %q, want %q", path, got, reason)
		}
	}
	if len(skipped) != len(wantSkips) {
		t.Errorf("got %d skips, want %d: %v", len(skipped), len(wantSkips), skipped)
	}

	gotEntries := map[string]string{}
	for _, e := range entries {
		gotEntries[e.Path+"#"+e.Field] = e.Value
		if e.Value == "" || e.Value == "<nil>" {
			t.Errorf("entry %s#%s imported with empty/nil value %q", e.Path, e.Field, e.Value)
		}
	}
	for _, k := range []string{"multi#user", "no-name#ok", "normal-value#"} {
		if _, ok := gotEntries[k]; !ok {
			t.Errorf("non-empty field %q missing from entries: %v", k, gotEntries)
		}
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3: %v", len(entries), gotEntries)
	}
}
