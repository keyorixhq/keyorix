package k8ssync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The list and value calls ask the server for project 7 / environment 3, but the
// answer is checked, not trusted: an entry or a value that says it belongs
// somewhere else is refused. The refusal is a plain error, never ErrUpstreamGone,
// because a contradicting server is not proof the secret is gone and must not
// wipe the synced copy.

// fetchScoped runs one Fetch of "production/db" (project 7) against the ok*
// bodies with list or value replaced, and reports how many value reads were made.
func fetchScoped(t *testing.T, list, value string) (v []byte, valueReads int32, err error) {
	t.Helper()
	var reads atomic.Int32
	inner := failClosedServer{body: map[string]string{"envs": okEnvs, "list": list, "value": value}}.handler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/secrets/") {
			reads.Add(1)
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	v, err = NewKeyorixFetcher(srv.URL, "tok", 7).Fetch(context.Background(), "production/db")
	return v, reads.Load(), err
}

func TestFetcher_ListEntryOutsideScopeFailsClosed(t *testing.T) {
	for name, list := range map[string]string{
		"other environment":   `{"data":{"secrets":[{"ID":9,"Name":"db","project_id":7,"environment_id":4}],"total_pages":1}}`,
		"other project":       `{"data":{"secrets":[{"ID":9,"Name":"db","project_id":8,"environment_id":3}],"total_pages":1}}`,
		"no environment":      `{"data":{"secrets":[{"ID":9,"Name":"db","project_id":7}],"total_pages":1}}`,
		"no project":          `{"data":{"secrets":[{"ID":9,"Name":"db","environment_id":3}],"total_pages":1}}`,
		"no scope":            `{"data":{"secrets":[{"ID":9,"Name":"db"}],"total_pages":1}}`,
		"null environment":    `{"data":{"secrets":[{"ID":9,"Name":"db","project_id":7,"environment_id":null}],"total_pages":1}}`,
		"first match foreign": `{"data":{"secrets":[{"ID":8,"Name":"db","project_id":7,"environment_id":4},{"ID":9,"Name":"db","project_id":7,"environment_id":3}],"total_pages":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, reads, err := fetchScoped(t, list, okValue)
			if err == nil || v != nil {
				t.Fatalf("out-of-scope list entry accepted: value %q, err %v", v, err)
			}
			if errors.Is(err, ErrUpstreamGone) {
				t.Fatalf("an out-of-scope entry must not read as upstream-gone (it would wipe the synced copy): %v", err)
			}
			if reads != 0 {
				t.Fatalf("%d value read(s) made for an entry the list placed outside the requested scope", reads)
			}
		})
	}
}

func TestFetcher_ValueOutsideScopeFailsClosed(t *testing.T) {
	for name, value := range map[string]string{
		"other id":          `{"data":{"value":"s3cr3t","secret":{"id":10,"project_id":7,"environment_id":3}}}`,
		"other project":     `{"data":{"value":"s3cr3t","secret":{"id":9,"project_id":8,"environment_id":3}}}`,
		"other environment": `{"data":{"value":"s3cr3t","secret":{"id":9,"project_id":7,"environment_id":4}}}`,
		"no id":             `{"data":{"value":"s3cr3t","secret":{"project_id":7,"environment_id":3}}}`,
		"empty secret":      `{"data":{"value":"s3cr3t","secret":{}}}`,
		"no secret":         `{"data":{"value":"s3cr3t"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, _, err := fetchScoped(t, okList, value)
			if err == nil || v != nil {
				t.Fatalf("out-of-scope value accepted: value %q, err %v", v, err)
			}
			if errors.Is(err, ErrUpstreamGone) {
				t.Fatalf("an out-of-scope value must not read as upstream-gone (it would wipe the synced copy): %v", err)
			}
			if strings.Contains(err.Error(), "s3cr3t") {
				t.Fatal("the refused value reached the error text")
			}
		})
	}
}

// Liveness control for the two tests above: the same bodies, correctly scoped,
// deliver the value, including with the list's "ID" spelling on the value side.
func TestFetcher_InScopeResponseStillDelivers(t *testing.T) {
	for name, value := range map[string]string{
		"id":       okValue,
		"ID":       `{"data":{"value":"s3cr3t","secret":{"ID":9,"project_id":7,"environment_id":3}}}`,
		"expiring": `{"data":{"value":"s3cr3t","secret":{"id":9,"project_id":7,"environment_id":3,"expiration":"2030-01-01T00:00:00Z"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			v, reads, err := fetchScoped(t, okList, value)
			if err != nil || string(v) != "s3cr3t" || reads != 1 {
				t.Fatalf("got %q, %v after %d value read(s)", v, err, reads)
			}
		})
	}
}
