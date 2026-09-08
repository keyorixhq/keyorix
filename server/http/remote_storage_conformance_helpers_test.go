// remote_storage_conformance_helpers_test.go — issue #1808: shared scaffold and
// comparator for the RemoteStorage differential conformance harness.
//
// # Why this exists (read remote_proxy_correctness_audit_test.go's package doc first)
//
// internal/storage/store/remote_*_test.go's existing corpus tests RemoteStorage
// against a hand-written httptest fake handler that asserts the exact path/payload
// the proxy code ITSELF sends. That is a tautology: if the proxy calls the wrong
// endpoint, the test asserts the same wrong endpoint and passes; if the proxy's
// wire struct omits a field, the fake handler never sends it and nothing notices.
// NewRouter appears in no test under internal/storage/store — the real route table
// is never consulted, so a route or field mismatch between the proxy and the real
// server is invisible by construction. This is documented as the cause of at least
// 4 of the 9 real defects found by #1800's historical-positive validation (see
// remote_proxy_correctness_audit_test.go's KNOWN NON-COVERAGE section).
//
// This file, and remote_storage_conformance_test.go alongside it, do NOT extend
// that pattern and do NOT replace it — the existing corpus still exercises the
// proxy's own request/response parsing and stays in place. This harness answers a
// different question: does RemoteStorage.M(x), run through the REAL
// server/http.NewRouter and a REAL LocalStorage-backed core.KeyorixCore, produce
// the same result as LocalStorage.M(x) against that same backing store? Only
// server/http can ask this question — internal/storage/store cannot import
// server/http (server/http -> internal/core -> internal/storage/store would cycle),
// so this harness necessarily lives here, not alongside the fake-handler corpus.
//
// # Field-exhaustive comparison, not a hand-written assertion list
//
// assertFieldExhaustiveEqual walks every EXPORTED field of the two structs being
// compared via reflection. It does not enumerate which fields to check — it
// enumerates which fields to EXCLUDE, and every exclusion is justified inline at
// its call site. The property this buys: adding a new field to a model
// automatically extends coverage, with no test-author action required. A test
// author's memory of which fields to compare is exactly the weakness that let
// AllowedCIDRs and ParentID vanish from the wire in the historical defects this
// harness exists to catch (see remote_proxy_correctness_audit_test.go's classes 3
// and 5) — a hand-picked assertion list has the identical blind spot as the
// hand-picked wire struct that dropped the field in the first place.
package http

import (
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// conformanceHarness wires a real LocalStorage-backed core.KeyorixCore behind a
// real server/http.NewRouter router, and a RemoteStorage pointed at it — the same
// pattern TestRemoteStorageLoginRateLimit_ThrottlesAcrossRealServer established,
// generalized for reuse across every seed method. ls and rs are two different
// storage.Storage handles onto the SAME backing database: ls talks to it directly
// in-process, rs talks to it over real HTTP through the real handler stack that
// wraps that exact ls instance. A field difference between what ls.M(x) and
// rs.M(x) each observe is therefore attributable only to what happens between
// RemoteStorage's client call and the server's own storage call — the proxy layer
// itself, not to two independent, unrelated databases drifting apart.
type conformanceHarness struct {
	upstreamCore  *core.KeyorixCore
	ls            *store.LocalStorage
	rs            *store.RemoteStorage
	server        *httptest.Server
	nodeToken     string
	adminUserID   uint
	projectID     uint
	environmentID uint
}

// newConformanceHarness bootstraps the system once (seeding an admin user, the
// admin/system_viewer roles, and a default project+environment — see
// createTestToken), mints a node-identity credential holding the admin role at
// global scope (createNodeToken — ADR-085's system.write ceiling requires a real
// role grant, not just "is a node"), and stands up a real router+server pair. The
// admin role is a strict superset of every permission gate the 7 seed methods sit
// behind (secrets.write/read, roles.assign, system.write, users.read — confirmed
// against internal/core/auth_bootstrap.go's adminPermissions) and additionally
// bypasses per-permission checks entirely as one of authz.go's adminRoleNames, so
// a single credential drives every seed method without per-test permission setup.
func newConformanceHarness(t *testing.T) *conformanceHarness {
	t.Helper()

	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstreamCore := newTestCore(t)
	ls, ok := upstreamCore.Storage().(*store.LocalStorage)
	require.True(t, ok, "conformance harness requires newTestCore to be LocalStorage-backed")

	token := createNodeToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	router, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        srv.URL,
		APIKey:         token,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)

	ctx := context.Background()
	admin, err := upstreamCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := ls.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects, "createTestToken must have seeded a default project")
	envs, err := ls.ListEnvironmentsByProject(ctx, projects[0].ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "createTestToken must have seeded a default environment")

	return &conformanceHarness{
		upstreamCore:  upstreamCore,
		ls:            ls,
		rs:            rs,
		server:        srv,
		nodeToken:     token,
		adminUserID:   admin.ID,
		projectID:     projects[0].ID,
		environmentID: envs[0].ID,
	}
}

// --- Field-exhaustive comparator ---

// fieldDiffs walks every exported field of want/got (structs, or pointers to the
// same struct type) via reflection and returns the names of every field whose
// value differs, skipping any field named in exclude. It is the pure, assertion-
// free core of assertFieldExhaustiveEqual below — kept separate so the mutation-
// validation tests (remote_storage_conformance_mutation_test.go) can assert
// directly on the diff set (e.g. "AllowedCIDRs must appear in the diff") without
// depending on *testing.T failure plumbing.
//
// time.Time / *time.Time fields are compared with Equal, not ==/DeepEqual: a
// value that round-trips through JSON changes Location (UTC becomes a fixed
// +00:00 offset) without changing the instant, and this repo has already hit that
// exact false-mismatch class once (see the GORM/SQLite timezone lesson in
// CLAUDE.md's memory). gorm.DeletedAt is compared on (Valid, Time.Equal) for the
// same reason.
func fieldDiffs(want, got interface{}, exclude map[string]bool) []string {
	wv := reflect.ValueOf(want)
	gv := reflect.ValueOf(got)
	if wv.Kind() == reflect.Pointer {
		if wv.IsNil() || gv.IsNil() {
			if wv.IsNil() != gv.IsNil() {
				return []string{"<nil-ness>"}
			}
			return nil
		}
		wv, gv = wv.Elem(), gv.Elem()
	}
	if wv.Type() != gv.Type() {
		return []string{fmt.Sprintf("<type: want %s, got %s>", wv.Type(), gv.Type())}
	}

	var diffs []string
	typ := wv.Type()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		if exclude[f.Name] {
			continue
		}
		wf := wv.Field(i).Interface()
		gf := gv.Field(i).Interface()
		if !valuesEqual(wf, gf) {
			diffs = append(diffs, f.Name)
		}
	}
	sort.Strings(diffs)
	return diffs
}

func valuesEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case time.Time:
		bv, ok := b.(time.Time)
		return ok && av.Equal(bv)
	case *time.Time:
		bv, ok := b.(*time.Time)
		if !ok {
			return false
		}
		if av == nil || bv == nil {
			return av == bv
		}
		return av.Equal(*bv)
	case gorm.DeletedAt:
		bv, ok := b.(gorm.DeletedAt)
		return ok && av.Valid == bv.Valid && av.Time.Equal(bv.Time)
	case models.JSON:
		bv, ok := b.(models.JSON)
		return ok && normalizeJSON(av) == normalizeJSON(bv)
	default:
		return reflect.DeepEqual(a, b)
	}
}

// normalizeJSON treats an empty/nil models.JSON and the literal 4-byte JSON
// "null" as the same value. models.JSON is a raw-passthrough []byte wrapper (see
// internal/storage/models/json.go): GORM's column Scanner returns a Go nil for an
// empty/absent column, but a value that round-trips through this harness's HTTP
// JSON envelope instead comes back as the literal text "null" (models.JSON's
// MarshalJSON emits "null" for a nil slice, matching the JSON spec, and its
// UnmarshalJSON stores the raw bytes it received verbatim rather than parsing
// them). Both represent "no metadata" once interpreted as JSON; only the Go-level
// representation differs, which is not a wire-fidelity defect this harness exists
// to catch. A genuine dropped/altered metadata VALUE (non-empty on one side, gone
// or different on the other) still fails this comparison — this normalizes only
// the nil-vs-null-literal case, not empty-vs-nonempty.
func normalizeJSON(j models.JSON) string {
	if len(j) == 0 || string(j) == "null" {
		return ""
	}
	return string(j)
}

// assertFieldExhaustiveEqual fails t with every differing field name (not just the
// first) when want and got diverge outside of exclude. label identifies the
// comparison in the failure message (method name + scenario).
func assertFieldExhaustiveEqual(t *testing.T, label string, want, got interface{}, exclude map[string]bool) {
	t.Helper()
	diffs := fieldDiffs(want, got, exclude)
	if len(diffs) > 0 {
		t.Errorf("%s: field-exhaustive comparison found %d differing field(s): %v\n  want: %#v\n  got:  %#v",
			label, len(diffs), diffs, want, got)
	}
}
