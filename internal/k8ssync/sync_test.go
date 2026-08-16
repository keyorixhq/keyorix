package k8ssync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFetcher serves values from a map; refs absent from the map return an error.
// fail models a TRANSIENT failure (network/5xx); revoked models a DEFINITIVE one
// (the real KeyorixFetcher's 404/401/403 handling, wrapping ErrUpstreamGone).
type fakeFetcher struct {
	values  map[string][]byte
	fail    map[string]bool
	revoked map[string]bool
}

func (f *fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if f.fail[ref] {
		return nil, errors.New("boom")
	}
	if f.revoked[ref] {
		return nil, fmt.Errorf("secret %q gone: %w", ref, ErrUpstreamGone)
	}
	v, ok := f.values[ref]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

// fakeSink records applies and can simulate pre-existing Secrets and apply errors.
// owned models the managed-by label: only owned Secrets are visible to List, and Apply
// stamps the Secret it writes as owned (mirroring the real label).
type fakeSink struct {
	existing  map[string]map[string][]byte // "ns/name" → data
	applied   map[string]map[string][]byte // "ns/name" → last applied data
	owned     map[string]bool              // "ns/name" → carries the managed-by label
	deleted   []string                     // "ns/name" deleted, in call order
	applyErr  map[string]bool
	getErr    map[string]bool
	listErr   map[string]bool // namespace → List fails
	deleteErr map[string]bool // "ns/name" → Delete fails
}

func newFakeSink() *fakeSink {
	return &fakeSink{
		existing:  map[string]map[string][]byte{},
		applied:   map[string]map[string][]byte{},
		owned:     map[string]bool{},
		applyErr:  map[string]bool{},
		getErr:    map[string]bool{},
		listErr:   map[string]bool{},
		deleteErr: map[string]bool{},
	}
}

func (s *fakeSink) key(ns, name string) string { return ns + "/" + name }

func (s *fakeSink) Get(_ context.Context, ns, name string) (map[string][]byte, error) {
	k := s.key(ns, name)
	if s.getErr[k] {
		return nil, errors.New("read error")
	}
	return s.existing[k], nil
}

func (s *fakeSink) Apply(_ context.Context, ns, name string, data map[string][]byte) error {
	k := s.key(ns, name)
	if s.applyErr[k] {
		return errors.New("apply error")
	}
	s.applied[k] = data
	s.existing[k] = data // reflect the write for subsequent comparisons
	s.owned[k] = true    // an applied Secret carries the managed-by label
	return nil
}

func (s *fakeSink) List(_ context.Context, ns string) ([]string, error) {
	if s.listErr[ns] {
		return nil, errors.New("list error")
	}
	var names []string
	for k, isOwned := range s.owned {
		if !isOwned {
			continue
		}
		if kns, name, ok := strings.Cut(k, "/"); ok && kns == ns {
			names = append(names, name)
		}
	}
	return names, nil
}

func (s *fakeSink) Delete(_ context.Context, ns, name string) error {
	k := s.key(ns, name)
	if s.deleteErr[k] {
		return errors.New("delete error")
	}
	s.deleted = append(s.deleted, k)
	delete(s.existing, k)
	delete(s.owned, k)
	return nil
}

func TestReconcile_CreatesAbsentSecret(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("p4ss"), "prod/api": []byte("k3y")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API_KEY"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	assert.Equal(t, 0, res.Updated+res.Unchanged+res.Failed)
	// Both keys landed in the one target Secret.
	assert.Equal(t, map[string][]byte{"DB_PASSWORD": []byte("p4ss"), "API_KEY": []byte("k3y")}, s.applied["app/creds"])
}

func TestReconcile_UnchangedWhenEqual(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("p4ss")}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("p4ss")}
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Unchanged)
	assert.Empty(t, s.applied, "an unchanged Secret must not be re-applied")
}

func TestReconcile_UpdatesOnRotation(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("rotated")}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("old")}
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Updated)
	assert.Equal(t, []byte("rotated"), s.applied["app/creds"]["DB_PASSWORD"])
}

func TestReconcile_FetchFailureSkipsWholeTarget(t *testing.T) {
	// One key fetches fine, the other fails: the Secret must NOT be written partially.
	f := &fakeFetcher{
		values: map[string][]byte{"prod/db": []byte("p4ss")},
		fail:   map[string]bool{"prod/api": true},
	}
	s := newFakeSink()
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API_KEY"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Failed)
	assert.Empty(t, s.applied, "a target with any failed fetch must not be applied")
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "app/creds")
}

// TestReconcile_RevokedUpstreamRemovesStaleSecret pins #140: on a definitive
// fetch failure (the upstream secret was deleted, or this agent's access was
// revoked), the PREVIOUSLY-materialized Secret must be actively removed from
// the cluster — not left at its last-known value indefinitely. The old
// behavior (skip and retry) never converges, since the same definitive
// failure recurs every pass; de-authorization never reached the cluster.
func TestReconcile_RevokedUpstreamRemovesStaleSecret(t *testing.T) {
	f := &fakeFetcher{revoked: map[string]bool{"prod/db": true}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("stale-value")}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Revoked)
	assert.Equal(t, 0, res.Failed, "a definitive revocation is not counted as a generic failure")
	assert.Contains(t, s.deleted, "app/creds", "the stale materialized Secret must be removed")
	_, stillExists := s.existing["app/creds"]
	assert.False(t, stillExists)
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "revoked")
}

// A TRANSIENT fetch failure (network error, 5xx) must NOT delete the existing
// Secret — only a definitive not-found/forbidden does. The old skip-and-retry
// behavior is exactly right here (the value may still be valid; the next pass
// will succeed once the transient issue clears).
func TestReconcile_TransientFetchFailureLeavesSecretUntouched(t *testing.T) {
	f := &fakeFetcher{fail: map[string]bool{"prod/db": true}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("still-valid")}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Failed)
	assert.Equal(t, 0, res.Revoked)
	assert.Empty(t, s.deleted, "a transient failure must not remove the existing Secret")
	assert.Equal(t, []byte("still-valid"), s.existing["app/creds"]["DB_PASSWORD"])
}

// In dry-run, a revocation is reported but not acted on.
func TestReconcile_RevokedUpstreamDryRunReportsButDoesNotDelete(t *testing.T) {
	f := &fakeFetcher{revoked: map[string]bool{"prod/db": true}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{"DB_PASSWORD": []byte("stale-value")}
	s.owned["app/creds"] = true
	e := NewEngine(f, s, WithDryRun())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Revoked)
	assert.Empty(t, s.deleted, "dry-run must not delete anything")
}

// TestReconcile_RevokedSingleKeyKeepsUnrelatedKeysInSameSecret pins the G05 fix: a
// target Secret backed by SEVERAL mappings (several distinct Keyorix refs, each its
// own key) must not be deleted wholesale just because ONE of those refs comes back
// ErrUpstreamGone (its lease independently revoked/rotated, or the secret deleted).
// The other, still-valid keys must survive — the Secret is updated to drop only the
// revoked key, never deleted outright, so unrelated workload-relied-upon keys in the
// same Secret aren't collaterally destroyed by one key's definitive failure.
func TestReconcile_RevokedSingleKeyKeepsUnrelatedKeysInSameSecret(t *testing.T) {
	f := &fakeFetcher{
		values:  map[string][]byte{"prod/api": []byte("k3y")},
		revoked: map[string]bool{"prod/db": true},
	}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{
		"DB_PASSWORD": []byte("stale-value"),
		"API_KEY":     []byte("k3y"),
	}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API_KEY"},
	})
	require.NoError(t, err)

	assert.Empty(t, s.deleted, "the whole Secret must not be deleted over one revoked key")
	assert.Equal(t, 0, res.Revoked, "the target itself was not removed, only trimmed")

	got, stillExists := s.existing["app/creds"]
	require.True(t, stillExists, "the Secret must still exist")
	assert.Equal(t, map[string][]byte{"API_KEY": []byte("k3y")}, got,
		"the still-valid key must survive; only the revoked key is dropped")

	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "revoked")
	assert.Contains(t, res.Errors[0], "prod/db")
}

// TestReconcile_RevokedAllKeysStillDeletesSecret confirms the existing single-mapping
// behavior generalizes correctly: when EVERY mapping for a target is revoked/gone
// (not just one of several), nothing valid remains and the Secret is still removed
// entirely, exactly as before the G05 fix.
func TestReconcile_RevokedAllKeysStillDeletesSecret(t *testing.T) {
	f := &fakeFetcher{revoked: map[string]bool{"prod/db": true, "prod/api": true}}
	s := newFakeSink()
	s.existing["app/creds"] = map[string][]byte{
		"DB_PASSWORD": []byte("stale-value"),
		"API_KEY":     []byte("also-stale"),
	}
	s.owned["app/creds"] = true
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB_PASSWORD"},
		{Ref: "prod/api", Namespace: "app", Name: "creds", Key: "API_KEY"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Revoked)
	assert.Contains(t, s.deleted, "app/creds")
	_, stillExists := s.existing["app/creds"]
	assert.False(t, stillExists)
}

func TestReconcile_DryRunReportsButDoesNotWrite(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/new": []byte("v"), "prod/chg": []byte("rotated")}}
	s := newFakeSink()
	s.existing["app/changed"] = map[string][]byte{"K": []byte("old")} // would update
	s.existing["app/same"] = map[string][]byte{"K": []byte("v")}      // unchanged
	e := NewEngine(f, s, WithDryRun())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/new", Namespace: "app", Name: "created", Key: "K"}, // would create
		{Ref: "prod/chg", Namespace: "app", Name: "changed", Key: "K"}, // would update
		{Ref: "prod/new", Namespace: "app", Name: "same", Key: "K"},    // unchanged
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created, "dry-run still reports a would-create")
	assert.Equal(t, 1, res.Updated, "dry-run still reports a would-update")
	assert.Equal(t, 1, res.Unchanged)
	assert.Empty(t, s.applied, "dry-run must not write any Secret")
}

func TestReconcile_OneTargetFailureDoesNotBlockOthers(t *testing.T) {
	f := &fakeFetcher{
		values: map[string][]byte{"prod/ok": []byte("v")},
		fail:   map[string]bool{"prod/bad": true},
	}
	s := newFakeSink()
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/bad", Namespace: "app", Name: "broken", Key: "K"},
		{Ref: "prod/ok", Namespace: "app", Name: "good", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created, "the healthy target still syncs")
	assert.Equal(t, 1, res.Failed)
	assert.Contains(t, s.applied, "app/good")
	assert.NotContains(t, s.applied, "app/broken")
}

func TestReconcile_ApplyAndGetErrors(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"r": []byte("v")}}
	s := newFakeSink()
	s.applyErr["app/applyfail"] = true
	s.getErr["app/getfail"] = true
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "r", Namespace: "app", Name: "applyfail", Key: "K"},
		{Ref: "r", Namespace: "app", Name: "getfail", Key: "K"},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Failed)
	assert.Len(t, res.Errors, 2)
}

func TestReconcile_InvalidAndDuplicateMappings(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"r": []byte("v")}}
	s := newFakeSink()
	e := NewEngine(f, s)

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "", Namespace: "app", Name: "x", Key: "K"},    // invalid: no ref
		{Ref: "r", Namespace: "", Name: "x", Key: "K"},      // invalid: no namespace
		{Ref: "r", Namespace: "app", Name: "dup", Key: "K"}, // ok
		{Ref: "r", Namespace: "app", Name: "dup", Key: "K"}, // duplicate key for same Secret
	})
	require.NoError(t, err)
	// 2 invalid + 1 duplicate = 3 failures recorded; the one valid target is created.
	assert.Equal(t, 3, res.Failed)
	assert.Equal(t, 1, res.Created)
	assert.Len(t, res.Errors, 3)
}

func TestReconcile_CleanupDeletesOrphan(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	// An agent-owned Secret left over from a mapping that no longer exists.
	s.owned["app/stale"] = true
	s.existing["app/stale"] = map[string][]byte{"K": []byte("old")}
	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	assert.Equal(t, 1, res.Deleted)
	assert.Equal(t, []string{"app/stale"}, s.deleted)
	assert.NotContains(t, s.existing, "app/stale", "the orphan is gone")
	assert.Contains(t, s.existing, "app/creds", "the live target remains")
}

func TestReconcile_CleanupDisabledByDefault(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	s.owned["app/stale"] = true
	s.existing["app/stale"] = map[string][]byte{"K": []byte("old")}
	e := NewEngine(f, s) // no WithCleanup

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Deleted)
	assert.Empty(t, s.deleted, "cleanup must be opt-in: nothing is deleted by default")
	assert.Contains(t, s.existing, "app/stale")
}

func TestReconcile_CleanupDryRunReportsButDoesNotDelete(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	s.owned["app/stale"] = true
	s.existing["app/stale"] = map[string][]byte{"K": []byte("old")}
	e := NewEngine(f, s, WithCleanup(), WithDryRun())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Deleted, "dry-run reports the would-delete")
	assert.Empty(t, s.deleted, "dry-run must not delete any Secret")
	assert.Contains(t, s.existing, "app/stale")
}

func TestReconcile_CleanupKeepsDesiredTargetWhenFetchFails(t *testing.T) {
	// A target still in the config whose upstream fetch fails this pass must NOT be
	// reaped — a transient Keyorix error can't be allowed to delete a live Secret.
	f := &fakeFetcher{fail: map[string]bool{"prod/db": true}}
	s := newFakeSink()
	s.owned["app/creds"] = true
	s.existing["app/creds"] = map[string][]byte{"DB": []byte("live")}
	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Failed)
	assert.Equal(t, 0, res.Deleted)
	assert.Empty(t, s.deleted)
	assert.Contains(t, s.existing, "app/creds", "the still-desired target survives a fetch failure")
}

func TestReconcile_CleanupIgnoresUnownedSecrets(t *testing.T) {
	// A foreign Secret (no managed-by label) in a managed namespace is invisible to
	// List, so cleanup never touches it.
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	s.existing["app/foreign"] = map[string][]byte{"K": []byte("notours")} // present but not owned
	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Deleted)
	assert.Empty(t, s.deleted)
	assert.Contains(t, s.existing, "app/foreign", "a Secret the agent never created is left alone")
}

func TestReconcile_CleanupListErrorIsRecorded(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	s.listErr["app"] = true
	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Created)
	assert.Equal(t, 1, res.Failed, "a list failure is surfaced, not silently swallowed")
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "list owned")
}

func TestReconcile_CleanupDeleteErrorIsRecorded(t *testing.T) {
	f := &fakeFetcher{values: map[string][]byte{"prod/db": []byte("v")}}
	s := newFakeSink()
	s.owned["app/stale"] = true
	s.existing["app/stale"] = map[string][]byte{"K": []byte("old")}
	s.deleteErr["app/stale"] = true
	e := NewEngine(f, s, WithCleanup())

	res, err := e.Reconcile(context.Background(), []SecretMapping{
		{Ref: "prod/db", Namespace: "app", Name: "creds", Key: "DB"},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Deleted)
	assert.Equal(t, 1, res.Failed)
	require.Len(t, res.Errors, 1)
	assert.Contains(t, res.Errors[0], "delete orphan")
}
