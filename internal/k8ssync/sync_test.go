package k8ssync

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFetcher serves values from a map; refs absent from the map return an error.
type fakeFetcher struct {
	values map[string][]byte
	fail   map[string]bool
}

func (f *fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	if f.fail[ref] {
		return nil, errors.New("boom")
	}
	v, ok := f.values[ref]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

// fakeSink records applies and can simulate pre-existing Secrets and apply errors.
type fakeSink struct {
	existing map[string]map[string][]byte // "ns/name" → data
	applied  map[string]map[string][]byte // "ns/name" → last applied data
	applyErr map[string]bool
	getErr   map[string]bool
}

func newFakeSink() *fakeSink {
	return &fakeSink{
		existing: map[string]map[string][]byte{},
		applied:  map[string]map[string][]byte{},
		applyErr: map[string]bool{},
		getErr:   map[string]bool{},
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
