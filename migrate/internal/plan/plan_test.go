package plan

import (
	"context"
	"errors"
	"testing"
)

// fakeAPI is an in-process target.API fake — no network, no Vault, no Keyorix — for testing
// BuildPlan/Apply's decision logic in isolation. internal/e2e's tests cover the same
// contract through the real wire encoding; these tests cover the decision branches more
// exhaustively and run fast enough to always be part of default CI (no VAULT_ADDR gate).
type fakeAPI struct {
	byName map[string]int
	meta   map[int]map[string]string
	value  map[int]string
	nextID int

	lookupErr error
	metaErr   error
	valueErr  error

	created []string
	updated []int
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		byName: map[string]int{},
		meta:   map[int]map[string]string{},
		value:  map[int]string{},
		nextID: 1,
	}
}

func (f *fakeAPI) LookupByName(_ context.Context, name string) (int, bool, error) {
	if f.lookupErr != nil {
		return 0, false, f.lookupErr
	}
	id, ok := f.byName[name]
	return id, ok, nil
}

func (f *fakeAPI) Metadata(_ context.Context, id int) (map[string]string, error) {
	if f.metaErr != nil {
		return nil, f.metaErr
	}
	return f.meta[id], nil
}

func (f *fakeAPI) Value(_ context.Context, id int) (string, error) {
	if f.valueErr != nil {
		return "", f.valueErr
	}
	return f.value[id], nil
}

func (f *fakeAPI) Create(_ context.Context, name, value string, metadata map[string]string) (int, error) {
	id := f.nextID
	f.nextID++
	f.byName[name] = id
	f.value[id] = value
	f.meta[id] = metadata
	f.created = append(f.created, name)
	return id, nil
}

func (f *fakeAPI) UpdateValue(_ context.Context, id int, value string) error {
	f.value[id] = value
	f.updated = append(f.updated, id)
	return nil
}

func TestBuildPlan_NewSecretIsCreate(t *testing.T) {
	api := newFakeAPI()
	items, err := BuildPlan(context.Background(), api, []Entry{{Name: "foo", Value: "v1", SourceID: "sid-1"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 1 || items[0].Outcome != Create {
		t.Fatalf("items = %+v, want one Create", items)
	}
}

func TestBuildPlan_MatchingSourceIDSameValueIsSkip(t *testing.T) {
	api := newFakeAPI()
	api.byName["foo"] = 1
	api.meta[1] = map[string]string{"migrate.source-id": "sid-1"}
	api.value[1] = "v1"

	items, err := BuildPlan(context.Background(), api, []Entry{{Name: "foo", Value: "v1", SourceID: "sid-1"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 1 || items[0].Outcome != Skip || items[0].ExistingID != 1 {
		t.Fatalf("items = %+v, want one Skip against id 1", items)
	}
}

func TestBuildPlan_MatchingSourceIDDifferentValueIsUpdate(t *testing.T) {
	api := newFakeAPI()
	api.byName["foo"] = 1
	api.meta[1] = map[string]string{"migrate.source-id": "sid-1"}
	api.value[1] = "old-value"

	items, err := BuildPlan(context.Background(), api, []Entry{{Name: "foo", Value: "new-value", SourceID: "sid-1"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 1 || items[0].Outcome != Update || items[0].ExistingID != 1 {
		t.Fatalf("items = %+v, want one Update against id 1", items)
	}
}

func TestBuildPlan_NameCollisionWithoutMatchingSourceIDIsConflict(t *testing.T) {
	api := newFakeAPI()
	api.byName["foo"] = 1
	api.meta[1] = map[string]string{} // no migrate.source-id at all: hand-created secret.
	api.value[1] = "hand-created-value"

	items, err := BuildPlan(context.Background(), api, []Entry{{Name: "foo", Value: "v1", SourceID: "sid-1"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 1 || items[0].Outcome != Conflict || items[0].ExistingID != 1 {
		t.Fatalf("items = %+v, want one Conflict against id 1", items)
	}
	if items[0].Reason == "" {
		t.Error("Conflict item has no Reason explaining the collision")
	}
}

func TestBuildPlan_DifferentSourceIDSameNameIsConflict(t *testing.T) {
	api := newFakeAPI()
	api.byName["foo"] = 1
	api.meta[1] = map[string]string{"migrate.source-id": "sid-OTHER"}
	api.value[1] = "v1"

	items, err := BuildPlan(context.Background(), api, []Entry{{Name: "foo", Value: "v1", SourceID: "sid-1"}})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 1 || items[0].Outcome != Conflict {
		t.Fatalf("items = %+v, want one Conflict (different source-id, same name)", items)
	}
}

func TestBuildPlan_LookupErrorBecomesPerItemError(t *testing.T) {
	api := newFakeAPI()
	api.lookupErr = errors.New("network exploded")

	items, err := BuildPlan(context.Background(), api, []Entry{
		{Name: "foo", Value: "v1", SourceID: "sid-1"},
		{Name: "bar", Value: "v2", SourceID: "sid-2"},
	})
	if err != nil {
		t.Fatalf("BuildPlan returned a top-level error, want per-item Error outcomes: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (one bad item must not swallow the others)", len(items))
	}
	for _, item := range items {
		if item.Outcome != Error {
			t.Errorf("item %q outcome = %s, want Error", item.Entry.Name, item.Outcome)
		}
	}
}

func TestApply_CreateWritesSourceIDAndSourceKindMetadata(t *testing.T) {
	api := newFakeAPI()
	items := []Item{{Entry: Entry{SourceKind: "vault", Name: "foo", Value: "v1", SourceID: "sid-1", Metadata: map[string]string{"owner": "team-a"}}, Outcome: Create}}

	results := Apply(context.Background(), api, items, false)
	if len(results) != 1 || results[0].Error != "" || !results[0].Ran {
		t.Fatalf("results = %+v, want one successful Create", results)
	}
	id := api.byName["foo"]
	if api.meta[id]["migrate.source-id"] != "sid-1" {
		t.Errorf("stored metadata = %v, want migrate.source-id=sid-1", api.meta[id])
	}
	if api.meta[id]["migrate.source"] != "vault" {
		t.Errorf("stored metadata = %v, want migrate.source=vault", api.meta[id])
	}
	if api.meta[id]["vault.owner"] != "team-a" {
		t.Errorf("stored metadata = %v, want vault.owner=team-a (source metadata prefixed by source kind)", api.meta[id])
	}
}

// TestApply_CreateWritesSourceVersionAndCreatedAt is Andrei's 2026-09-25 decision on
// all-versions import: every imported secret records which source version it came from, even
// though only the latest version is ever imported.
func TestApply_CreateWritesSourceVersionAndCreatedAt(t *testing.T) {
	api := newFakeAPI()
	items := []Item{{Entry: Entry{SourceKind: "vault", Name: "foo", Value: "v1", SourceID: "sid-1", SourceVersion: "3", SourceCreatedAt: "2026-09-25T00:00:00Z"}, Outcome: Create}}

	results := Apply(context.Background(), api, items, false)
	if len(results) != 1 || results[0].Error != "" {
		t.Fatalf("results = %+v, want one successful Create", results)
	}
	id := api.byName["foo"]
	if api.meta[id]["migrate.source-version"] != "3" {
		t.Errorf("stored metadata = %v, want migrate.source-version=3", api.meta[id])
	}
	if api.meta[id]["migrate.source-created-at"] != "2026-09-25T00:00:00Z" {
		t.Errorf("stored metadata = %v, want migrate.source-created-at=2026-09-25T00:00:00Z", api.meta[id])
	}
}

// TestApply_CreateOmitsEmptySourceVersion covers a source with no version concept (Vault KV
// v1): the metadata key must not appear at all, not appear with an empty value.
func TestApply_CreateOmitsEmptySourceVersion(t *testing.T) {
	api := newFakeAPI()
	items := []Item{{Entry: Entry{SourceKind: "vault", Name: "foo", Value: "v1", SourceID: "sid-1"}, Outcome: Create}}

	Apply(context.Background(), api, items, false)
	id := api.byName["foo"]
	if _, ok := api.meta[id]["migrate.source-version"]; ok {
		t.Errorf("stored metadata = %v, want no migrate.source-version key for a versionless source", api.meta[id])
	}
	if _, ok := api.meta[id]["migrate.source-created-at"]; ok {
		t.Errorf("stored metadata = %v, want no migrate.source-created-at key for a versionless source", api.meta[id])
	}
}

func TestApply_SkipDoesNotCallAPI(t *testing.T) {
	api := newFakeAPI()
	items := []Item{{Entry: Entry{Name: "foo"}, Outcome: Skip, ExistingID: 1}}
	results := Apply(context.Background(), api, items, false)
	if len(results) != 1 || results[0].Ran {
		t.Fatalf("results = %+v, want one un-run Skip", results)
	}
	if len(api.created) != 0 || len(api.updated) != 0 {
		t.Errorf("Skip caused a write: created=%v updated=%v", api.created, api.updated)
	}
}

func TestApply_ConflictWithoutForceDoesNotWrite(t *testing.T) {
	api := newFakeAPI()
	items := []Item{{Entry: Entry{Name: "foo", Value: "v1"}, Outcome: Conflict, ExistingID: 1}}
	results := Apply(context.Background(), api, items, false)
	if len(results) != 1 || results[0].Ran {
		t.Fatalf("results = %+v, want one un-run Conflict (force=false)", results)
	}
	if len(api.updated) != 0 {
		t.Errorf("Conflict without --force wrote anyway: updated=%v", api.updated)
	}
}

func TestApply_ConflictWithForceOverwrites(t *testing.T) {
	api := newFakeAPI()
	api.value[1] = "someone-elses-value"
	items := []Item{{Entry: Entry{Name: "foo", Value: "v1"}, Outcome: Conflict, ExistingID: 1}}
	results := Apply(context.Background(), api, items, true)
	if len(results) != 1 || !results[0].Ran || results[0].Error != "" {
		t.Fatalf("results = %+v, want one successful forced overwrite", results)
	}
	if api.value[1] != "v1" {
		t.Errorf("value after forced overwrite = %q, want v1", api.value[1])
	}
}

func TestSourceID_StableAndDistinct(t *testing.T) {
	a := SourceID("addr", "mount", "path", "value")
	b := SourceID("addr", "mount", "path", "value")
	if a != b {
		t.Error("SourceID is not deterministic across identical inputs")
	}
	c := SourceID("addr", "mount", "other-path", "value")
	if a == c {
		t.Error("SourceID collided across different inputs")
	}
}
