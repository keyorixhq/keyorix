package cmd

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
)

// fakeTargetAPI is an in-process target.API fake — no network, no Keyorix server — for testing
// the cmd layer's plan/resume wiring in isolation, mirroring internal/plan/plan_test.go's own
// fakeAPI (kept package-local rather than exported from internal/plan, matching that package's
// existing convention of not exposing its test fake outside itself).
type fakeTargetAPI struct {
	byName map[string]int
	meta   map[int]map[string]string
	value  map[int]string
	nextID int
}

func newFakeTargetAPI() *fakeTargetAPI {
	return &fakeTargetAPI{byName: map[string]int{}, meta: map[int]map[string]string{}, value: map[int]string{}, nextID: 1}
}

func (f *fakeTargetAPI) LookupByName(_ context.Context, name string) (int, bool, error) {
	id, ok := f.byName[name]
	return id, ok, nil
}

func (f *fakeTargetAPI) Metadata(_ context.Context, id int) (map[string]string, error) {
	return f.meta[id], nil
}

func (f *fakeTargetAPI) Value(_ context.Context, id int) (string, error) {
	return f.value[id], nil
}

func (f *fakeTargetAPI) Create(_ context.Context, name, value string, metadata map[string]string) (int, error) {
	id := f.nextID
	f.nextID++
	f.byName[name] = id
	f.value[id] = value
	f.meta[id] = metadata
	return id, nil
}

func (f *fakeTargetAPI) UpdateValue(_ context.Context, id int, value string) error {
	f.value[id] = value
	return nil
}

func TestBuildCloudPlanEntries_SanitizesNameAndExplodesField(t *testing.T) {
	entries := []cloudentry.Entry{
		{RawName: "team a/db password", Value: "v1", Locator: "loc1"},
		{RawName: "creds", Field: "username", Value: "alice", Locator: "loc2"},
	}
	out := buildCloudPlanEntries("aws", entries, func(e cloudentry.Entry) string { return "sid-" + e.RawName })
	if len(out) != 2 {
		t.Fatalf("out = %+v, want 2", out)
	}
	if out[0].Name != "team-a-db-password" {
		t.Errorf("out[0].Name = %q, want sanitized team-a-db-password", out[0].Name)
	}
	if out[1].Name != "creds-username" {
		t.Errorf("out[1].Name = %q, want creds-username (field-exploded)", out[1].Name)
	}
	if out[0].SourceKind != "aws" {
		t.Errorf("out[0].SourceKind = %q, want aws", out[0].SourceKind)
	}
}

// TestSplitIntraBatchNameCollisions_SecondOfTwoSameNameEntriesIsConflict is the "name collision"
// case: two source items in ONE run that sanitize to the same Keyorix secret name must never
// both silently plan as Create — plan.BuildPlan alone cannot catch this (see this function's own
// doc comment), so the cmd layer must.
func TestSplitIntraBatchNameCollisions_SecondOfTwoSameNameEntriesIsConflict(t *testing.T) {
	entries := []plan.Entry{
		{Name: "foo", Value: "v1", SourceID: "sid-1"},
		{Name: "foo", Value: "v2", SourceID: "sid-2"}, // e.g. a whole secret and its own split-json field colliding
		{Name: "bar", Value: "v3", SourceID: "sid-3"},
	}
	unique, collided := splitIntraBatchNameCollisions(entries)
	if len(unique) != 2 {
		t.Fatalf("unique = %+v, want 2 (first foo + bar)", unique)
	}
	if len(collided) != 1 {
		t.Fatalf("collided = %+v, want 1", collided)
	}
	if collided[0].Entry.SourceID != "sid-2" {
		t.Errorf("collided[0] = %+v, want the SECOND foo (sid-2) flagged, first one wins", collided[0])
	}
	if collided[0].Outcome != plan.Conflict {
		t.Errorf("collided[0].Outcome = %q, want Conflict", collided[0].Outcome)
	}
	if collided[0].Reason == "" {
		t.Error("collided[0] has no Reason explaining the collision")
	}
}

func TestSplitIntraBatchNameCollisions_NoCollisionPassesAllThrough(t *testing.T) {
	entries := []plan.Entry{{Name: "foo"}, {Name: "bar"}}
	unique, collided := splitIntraBatchNameCollisions(entries)
	if len(unique) != 2 || len(collided) != 0 {
		t.Fatalf("unique=%+v collided=%+v, want 2 unique and 0 collided", unique, collided)
	}
}

// TestCloudEntryResumeThroughPlan proves the resume mechanism (docs/design-keyorix-migrate.md's
// "Resume" section) is inherited by construction for a cloud-shaped entry, exactly as it is for
// Vault: BuildPlan+Apply are source-agnostic (plan_test.go covers the decision logic directly),
// so applying only the first of two planned items, then rebuilding the plan fresh, must resolve
// the already-applied item to Skip and only actually write the second.
func TestCloudEntryResumeThroughPlan(t *testing.T) {
	cloudEntries := []cloudentry.Entry{
		{RawName: "s1", Value: "v1", Locator: "aws-secrets-manager:us-east-1/s1"},
		{RawName: "s2", Value: "v2", Locator: "aws-secrets-manager:us-east-1/s2"},
	}
	planEntries := buildCloudPlanEntries("aws", cloudEntries, func(e cloudentry.Entry) string {
		return plan.SourceID("aws", "us-east-1", e.RawName, "value")
	})

	api := newFakeTargetAPI()
	items, err := plan.BuildPlan(t.Context(), api, planEntries)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(items) != 2 || items[0].Outcome != plan.Create || items[1].Outcome != plan.Create {
		t.Fatalf("items = %+v, want two Create", items)
	}

	// Simulate a kill mid-run: only the first item is ever applied.
	plan.Apply(t.Context(), api, items[:1], false)

	// Resume: rebuild the plan fresh from scratch, exactly as a re-run of the tool would.
	resumed, err := plan.BuildPlan(t.Context(), api, planEntries)
	if err != nil {
		t.Fatalf("BuildPlan (resume): %v", err)
	}
	if resumed[0].Outcome != plan.Skip {
		t.Errorf("resumed[0].Outcome = %q, want Skip (already applied)", resumed[0].Outcome)
	}
	if resumed[1].Outcome != plan.Create {
		t.Errorf("resumed[1].Outcome = %q, want Create (never applied)", resumed[1].Outcome)
	}

	results := plan.Apply(t.Context(), api, resumed, false)
	created := 0
	for _, r := range results {
		if r.Ran {
			created++
		}
	}
	if created != 1 {
		t.Errorf("resume run performed %d writes, want exactly 1 (the un-applied item)", created)
	}
}
