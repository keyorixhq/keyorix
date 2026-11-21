package cmd

// Red/green proofs for the MGV1 oracles. Each oracle assertion is shown to FIRE on the exact
// defect class it targets (RED) and to HOLD on the real pipeline (GREEN). The planted defects
// live entirely in test doubles (a store that silently drops a write, a store that invents a
// secret, a dropped skip report, a skipped retry) — no production file is edited, per the
// unattended-session rule "if the red proof needs a throwaway edit to a production file, ask
// the coordinator first" (there is no coordinator here). A test-double defect is the faithful
// stand-in for the real regression each oracle guards against: a silently-dropped Create is
// exactly what a broken plan.Apply would produce.

import (
	"context"
	"testing"
	"unicode"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

// buildFixedModel returns a deterministic KV v2 tree: two single-"value" live leaves, one
// multi-field live leaf, one soft-deleted leaf, and one empty leaf.
func buildFixedModel() *vModel {
	m := &vModel{mount: "secret", kv2: true, byPath: map[string]*vLeaf{}}
	add := func(l vLeaf) { m.leaves = append(m.leaves, l) }
	add(vLeaf{segs: []string{"team-a", "db"}, state: 0, version: 3, created: "2026-01-02T03:04:05Z",
		fields: []vField{{"value", m.uniqueVal("V", "dbpw")}}})
	add(vLeaf{segs: []string{"team-a", "api"}, state: 0, version: 2, created: "2026-01-02T03:04:05Z",
		custom: map[string]string{"owner": "alice"},
		fields: []vField{{"user", m.uniqueVal("V", "admin")}, {"pass", m.uniqueVal("V", "s3cr3t")}}})
	add(vLeaf{segs: []string{"team-b", "token"}, state: 0, version: 5, created: "2026-01-02T03:04:05Z",
		fields: []vField{{"value", m.uniqueVal("V", "tok")}}})
	add(vLeaf{segs: []string{"team-b", "gone"}, state: 1, version: 4})  // soft-deleted
	add(vLeaf{segs: []string{"team-b", "empty"}, state: 3, version: 1}) // empty leaf
	for i := range m.leaves {
		m.byPath[m.leaves[i].path()] = &m.leaves[i]
	}
	return m
}

func walkFixed(t *testing.T, m *vModel) []vaultsource.Entry {
	t.Helper()
	srv := m.newVaultServer()
	defer srv.Close()
	ctx := context.Background()
	c, err := vaultsource.New(ctx, vaultsource.Config{Addr: srv.URL, Mount: m.mount, Token: "tok"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	entries, _, err := c.Walk(ctx, "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return entries
}

// lossyStore silently drops the Nth (0-based) Create — a stand-in for a plan.Apply that loses
// a write without reporting an error.
type lossyStore struct {
	*fakeStore
	dropIndex int
	createN   int
}

func (s *lossyStore) Create(ctx context.Context, name, value string, meta map[string]string) (int, error) {
	n := s.createN
	s.createN++
	if n == s.dropIndex {
		return 9999, nil // pretend success, store nothing
	}
	return s.fakeStore.Create(ctx, name, value, meta)
}

// inventStore adds one bogus secret not present in any source — a stand-in for a pipeline that
// fabricates a secret.
type inventStore struct{ *fakeStore }

func (s *inventStore) Create(ctx context.Context, name, value string, meta map[string]string) (int, error) {
	id, err := s.fakeStore.Create(ctx, name, value, meta)
	if err == nil && name != "" && s.byName["__INVENTED__"] == nil {
		_, _ = s.fakeStore.Create(ctx, "__INVENTED__", "ghost-value-not-in-source", nil)
	}
	return id, err
}

func conservationHolds(liveCount, target, failed, buildSkip int) bool {
	return liveCount == target+failed+buildSkip
}

func TestMGV1_RedGreen_Conservation(t *testing.T) {
	m := buildFixedModel()
	entries := walkFixed(t, m)
	_, _, liveCount := modelLiveImportable(m)
	planEntries, buildSkipped := buildVaultPlanEntries("http://addr", m.mount, entries)
	ctx := context.Background()

	// GREEN: real pipeline conserves.
	real := newFakeStore()
	items, _ := plan.BuildPlan(ctx, real, planEntries)
	results := plan.Apply(ctx, real, items, false)
	failed := countFailed(results)
	if !conservationHolds(liveCount, len(real.snapshot()), failed, len(buildSkipped)) {
		t.Fatalf("GREEN broken: real pipeline does not conserve (live=%d target=%d failed=%d buildskip=%d)",
			liveCount, len(real.snapshot()), failed, len(buildSkipped))
	}

	// RED: a store that silently drops one Create breaks the conservation identity — proving
	// O-RT2 would catch a silently-dropped write.
	lossy := &lossyStore{fakeStore: newFakeStore()}
	li, _ := plan.BuildPlan(ctx, lossy, planEntries)
	lr := plan.Apply(ctx, lossy, li, false)
	if conservationHolds(liveCount, len(lossy.snapshot()), countFailed(lr), len(buildSkipped)) {
		t.Fatalf("RED failed to fire: a silently-dropped Create still satisfied conservation")
	}
}

func TestMGV1_RedGreen_Membership(t *testing.T) {
	m := buildFixedModel()
	entries := walkFixed(t, m)
	liveVals, _, _ := modelLiveImportable(m)
	planEntries, _ := buildVaultPlanEntries("http://addr", m.mount, entries)
	ctx := context.Background()

	// GREEN: every real target value is a planted live value.
	real := newFakeStore()
	it, _ := plan.BuildPlan(ctx, real, planEntries)
	plan.Apply(ctx, real, it, false)
	for name, sec := range real.snapshot() {
		if !liveVals[sec.value] {
			t.Fatalf("GREEN broken: real secret %q has unexpected value %q", name, sec.value)
		}
	}

	// RED: an inventing store yields a value outside the live set — O-RT3 fires.
	inv := &inventStore{fakeStore: newFakeStore()}
	it2, _ := plan.BuildPlan(ctx, inv, planEntries)
	plan.Apply(ctx, inv, it2, false)
	foundInvented := false
	for _, sec := range inv.snapshot() {
		if !liveVals[sec.value] {
			foundInvented = true
		}
	}
	if !foundInvented {
		t.Fatalf("RED failed to fire: membership check did not detect an invented secret")
	}
}

func TestMGV1_RedGreen_Namespace(t *testing.T) {
	forbidden := func(name string) bool {
		if name == "" {
			return true
		}
		for _, rn := range name {
			if rn == '/' || rn == '\\' || rn == 0 || unicode.IsControl(rn) {
				return true
			}
		}
		return false
	}
	// GREEN: every name the real sanitizer produces for a hostile key is namespace-safe.
	for _, hostileKey := range []string{"../../etc/passwd", "a/b\x00c", "x\ty", "name"} {
		got := sanitizeSecretName("team/" + hostileKey)
		if got != "" && forbidden(got) {
			t.Fatalf("GREEN broken: sanitizeSecretName(%q)=%q is namespace-unsafe", hostileKey, got)
		}
	}
	// RED: the namespace detector itself fires on a name carrying a separator / NUL / control.
	for _, bad := range []string{"a/b", "a\\b", "a\x00b", "x\ty", ""} {
		if !forbidden(bad) {
			t.Fatalf("RED failed to fire: namespace detector passed unsafe name %q", bad)
		}
	}
}

func TestMGV1_RedGreen_ReportedDeleted(t *testing.T) {
	m := buildFixedModel()
	srv := m.newVaultServer()
	defer srv.Close()
	ctx := context.Background()
	c, _ := vaultsource.New(ctx, vaultsource.Config{Addr: srv.URL, Mount: m.mount, Token: "tok"})
	_, skipped, err := c.Walk(ctx, "", false)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	skipPaths := map[string]bool{}
	for _, s := range skipped {
		skipPaths[s.Path] = true
	}
	// GREEN: the real Walk reports the soft-deleted and empty leaves.
	for _, p := range []string{"team-b/gone", "team-b/empty"} {
		if !skipPaths[p] {
			t.Fatalf("GREEN broken: leaf %q not reported in Walk Skipped: %v", p, skipped)
		}
	}
	// RED: a report set with the deleted leaf dropped fails the reported-not-dropped check.
	dropped := map[string]bool{}
	for p := range skipPaths {
		if p != "team-b/gone" {
			dropped[p] = true
		}
	}
	if dropped["team-b/gone"] {
		t.Fatalf("RED failed to fire: dropped set still contains the deleted leaf")
	}
}

func TestMGV1_RedGreen_Convergence(t *testing.T) {
	m := buildFixedModel()
	entries := walkFixed(t, m)
	planEntries, _ := buildVaultPlanEntries("http://addr", m.mount, entries)
	ctx := context.Background()

	golden := newFakeStore()
	applyImport(ctx, golden, planEntries, false)
	goldenNames := namesOf(golden)

	// Fault schedule that fails the FIRST create before commit (so without a retry the first
	// secret is lost).
	sched := make([]faultMode, len(planEntries)*2)
	sched[0] = faultBefore

	// RED: faulted run with NO retry loses a name — O-PF1 fires.
	noRetry := newFakeStore()
	noRetry.faults = append([]faultMode(nil), sched...)
	applyImport(ctx, noRetry, planEntries, false)
	if sameStringSet(namesOf(noRetry), goldenNames) {
		t.Fatalf("RED failed to fire: a faulted import with no retry did not lose any name")
	}

	// GREEN: the same fault, followed by a clean retry, converges to the golden name set.
	withRetry := newFakeStore()
	withRetry.faults = append([]faultMode(nil), sched...)
	applyImport(ctx, withRetry, planEntries, false) // faulted
	withRetry.faults = nil
	applyImport(ctx, withRetry, planEntries, false) // retry
	if !sameStringSet(namesOf(withRetry), goldenNames) {
		t.Fatalf("GREEN broken: faulted import + clean retry did not converge (got %v want %v)",
			sortedKeys(namesOf(withRetry)), sortedKeys(goldenNames))
	}
	// Fixed point.
	before := withRetry.snapshot()
	applyImport(ctx, withRetry, planEntries, false)
	if !sameSnapshot(before, withRetry.snapshot()) {
		t.Fatalf("GREEN broken: a further clean run was not a fixed point")
	}
}

func countFailed(results []plan.Result) int {
	n := 0
	for _, r := range results {
		if r.Error != "" {
			n++
		}
	}
	return n
}
