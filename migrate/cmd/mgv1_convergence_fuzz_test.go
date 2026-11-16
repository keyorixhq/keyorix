package cmd

// FuzzVaultImportConvergence — the MGV1 partial-failure oracle. It imports a generated Vault
// KV tree while failing write seams (target.Create / target.UpdateValue) BEFORE a commit
// (nothing written) or AFTER an atomic commit (row+metadata written, but the client sees an
// error — the classic "committed server-side, response lost" HTTP partial failure). It then
// re-runs the import cleanly (the operator's retry) and requires convergence: every secret
// present exactly once, no duplicates, no lost names, no soft-deleted value resurrected, and a
// further clean run is a fixed point (idempotent).
//
// This exercises the idempotency design (plan.planOne: match by name, then stored source-id,
// then value). A regression that broke it — dropping the source-id check, or the
// value-equality Skip — would make a retry re-create or wrongly Conflict, which this oracle
// catches. The fakeStore models the real Create as an ATOMIC row+metadata write (one HTTP
// POST): a post-commit fault still persists the source-id, so a retry can recognise it.
//
// Oracles (what each does NOT verify is in .scratch/mgv1-REPORT.md):
//   - O-PF1 NO-LOST-NAMES: after retry, the set of target names equals the set a clean import
//     produces — no secret vanished because a write seam failed mid-run.
//   - O-PF2 VALID-WINNER: each surviving secret's value is a planted live value for that
//     derived name (never empty, garbage, or a soft-deleted value).
//   - O-PF3 NO-DUPLICATES: target values are distinct; one row per name.
//   - O-PF4 FIXED-POINT: a further clean re-run changes nothing (idempotent convergence).
//
// Resource meters: inline memory-alloc ceiling + hang deadline + native go-test panic
// detection. Network/disk/sleep meters are not applicable — the convergence pipeline makes a
// single clean Vault walk and then runs entirely in-memory. (The shared hostile.Harness is
// used by FuzzVaultImportRoundTrip, which is the network-bearing target.)

import (
	"context"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

func FuzzVaultImportConvergence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	f.Add([]byte{0, 0, 0, 255, 128, 64, 32, 16, 8, 4, 2, 1, 3, 5, 7, 9})
	f.Add(bytesRange(80))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)

		r := &reader{b: data}
		m := genModel(r)
		srv := m.newVaultServer()
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 20*1e9) // 20s hang guard
		defer cancel()

		c, err := vaultsource.New(ctx, vaultsource.Config{Addr: srv.URL, Mount: m.mount, Token: "kx-mgv1-token"})
		if err != nil {
			t.Fatalf("vaultsource.New: %v", err)
		}
		entries, _, err := c.Walk(ctx, "", false)
		if err != nil {
			return // a Walk error is fail-closed; convergence of the write path is moot
		}
		planEntries, _ := buildVaultPlanEntries(srv.URL, m.mount, entries)
		if len(planEntries) == 0 {
			return
		}

		// name -> set of candidate winner values (any entry mapping to that derived name).
		nameVals := map[string]map[string]bool{}
		liveVals := map[string]bool{}
		for _, e := range planEntries {
			if nameVals[e.Name] == nil {
				nameVals[e.Name] = map[string]bool{}
			}
			nameVals[e.Name][e.Value] = true
			liveVals[e.Value] = true
		}

		// Golden: a clean import. Its set of names is the convergence target.
		golden := newFakeStore()
		applyImport(ctx, golden, planEntries, false)
		goldenNames := namesOf(golden)

		// Faulted run: decode a per-write fault schedule, import under it, then retry cleanly.
		store := newFakeStore()
		sched := decodeFaults(r, 4*len(planEntries)+4)
		store.faults = sched
		applyImport(ctx, store, planEntries, false) // run 1: faults active
		store.faults = nil                          // operator retry: clean
		applyImport(ctx, store, planEntries, false) // run 2
		snap2 := store.snapshot()

		// O-PF1: no lost / extra names.
		got := namesOf(store)
		if !sameStringSet(got, goldenNames) {
			t.Fatalf("O-PF1 NO-LOST-NAMES: after retry names=%v, clean import names=%v\nfaults=%v", sortedKeys(got), sortedKeys(goldenNames), sched)
		}

		// O-PF2 / O-PF3.
		seen := map[string]bool{}
		for name, sec := range snap2 {
			if cand := nameVals[name]; cand == nil || !cand[sec.value] {
				t.Fatalf("O-PF2 VALID-WINNER: secret %q has value %q which is not a planted value for that name", name, sec.value)
			}
			if !liveVals[sec.value] {
				t.Fatalf("O-PF2: secret %q value %q is not a planted live value (resurrected/garbage)", name, sec.value)
			}
			if seen[sec.value] {
				t.Fatalf("O-PF3 NO-DUPLICATES: value %q present in more than one secret", sec.value)
			}
			seen[sec.value] = true
		}

		// O-PF4: a further clean run is a fixed point.
		applyImport(ctx, store, planEntries, false) // run 3
		snap3 := store.snapshot()
		if !sameSnapshot(snap2, snap3) {
			t.Fatalf("O-PF4 FIXED-POINT: a clean re-run changed the target\nbefore=%v\nafter=%v", snap2, snap3)
		}

		runtime.ReadMemStats(&m1)
		if d := m1.TotalAlloc - m0.TotalAlloc; d > 256<<20 {
			t.Fatalf("resource: convergence run allocated %d bytes (> 256 MiB ceiling)", d)
		}
	})
}

// applyImport builds and applies a plan for entries into store (one import run).
func applyImport(ctx context.Context, store *fakeStore, entries []plan.Entry, force bool) {
	items, err := plan.BuildPlan(ctx, store, entries)
	if err != nil {
		return
	}
	plan.Apply(ctx, store, items, force)
}

// decodeFaults reads up to n fault modes from the reader, weighted toward OK so some writes
// succeed. faultsDump records them for diagnostics.
func decodeFaults(r *reader, n int) []faultMode {
	out := make([]faultMode, 0, n)
	for range n {
		switch r.intn(4) {
		case 0:
			out = append(out, faultBefore)
		case 1:
			out = append(out, faultAfter)
		default:
			out = append(out, faultOK)
		}
	}
	return out
}

func namesOf(s *fakeStore) map[string]bool {
	out := map[string]bool{}
	for name := range s.snapshot() {
		out[name] = true
	}
	return out
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sameSnapshot(a, b map[string]storedSecret) bool {
	if len(a) != len(b) {
		return false
	}
	for name, sa := range a {
		sb, ok := b[name]
		if !ok || sa.value != sb.value {
			return false
		}
	}
	return true
}
