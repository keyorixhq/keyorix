package cmd

// FuzzVaultImportRoundTrip — the MGV1 round-trip + hostile-input oracle for the migrate
// tool's Vault importer (vaultsource.Walk -> buildVaultPlanEntries/sanitizeSecretName ->
// plan.BuildPlan -> plan.Apply -> target). It generates a Vault KV v1/v2 export shape,
// serves it over a faithful httptest Vault, runs the REAL import pipeline into an in-memory
// "Keyorix", reads the result back ("Keyorix export"), and asserts a conservation oracle plus
// hostile-safety — WITHOUT mirroring the implementation's name/field branching (it checks
// counts and value-set membership, which a re-implementation of the rules could not fake).
//
// Oracles (what each does NOT verify is stated in .scratch/mgv1-REPORT.md):
//   - O-RT1 WALK-CONSERVATION: len(entries) == #(live, non-empty-key, non-empty-value fields,
//     last-wins-deduped). Catches any secret Walk silently drops or duplicates at the parse
//     layer, including duplicate-JSON-key handling.
//   - O-RT2 PIPELINE-CONSERVATION: liveImportableCount == len(target) + failedCreates +
//     buildSkips. Nothing silently vanishes between Walk and the target; nothing is invented.
//   - O-RT3 VALUE-MEMBERSHIP: every target value was a planted live value (no invention, no
//     resurrection of a soft-deleted/destroyed secret); target values are distinct (no dup).
//   - O-RT4 NAMESPACE-SAFETY: every target secret name carries no '/','\\', NUL, or control
//     char and is non-empty — a hostile Vault key can never escape the target namespace.
//   - O-RT5 VERSION/METADATA-FIDELITY: each created secret records the source version,
//     created-time and custom_metadata of its leaf (or omits version/created-time for KV v1).
//   - O-RT6 REPORTED-NOT-DROPPED: every soft-deleted/destroyed/empty leaf appears in Walk's
//     Skipped set — reported, never silently absent.
//   - O-RT7 NO-LEAK: the secret-value canary never appears in a Walk error, a Skipped.Reason,
//     a build-skip reason, an Apply error, or captured slog output.
//   - O1/O2/O4 (panic/hang/memory) via the shared hostile.Harness.Run around Walk.
//
// Resource meters (shared helper hostile.Harness.Run): network (httptest Vault), O1 panic,
// O2 hang (Walk deadline), O4 bounded-alloc (256 MiB ceiling), O7 leak scan of error+logs.
// O3 goroutine/FD-leak, O8 request-ceiling and O9 redirect oracles are vacuous here by
// construction (the metered call drives a SEPARATE in-process httptest Vault, not the
// harness's own server — transport-level safety of Walk is covered by
// FuzzVaultSourceHostileWalk); this is stated in the report.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/keyorixhq/keyorix/migrate/internal/hostile"
	"github.com/keyorixhq/keyorix/migrate/internal/plan"
	"github.com/keyorixhq/keyorix/migrate/internal/vaultsource"
)

func FuzzVaultImportRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Add([]byte{0x00, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80})
	f.Add([]byte{3, 7, 1, 9, 2, 8, 4, 6, 5, 0, 11, 13, 17, 19, 23, 29, 31})
	f.Add(bytesRange(64))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := &reader{b: data}
		m := genModel(r)

		srv := m.newVaultServer()
		defer srv.Close()

		// Shared resource helper: meter Walk (network call) for panic/hang/alloc/leak.
		h := hostile.New(hostile.Config{
			Credentials: []string{"kx-mgv1-token"},
			CallTimeout: 3 * time.Second, // a legal tree must walk well within it
		})
		defer h.Close()

		var entries []vaultsource.Entry
		var skipped []vaultsource.Skipped
		errWalk := h.Run("vaultsource.Walk", func(ctx context.Context) error {
			c, err := vaultsource.New(ctx, vaultsource.Config{Addr: srv.URL, Mount: m.mount, Token: "kx-mgv1-token"})
			if err != nil {
				return err
			}
			entries, skipped, err = c.Walk(ctx, "", false)
			return err
		})

		// O-RT7: no value canary in a Walk error or any skip reason.
		if errWalk != nil {
			h.CheckLeak("Walk", errWalk.Error())
			// A legal model should Walk cleanly; if it errored we cannot do conservation,
			// but a fail-closed non-nil error is acceptable — just verify no leak + no panic.
			assertNoCanary(t, "walk-error", errWalk.Error())
			surfaceHarnessViolations(t, h)
			return
		}
		for _, s := range skipped {
			assertNoCanary(t, "walk-skip-reason", s.Reason)
		}

		// Independent truth from the model.
		liveVals, valToLeaf, liveCount := modelLiveImportable(m)

		// O-RT1: Walk conservation.
		if len(entries) != liveCount {
			t.Fatalf("O-RT1 WALK-CONSERVATION: Walk returned %d entries, model has %d importable live fields\nmount=%q kv2=%v", len(entries), liveCount, m.mount, m.kv2)
		}

		// O-RT6: every soft-deleted/destroyed/empty leaf is reported in Skipped.
		// A soft-deleted/destroyed/empty-leaf skip always carries the plain leaf path as
		// Skipped.Path (empty-value/empty-field-name skips use a "path#field" form, which is
		// harmless noise in this set — we only test membership of a leaf path, never require
		// every skip to be a leaf). Matching the raw path avoids truncating a leaf path that
		// legitimately contains '#'.
		skipPaths := map[string]bool{}
		for _, s := range skipped {
			skipPaths[s.Path] = true
		}
		for i := range m.leaves {
			l := &m.leaves[i]
			if l.state == 1 || l.state == 2 || l.state == 3 {
				if !skipPaths[l.path()] {
					t.Fatalf("O-RT6 REPORTED-NOT-DROPPED: leaf %q (state %d) is not reported in Walk Skipped\nskipped=%v", l.path(), l.state, skipped)
				}
			}
		}

		// Import pipeline (the real code under test).
		planEntries, buildSkipped := buildVaultPlanEntries(srv.URL, m.mount, entries)
		for _, bs := range buildSkipped {
			assertNoCanary(t, "build-skip-reason", bs.Reason)
		}
		store := newFakeStore()
		ctx := context.Background()
		items, err := plan.BuildPlan(ctx, store, planEntries)
		if err != nil {
			t.Fatalf("BuildPlan returned a top-level error (must be per-item): %v", err)
		}
		results := plan.Apply(ctx, store, items, false)

		failedCreates := 0
		for _, res := range results {
			if res.Error != "" {
				failedCreates++
				assertNoCanary(t, "apply-error", res.Error)
			}
		}

		snap := store.snapshot()

		// O-RT2: pipeline conservation.
		if liveCount != len(snap)+failedCreates+len(buildSkipped) {
			t.Fatalf("O-RT2 PIPELINE-CONSERVATION: liveCount=%d but target=%d + failedCreates=%d + buildSkips=%d = %d\nmount=%q kv2=%v",
				liveCount, len(snap), failedCreates, len(buildSkipped), len(snap)+failedCreates+len(buildSkipped), m.mount, m.kv2)
		}

		// O-RT3/4/5.
		seenVal := map[string]bool{}
		for name, sec := range snap {
			// O-RT4 namespace safety.
			if name == "" {
				t.Fatalf("O-RT4 NAMESPACE: empty target secret name")
			}
			for _, rn := range name {
				if rn == '/' || rn == '\\' || rn == 0 || unicode.IsControl(rn) {
					t.Fatalf("O-RT4 NAMESPACE: target name %q contains forbidden rune %q", name, rn)
				}
			}
			// O-RT3 membership + no-dup.
			if !liveVals[sec.value] {
				t.Fatalf("O-RT3 VALUE-MEMBERSHIP: target secret %q holds value not in the live import set (invented or resurrected): %q", name, sec.value)
			}
			if seenVal[sec.value] {
				t.Fatalf("O-RT3 VALUE-MEMBERSHIP: value %q imported into more than one target secret (duplicate)", sec.value)
			}
			seenVal[sec.value] = true
			// O-RT5 version/metadata fidelity.
			l := valToLeaf[sec.value]
			if sec.meta["migrate.source"] != "vault" {
				t.Fatalf("O-RT5: secret %q missing migrate.source=vault, got %q", name, sec.meta["migrate.source"])
			}
			if sec.meta["migrate.source-id"] == "" {
				t.Fatalf("O-RT5: secret %q missing migrate.source-id", name)
			}
			if m.kv2 {
				if got := sec.meta["migrate.source-version"]; got != strconv.Itoa(l.version) {
					t.Fatalf("O-RT5 VERSION: secret %q version metadata = %q, want %q", name, got, strconv.Itoa(l.version))
				}
				if got := sec.meta["migrate.source-created-at"]; got != l.created {
					t.Fatalf("O-RT5: secret %q created-at = %q, want %q", name, got, l.created)
				}
				for ck, cv := range l.custom {
					if got := sec.meta["vault."+ck]; got != cv {
						t.Fatalf("O-RT5 CUSTOM-META: secret %q meta[vault.%s] = %q, want %q", name, ck, got, cv)
					}
				}
			} else {
				if _, ok := sec.meta["migrate.source-version"]; ok {
					t.Fatalf("O-RT5: KV v1 secret %q unexpectedly carries source-version", name)
				}
			}
		}

		// O-RT7: no canary in captured logs.
		if strings.Contains(h.Logs(), hostile.Canary) {
			t.Fatalf("O-RT7 NO-LEAK: captured slog output contains the value canary")
		}
		surfaceHarnessViolations(t, h)
	})
}

// surfaceHarnessViolations fails the test on any O2/O4/O7 violation recorded by
// hostile.Harness.Run. Harness.Finish is deliberately not used (see this file's header): the
// metered call drives a separate in-process Vault, so Finish's O3/O8/O9 aggregate is vacuous
// (O8/O9) or cross-server-false-positive-prone (O3); Run's own meters are the load-bearing
// ones and are surfaced here instead.
func surfaceHarnessViolations(t *testing.T, h *hostile.Harness) {
	t.Helper()
	if v := h.Violations(); len(v) > 0 {
		t.Fatalf("hostile.Harness oracle violation(s): %s", strings.Join(v, "; "))
	}
}

// modelLiveImportable computes, independently of the code under test, the set of values that
// MUST be imported (live leaves; non-empty key; non-empty value; duplicate keys collapsed
// last-wins exactly as encoding/json does), a value->leaf map, and the count.
func modelLiveImportable(m *vModel) (vals map[string]bool, toLeaf map[string]*vLeaf, count int) {
	vals = map[string]bool{}
	toLeaf = map[string]*vLeaf{}
	for i := range m.leaves {
		l := &m.leaves[i]
		if l.state != 0 {
			continue
		}
		dedup := map[string]string{}
		order := []string{}
		for _, fdef := range l.fields {
			if _, seen := dedup[fdef.key]; !seen {
				order = append(order, fdef.key)
			}
			dedup[fdef.key] = fdef.val // last-wins
		}
		for _, k := range order {
			v := dedup[k]
			if k == "" || v == "" {
				continue
			}
			vals[v] = true
			toLeaf[v] = l
			count++
		}
	}
	return vals, toLeaf, count
}

func assertNoCanary(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, hostile.Canary) {
		t.Fatalf("O-RT7 NO-LEAK: value canary leaked into %s: %q", where, text)
	}
}

func bytesRange(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}
