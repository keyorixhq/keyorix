package core

// resguard_resetsoundness_test.go — RSG2 Pilot #3 (stateful PG).
//
// FuzzCoreOperationSequence reuses ONE per-worker world and resets it between
// inputs with the hand-named coreSeqResetTables (fuzzworld.World.Reset). The
// whole model-based oracle is only sound if that reset is COMPLETE: a table the
// fuzzer dirties but the reset list forgets accumulates rows across inputs, so a
// later input is judged against state an earlier input left behind — the "stateful
// fuzzers decay/starve" failure RSG1 exists to attack. This test adopts
// fuzzworld.WorldDigest to prove reset-soundness against a REAL world (SQLite
// always, PostgreSQL when KEYORIX_TEST_PG_DSN is set):
//
//	seed fixtures -> baseline ROW digest -> run real core ops that dirty many
//	tables (create/grant/rotate) -> reset+reseed -> ROW digest == baseline.
//
// Rows, not sequences: PG TRUNCATE (without RESTART IDENTITY, as World.Reset uses)
// legitimately leaves sequences advanced across reseeds, so sequence last-values
// differ by design — but ROW counts are the decay-relevant signal (accumulating
// rows are what starve the fuzzer), and those must return to baseline.
//
// What this does NOT verify: it does not re-run FuzzCoreOperationSequence's authz/
// integrity oracles (those own their own test); it proves ONLY that the reset list
// fully restores every table the exercised ops touch. A table dirtied by an op
// kind this test does not exercise would be invisible to it — the op coverage here
// (create, grant, rotate, revoke) is the fuzzer's full write surface, stated so the
// coverage claim is checkable.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// seedResetSoundnessWorld reseeds w's fixtures exactly as FuzzCoreOperationSequence's
// newWorld does and returns a core + the project/env ids. It resets with the given
// resetTables first, so a caller can inject an INCOMPLETE list for the red proof.
func seedResetSoundnessWorld(t *testing.T, w *fuzzworld.World, resetTables []string) (*KeyorixCore, uint, uint) {
	t.Helper()
	const (
		adminRoleID  = 900
		readerRoleID = 901
		readPermID   = 900
		adminUserID  = 1
	)
	principals := []uint{2, 3, 4}
	if err := w.Reset(resetTables); err != nil {
		t.Fatalf("reset: %v", err)
	}
	db := w.DB
	ctx := context.Background()
	ls := store.NewLocalStorage(db)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "projA"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	mustCreate := func(v any) {
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}
	mustCreate(&models.Role{ID: adminRoleID, Name: "fuzz-admin", NameFolded: "fuzz-admin", BypassesPermissionChecks: true})
	mustCreate(&models.Role{ID: readerRoleID, Name: "fuzz-reader", NameFolded: "fuzz-reader"})
	mustCreate(&models.Permission{ID: readPermID, Name: "secrets.read", Resource: "secrets", Action: "read"})
	mustCreate(&models.RolePermission{RoleID: readerRoleID, PermissionID: readPermID})
	mkUser := func(id uint) {
		mustCreate(&models.User{
			ID: id, Username: fmt.Sprintf("u%d", id), UsernameFolded: fmt.Sprintf("u%d", id),
			Email: fmt.Sprintf("u%d@x.io", id), EmailFolded: fmt.Sprintf("u%d@x.io", id), IsActive: true,
		})
	}
	mkUser(adminUserID)
	mustCreate(&models.UserRole{UserID: adminUserID, RoleID: adminRoleID})
	for _, p := range principals {
		mkUser(p)
	}
	return NewKeyorixCore(ls), proj.ID, env.ID
}

// dirtyCoreOps runs real create/grant/rotate/revoke operations, writing rows into
// secret_nodes, secret_versions, user_roles (and whatever those cascade to) — the
// fuzzer's full write surface.
func dirtyCoreOps(t *testing.T, c *KeyorixCore, projID, envID uint) {
	t.Helper()
	ctx := context.Background()
	const readerRoleID = 901
	scope := Scope{ProjectID: projID}
	var ids []uint
	for i := range 5 {
		s, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: fmt.Sprintf("s%d", i), Value: []byte{byte(i), 0x11}, ProjectID: projID, EnvironmentID: envID,
			Type: "password", CreatedBy: "fuzz-admin", OwnerID: 1,
		})
		if err != nil || s == nil {
			t.Fatalf("create secret %d: %v", i, err)
		}
		ids = append(ids, s.ID)
	}
	for _, u := range []uint{2, 3, 4} {
		if err := c.AssignUserRole(ctx, 0, u, readerRoleID, scope, false); err != nil {
			t.Fatalf("grant %d: %v", u, err)
		}
	}
	for i, sid := range ids {
		if _, err := c.RotateSecret(ctx, sid, []byte{0xAA, byte(i), byte(i), 0x22, 0x33}, 1, "fuzz-admin"); err != nil {
			t.Fatalf("rotate %d: %v", sid, err)
		}
	}
	// revoke one, to exercise the delete path too
	if err := c.RemoveUserRole(ctx, 0, 2, readerRoleID, scope); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// rowsEqual compares only the row counts of two digests (ignoring sequences, which
// PG TRUNCATE legitimately advances), returning a sorted human diff on mismatch.
func rowsEqual(a, b fuzzworld.WorldDigest) (bool, string) {
	var diffs []string
	for k, av := range a.Rows {
		if bv, ok := b.Rows[k]; !ok || av != bv {
			diffs = append(diffs, fmt.Sprintf("%s: %d->%d", k, av, bv))
		}
	}
	for k := range b.Rows {
		if _, ok := a.Rows[k]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: missing->%d", k, b.Rows[k]))
		}
	}
	sort.Strings(diffs)
	return len(diffs) == 0, strings.Join(diffs, "; ")
}

func TestResguardCoreSeqResetSoundness(t *testing.T) {
	worlds := fuzzworld.Worlds(t, "rsg2coreseq", ":memory:", 1)
	for _, w := range worlds {
		t.Run(w.Backend, func(t *testing.T) {
			// GREEN: the real reset list fully restores the world's rows.
			c, projID, envID := seedResetSoundnessWorld(t, w, coreSeqResetTables)
			live, err := fuzzworld.LiveTables(w)
			if err != nil {
				t.Fatalf("live tables: %v", err)
			}
			baseline, err := fuzzworld.Digest(w, live)
			if err != nil {
				t.Fatalf("baseline digest: %v", err)
			}

			dirtyCoreOps(t, c, projID, envID)
			dirty, err := fuzzworld.Digest(w, live)
			if err != nil {
				t.Fatalf("dirty digest: %v", err)
			}
			if ok, _ := rowsEqual(baseline, dirty); ok {
				t.Fatalf("precondition: the core ops must DIRTY the world (rows unchanged means the test exercised nothing)")
			}

			// reset+reseed with the real list, then rows must match baseline.
			c2, _, _ := seedResetSoundnessWorld(t, w, coreSeqResetTables)
			_ = c2
			after, err := fuzzworld.Digest(w, live)
			if err != nil {
				t.Fatalf("after-reset digest: %v", err)
			}
			if ok, diff := rowsEqual(baseline, after); !ok {
				t.Fatalf("RESET UNSOUND: coreSeqResetTables did not restore the world; row diff baseline->after: %s", diff)
			}

			// RED: an INCOMPLETE reset list must leave residue, so we know the GREEN
			// check above can actually fail — a guard nobody has watched fail is not a
			// guard. "projects" is dropped specifically because it is a ROOT parent:
			// PG TRUNCATE ... CASCADE propagates to CHILDREN, never up to a parent,
			// so (unlike secret_versions, which CASCADE from secret_nodes/environments
			// would rescue) a reset list that omits projects genuinely leaves the old
			// project row behind on BOTH backends. A full reset clears it; the
			// incomplete one does not — that gap is the forgotten-table decay.
			incomplete := without(coreSeqResetTables, "projects")

			c3, pid3, eid3 := seedResetSoundnessWorld(t, w, coreSeqResetTables)
			dirtyCoreOps(t, c3, pid3, eid3)
			if err := w.Reset(coreSeqResetTables); err != nil { // full reset
				t.Fatalf("full reset: %v", err)
			}
			full, err := fuzzworld.Digest(w, []string{"projects"})
			if err != nil {
				t.Fatalf("full-reset digest: %v", err)
			}
			if full.Rows["projects"] != 0 {
				t.Fatalf("SOUND reset should clear projects, got %d rows", full.Rows["projects"])
			}

			c4, pid4, eid4 := seedResetSoundnessWorld(t, w, coreSeqResetTables)
			dirtyCoreOps(t, c4, pid4, eid4)
			if err := w.Reset(incomplete); err != nil { // incomplete reset
				t.Fatalf("incomplete reset: %v", err)
			}
			red, err := fuzzworld.Digest(w, []string{"projects"})
			if err != nil {
				t.Fatalf("incomplete-reset digest: %v", err)
			}
			if red.Rows["projects"] == 0 {
				t.Fatalf("RED proof failed: dropping projects from the reset list must leave residual project rows, got 0")
			}
			t.Logf("reset-soundness GREEN (rows restored); RED: full reset clears projects (0), incomplete leaves %d — oracle fires on %s",
				red.Rows["projects"], w.Backend)
		})
	}
}

func without(xs []string, drop string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}
