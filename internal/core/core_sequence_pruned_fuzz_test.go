package core

// FuzzCoreOperationSequencePruned is a copy of FuzzCoreOperationSequence with
// one milestone-predicate pruning checkpoint added to the READ operation (op=3):
//
//	CP-1: if canRead[u]=true (the user is authorised in the shadow model),
//	      return from the step closure immediately without executing the read.
//
// Rationale: the FAIL-CLOSED oracle only fires when canRead[u]=false AND the
// real call returns non-error (i.e. an over-allow). Authorised reads (canRead=true)
// cannot trigger that oracle direction; a mutation that causes over-denial is
// invisible to FAIL-CLOSED. Skipping those reads focuses the fuzzer's budget on
// reads that ARE oracle-visible for the RBAC-bypass mutation class.
//
// The safety-net read at the end of every iteration (step(3,0,0)) goes through
// the same pruned step, so it is also skipped when canRead[principals[0]]=true —
// but that is fine: when canRead[2]=true the safety net cannot detect an
// over-allow anyway.
//
// This file is an experiment artifact on branch fuzz/sg2g3-milestone-pruning-experiment
// and is NOT intended for merge.

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

func FuzzCoreOperationSequencePruned(f *testing.F) {
	const (
		adminRoleID  = 900
		readerRoleID = 901
		readPermID   = 900
		adminUserID  = 1
	)
	principals := []uint{2, 3, 4}

	newWorld := func(t *testing.T, w *fuzzworld.World) (*KeyorixCore, *store.LocalStorage, uint, uint) {
		t.Helper()
		if err := w.Reset(coreSeqResetTables); err != nil {
			t.Fatalf("reset: %v", err)
		}
		db := w.DB
		ls := store.NewLocalStorage(db)
		ctx := context.Background()

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

		c := NewKeyorixCore(ls)
		return c, ls, proj.ID, env.ID
	}

	createSecret := func(t *testing.T, c *KeyorixCore, projID, envID uint, name string, val []byte) (uint, bool) {
		t.Helper()
		s, err := c.CreateSecret(context.Background(), &CreateSecretRequest{
			Name: name, Value: val, ProjectID: projID, EnvironmentID: envID,
			Type: "password", CreatedBy: "fuzz-admin", OwnerID: adminUserID,
		})
		if err != nil || s == nil {
			return 0, false
		}
		return s.ID, true
	}

	worlds := fuzzworld.Worlds(f, "coreseqpruned", ":memory:", 1)

	// Same seeds as FuzzCoreOperationSequence — fair comparison requires identical input distribution.
	f.Add([]byte{0xFF, 0, 0, 1, 0, 3, 0, 2, 0, 3, 0})
	f.Add([]byte{0xFF, 0, 1, 3, 1, 1, 1, 3, 4, 2, 1, 3, 4})
	f.Add([]byte{0xFF, 0, 0, 4, 0, 9, 3, 0, 0, 1, 2, 3, 2})
	f.Add([]byte{})
	f.Add([]byte{0b10010, 1, 0, 0, 4, 1, 2, 1})
	f.Add([]byte{0b01100, 2, 0, 0, 3, 1, 2, 1})

	f.Fuzz(func(t *testing.T, program []byte) {
		for _, w := range worlds {
			runCoreSeqPrunedIteration(t, w, program, newWorld, createSecret, principals, adminRoleID, readerRoleID, adminUserID)
		}
	})
}

// runCoreSeqPrunedIteration is runCoreSeqIteration with one pruning checkpoint:
// READ ops where canRead[u]=true are skipped (they cannot fire the FAIL-CLOSED
// oracle for the RBAC-bypass mutation class).
func runCoreSeqPrunedIteration(
	t *testing.T, w *fuzzworld.World, program []byte,
	newWorld func(*testing.T, *fuzzworld.World) (*KeyorixCore, *store.LocalStorage, uint, uint),
	createSecret func(*testing.T, *KeyorixCore, uint, uint, string, []byte) (uint, bool),
	principals []uint, adminRoleID, readerRoleID, adminUserID uint,
) {
	t.Helper()
	c, _, projID, envID := newWorld(t, w)
	ctx := context.Background()
	scope := Scope{ProjectID: projID}

	subsetByte := byte(0xFF)
	body := program
	if len(program) > 0 {
		subsetByte = program[0]
		body = program[1:]
	}
	subset := decodeOpSubset(subsetByte)

	canRead := map[uint]bool{}
	value := map[uint][]byte{}
	var secretIDs []uint
	secretSeq, rotateSeq := 0, 0

	assertAdminValue := func(sid uint, want []byte) {
		var got []byte
		var aerr error
		fuzzutil.Guard(t.Fatalf, "admin GetSecretValueWithPermissionCheck", func() {
			got, aerr = c.GetSecretValueWithPermissionCheck(ctx, sid, adminUserID)
		})
		if aerr != nil {
			t.Fatalf("DATA LOSS/AVAILABILITY: admin cannot read secret %d after a successful mutation: %v", sid, aerr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("DATA CORRUPTION: secret %d admin-read=%q want=%q", sid, got, want)
		}
	}

	step := func(op, a, b byte) {
		switch op {
		case 0:
			secretSeq++
			val := []byte{a, b}
			if id, ok := createSecret(t, c, projID, envID, fmt.Sprintf("s%d", secretSeq), val); ok {
				secretIDs = append(secretIDs, id)
				value[id] = val
				assertAdminValue(id, val)
			}
		case 1:
			u := principals[int(a)%len(principals)]
			if err := c.AssignUserRole(ctx, 0, u, readerRoleID, scope, false); err == nil {
				canRead[u] = true
			}
		case 2:
			u := principals[int(a)%len(principals)]
			if err := c.RemoveUserRole(ctx, 0, u, readerRoleID, scope); err == nil {
				canRead[u] = false
			}
		case 3:
			if len(secretIDs) == 0 {
				return
			}
			u := principals[int(a)%len(principals)]
			// CP-1: milestone predicate pruning — skip authorised reads.
			// canRead[u]=true means the oracle's FAIL-CLOSED check cannot fire for this
			// read: the oracle only asserts "must deny when canRead=false"; an authorised
			// read that succeeds or fails says nothing about an over-allow mutation.
			// Returning here (from the step closure) leaves the safety-net call at the
			// end of the iteration intact — it uses principals[0] with canRead[2] checked
			// at that point, so it fires for all programs where canRead[2] is still false.
			if canRead[u] {
				return
			}
			sid := secretIDs[int(b)%len(secretIDs)]
			var got []byte
			var rerr error
			fuzzutil.Guard(t.Fatalf, "GetSecretValueWithPermissionCheck", func() {
				got, rerr = c.GetSecretValueWithPermissionCheck(ctx, sid, u)
			})
			if !canRead[u] {
				if rerr == nil {
					t.Fatalf("AUTHZ BYPASS: principal %d read secret %d plaintext with no read grant (canRead=false): %q", u, sid, got)
				}
			} else if rerr == nil {
				if !bytes.Equal(got, value[sid]) {
					t.Fatalf("INTEGRITY: principal %d read secret %d got=%q want=%q", u, sid, got, value[sid])
				}
			}
			if rerr != nil && got != nil {
				t.Fatalf("result-shape: denied read returned non-nil plaintext (id=%d principal=%d): %q", sid, u, got)
			}
		case 4:
			if len(secretIDs) == 0 {
				return
			}
			sid := secretIDs[int(a)%len(secretIDs)]
			rotateSeq++
			newVal := []byte{0xAA, byte(rotateSeq >> 8), byte(rotateSeq), a, b}
			var rerr error
			fuzzutil.Guard(t.Fatalf, "RotateSecret", func() {
				_, rerr = c.RotateSecret(ctx, sid, newVal, adminUserID, "fuzz-admin")
			})
			if rerr == nil {
				value[sid] = newVal
				assertAdminValue(sid, newVal)
			}
		}
	}

	dispatch := func(op, a, b byte) {
		step(byte(subset[int(op)%len(subset)]), a, b)
	}

	const maxSteps = 32
	steps := 0
	for i := 0; i+2 < len(body) && steps < maxSteps; i += 3 {
		dispatch(body[i], body[i+1], body[i+2])
		steps++
	}
	if len(secretIDs) == 0 {
		if id, ok := createSecret(t, c, projID, envID, "s-seed", []byte("v")); ok {
			secretIDs = append(secretIDs, id)
			value[id] = []byte("v")
		}
	}
	if len(secretIDs) > 0 {
		step(3, 0, 0) // outsider read — must be denied; CP-1 fires when canRead[2]=true
	}
}
