package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/fuzzworld"
)

// FuzzSecretLifecycleModel is an op-sequence fuzzer over the secret VERSION
// HISTORY and LIFECYCLE state machine: create / update / rotate / rollback /
// soft-delete / restore / retention purge, on three named slots, against a
// per-slot model that is the oracle (state + the ordered list of plaintext
// versions). After EVERY op, for every slot, the real store must agree with the
// model on: whether the secret is live / soft-deleted / gone, how many versions
// exist and their numbers (1..n, gap-free), the plaintext of EVERY version
// (decrypted through the real path), that the latest read is the last version,
// that a soft-deleted secret serves no value yet keeps its ciphertext rows (so
// restore brings back the whole history), and that a purged secret leaves no
// node, version or ACL row behind.
//
// Rules the model states (the oracle, not a copy of the code):
//
//   - create makes version 1; update-with-value, rotate and rollback each APPEND
//     exactly one version (history is append-only; a rollback re-instates the
//     target's value as a NEW version, and rolling back to the current latest
//     or to a version that does not exist is refused and changes nothing);
//   - an update WITHOUT a value (metadata only) appends nothing;
//   - update / rotate / rollback / delete of a soft-deleted or purged secret is
//     refused and changes nothing; restore of a live secret is refused;
//   - restore returns the secret with its full history; purge removes only
//     soft-deleted secrets that are past their purge date.
//
// Time: the store stamps soft-deletes with the real wall clock, so "past the
// purge date" is made controllable by an explicit op (expire) that rewrites the
// deleted_at / purge_at of ONE soft-deleted secret into the past relative to a
// reference taken at the start of the program; the purge sweep's cutoff sits
// between the two. A not-expired soft-deleted secret must survive any number of
// sweeps.
//
// Program encoding (op numbers are corpus encoding: APPEND ONLY, never renumber).
// Bytes are (op, arg) pairs, at most secretLifecycleMaxOps of them; slot =
// arg%3, x = arg/3:
//
//	0 create        (only for a slot that is empty or purged)
//	1 update value
//	2 rotate
//	3 rollback to version 1+x%(n+1)  (n+1 does not exist: refused)
//	4 soft-delete
//	5 restore
//	6 expire        (a soft-deleted secret becomes purge-eligible)
//	7 purge sweep   (PurgeExpiredSoftDeletes)
//	8 read          (latest + version 1+x%n)
//	9 check         (invariants only)
//	10 update metadata only (no value)
//
// No bcrypt / KDF: values are short strings and the AEAD key is the fixture's.
// Per-program cost is bounded by the op cap and secretLifecycleMaxVersions.
//
// Not covered: authorization (see FuzzCoreOperationSequence), per-secret
// retention overrides, max-reads / expiry guards, project / environment
// cascades, dependency edges, concurrent callers, Postgres.
func FuzzSecretLifecycleModel(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 2, 0, 3, 0, 9, 0})                         // create, update, rotate, rollback
	f.Add([]byte{0, 0, 1, 0, 4, 0, 5, 0, 9, 0})                         // delete then restore keeps history
	f.Add([]byte{0, 0, 1, 0, 4, 3, 7, 0, 6, 0, 7, 0, 9, 0})             // delete, expire, purge
	f.Add([]byte{0, 0, 4, 0, 7, 0, 6, 0, 7, 0, 0, 0, 1, 0, 9, 0})       // purge not-expired survives, then recreate
	f.Add([]byte{0, 0, 3, 0, 3, 3, 1, 0, 3, 0, 3, 0})                   // rollback to current / nonexistent / chain
	f.Add([]byte{0, 0, 10, 0, 10, 0, 9, 0})                             // metadata-only update appends nothing
	f.Add([]byte{0, 0, 1, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0, 9, 0})       // mutations on a deleted secret refused
	f.Add([]byte{0, 0, 0, 1, 0, 2, 4, 1, 6, 1, 7, 0, 5, 1, 5, 0, 9, 0}) // multi-slot, restore of purged / live

	// One SQLite world for the process (opening + migrating per input dominates
	// otherwise); Reset empties it per input. SQLite only: no Docker, no PG.
	world := &fuzzworld.World{Backend: fuzzworld.BackendSQLite, DB: fuzzworld.OpenSQLite(f, ":memory:", 1)}
	fuzzworld.Bootstrap(f, world.DB)

	f.Fuzz(func(t *testing.T, prog []byte) {
		secretLifecycleProgram(t, world, prog)
	})
}

const (
	secretLifecycleMaxOps      = 48
	secretLifecycleMaxVersions = 12
	secretLifecycleSlots       = 3
)

type slotState int

const (
	slotNone slotState = iota
	slotLive
	slotDeleted
	slotPurged
)

func (s slotState) String() string { return [...]string{"none", "live", "deleted", "purged"}[s] }

type lifecycleSlot struct {
	state    slotState
	id       uint
	versions []string // plaintext per version, index 0 = version 1
	expired  bool     // soft-deleted and past its purge date
}

func secretLifecycleProgram(t *testing.T, w *fuzzworld.World, prog []byte) {
	t.Helper()
	ctx := context.Background()
	if err := w.Reset(coreSeqResetTables); err != nil {
		t.Fatalf("reset: %v", err)
	}
	db := w.DB
	ls := store.NewLocalStorage(db)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "projA"})
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("create env: %v", err)
	}
	if err := db.Create(&models.User{ID: 1, Username: "u1", UsernameFolded: "u1", Email: "u1@x.io", EmailFolded: "u1@x.io", IsActive: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	c := NewKeyorixCore(ls)

	// Reference instant for the controllable purge dates. Only used as a base
	// for offsets (the store stamps real time); nothing is formatted or parsed.
	ref := time.Now().UTC()
	pastDeleted, pastPurge, sweepBefore := ref.Add(-48*time.Hour), ref.Add(-24*time.Hour), ref.Add(-12*time.Hour)

	var slots [secretLifecycleSlots]lifecycleSlot
	counter := 0
	val := func() string { counter++; return fmt.Sprintf("value-%d-padpadpad", counter) }
	name := func(i int) string { return fmt.Sprintf("secret-%d", i) }

	count := func(table, col string, id uint) int64 {
		var n int64
		if err := db.Raw("SELECT COUNT(*) FROM "+table+" WHERE "+col+" = ?", id).Scan(&n).Error; err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table/col are hardcoded literals at every call site below
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}

	check := func(step int, what string) {
		t.Helper()
		for i := range slots {
			s := &slots[i]
			tag := fmt.Sprintf("step %d (%s) slot %d state=%s", step, what, i, s.state)
			switch s.state {
			case slotLive:
				if _, err := ls.GetSecret(ctx, s.id); err != nil {
					t.Fatalf("%s: live secret not readable: %v", tag, err)
				}
				vs, err := c.GetSecretVersions(ctx, s.id)
				if err != nil {
					t.Fatalf("%s: list versions: %v", tag, err)
				}
				if len(vs) != len(s.versions) {
					t.Fatalf("%s: %d versions stored, model has %d", tag, len(vs), len(s.versions))
				}
				seen := map[int]bool{}
				for _, v := range vs {
					seen[v.VersionNumber] = true
				}
				for n := 1; n <= len(s.versions); n++ {
					if !seen[n] {
						t.Fatalf("%s: version numbers not 1..%d (missing %d)", tag, len(s.versions), n)
					}
					got, err := c.GetSecretValueByVersion(ctx, s.id, n)
					if err != nil {
						t.Fatalf("%s: read version %d: %v", tag, n, err)
					}
					if string(got) != s.versions[n-1] {
						t.Fatalf("%s: version %d plaintext %q, model %q", tag, n, got, s.versions[n-1])
					}
				}
				latest, err := c.GetSecretValue(ctx, s.id)
				if err != nil || string(latest) != s.versions[len(s.versions)-1] {
					t.Fatalf("%s: latest value %q (err %v), model %q", tag, latest, err, s.versions[len(s.versions)-1])
				}
			case slotDeleted:
				if _, err := ls.GetSecret(ctx, s.id); err == nil {
					t.Fatalf("%s: soft-deleted secret is still returned by GetSecret", tag)
				}
				got, err := ls.GetSecretIncludingDeleted(ctx, s.id)
				if err != nil || !got.DeletedAt.Valid {
					t.Fatalf("%s: soft-deleted row missing or not flagged deleted (err %v)", tag, err)
				}
				if v, err := c.GetSecretValue(ctx, s.id); err == nil {
					t.Fatalf("%s: SOFT-DELETED SECRET SERVED A VALUE (%d bytes)", tag, len(v))
				}
				if n := count("secret_versions", "secret_node_id", s.id); n != int64(len(s.versions)) {
					t.Fatalf("%s: %d version rows kept, model %d (history must survive a soft delete)", tag, n, len(s.versions))
				}
			case slotNone, slotPurged:
				if s.id == 0 {
					continue
				}
				if n := count("secret_nodes", "id", s.id); n != 0 {
					t.Fatalf("%s: purged secret's node row still present", tag)
				}
				if n := count("secret_versions", "secret_node_id", s.id); n != 0 {
					t.Fatalf("%s: PURGED SECRET'S CIPHERTEXT VERSIONS STILL PRESENT (%d rows)", tag, n)
				}
				if n := count("secret_acls", "secret_id", s.id); n != 0 {
					t.Fatalf("%s: purged secret's ACL rows still present", tag)
				}
			}
		}
	}

	for i := 0; i+1 < len(prog) && i/2 < secretLifecycleMaxOps; i += 2 {
		op, arg := prog[i]%11, int(prog[i+1])
		si, x := arg%secretLifecycleSlots, arg/secretLifecycleSlots
		s := &slots[si]
		step := i / 2
		what := fmt.Sprintf("op %d slot %d x %d", op, si, x)
		n := len(s.versions)
		switch op {
		case 0:
			if s.state != slotNone && s.state != slotPurged {
				break
			}
			v := val()
			created, err := c.CreateSecret(ctx, &CreateSecretRequest{
				Name: name(si), Value: []byte(v), ProjectID: proj.ID, EnvironmentID: env.ID,
				Type: "password", CreatedBy: "fuzz", OwnerID: 1,
			})
			if err != nil || created == nil {
				t.Fatalf("step %d: create on an empty slot failed: %v", step, err)
			}
			*s = lifecycleSlot{state: slotLive, id: created.ID, versions: []string{v}}
		case 1, 2, 3, 10:
			live := s.state == slotLive && n < secretLifecycleMaxVersions
			if s.state == slotLive && !live {
				break // version cap reached: not exercised, not asserted
			}
			var err error
			var appended string
			switch op {
			case 1:
				appended = val()
				_, err = c.UpdateSecret(ctx, &UpdateSecretRequest{ID: s.id, Value: []byte(appended), UpdatedBy: "fuzz", UserID: 1})
			case 2:
				appended = val()
				_, err = c.RotateSecret(ctx, s.id, []byte(appended), 1, "fuzz")
			case 3:
				target := 1 + x%(n+1)
				if s.state == slotLive {
					wantErr := target > n || target == n
					_, err = c.RollbackSecret(ctx, s.id, target, 1, "fuzz")
					if wantErr {
						if err == nil {
							t.Fatalf("step %d: rollback to %d of %d versions was accepted, want refusal", step, target, n)
						}
						goto done
					}
					appended = s.versions[target-1]
				} else {
					_, err = c.RollbackSecret(ctx, s.id, 1, 1, "fuzz")
				}
			case 10:
				d := "metadata only"
				_, err = c.UpdateSecret(ctx, &UpdateSecretRequest{ID: s.id, Description: &d, UpdatedBy: "fuzz", UserID: 1})
			}
			if s.state != slotLive {
				if s.id != 0 && err == nil {
					t.Fatalf("step %d (%s): mutation of a %s secret was accepted", step, what, s.state)
				}
				break
			}
			if err != nil {
				t.Fatalf("step %d (%s): refused on a live secret: %v", step, what, err)
			}
			if op != 10 {
				s.versions = append(s.versions, appended)
			}
		case 4:
			err := c.DeleteSecret(ctx, s.id)
			switch s.state {
			case slotLive:
				if err != nil {
					t.Fatalf("step %d: delete of a live secret refused: %v", step, err)
				}
				s.state = slotDeleted
				// A store that knows the retention window freezes purge_at at delete
				// time; this one may not (legacy rule on deleted_at). Odd x emulates
				// the frozen form with a date well in the future, so both purge
				// predicates are exercised against a not-yet-expired secret.
				if x%2 == 1 {
					if err := db.Exec("UPDATE secret_nodes SET purge_at = ? WHERE id = ?", ref.Add(30*24*time.Hour), s.id).Error; err != nil {
						t.Fatalf("step %d: freeze purge_at: %v", step, err)
					}
				}
			default:
				if s.id != 0 && s.state != slotDeleted && err == nil {
					t.Fatalf("step %d: delete of a %s secret accepted", step, s.state)
				}
				if s.state == slotDeleted && err == nil {
					t.Fatalf("step %d: delete of an already soft-deleted secret accepted", step)
				}
			}
		case 5:
			err := c.RestoreSecret(ctx, 1, s.id)
			switch s.state {
			case slotDeleted:
				if err != nil {
					t.Fatalf("step %d: restore of a soft-deleted secret refused: %v", step, err)
				}
				s.state, s.expired = slotLive, false
			default:
				if s.id != 0 && err == nil {
					t.Fatalf("step %d: restore of a %s secret accepted", step, s.state)
				}
			}
		case 6:
			if s.state == slotDeleted && !s.expired {
				if err := db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?", pastDeleted, pastPurge, s.id).Error; err != nil {
					t.Fatalf("step %d: expire: %v", step, err)
				}
				s.expired = true
			}
		case 7:
			want := int64(0)
			for k := range slots {
				if slots[k].state == slotDeleted && slots[k].expired {
					want++
				}
			}
			res, err := c.PurgeExpiredSoftDeletes(ctx, sweepBefore)
			if err != nil {
				t.Fatalf("step %d: purge sweep: %v", step, err)
			}
			if res.Secrets != want {
				t.Fatalf("step %d: purge removed %d secrets, model says %d eligible", step, res.Secrets, want)
			}
			for k := range slots {
				if slots[k].state == slotDeleted && slots[k].expired {
					slots[k].state, slots[k].expired = slotPurged, false
					slots[k].versions = nil
				}
			}
		case 8:
			if s.state == slotLive {
				if got, err := c.GetSecretValue(ctx, s.id); err != nil || string(got) != s.versions[n-1] {
					t.Fatalf("step %d: latest read %q (err %v), model %q", step, got, err, s.versions[n-1])
				}
			}
		case 9:
		}
	done:
		check(step, what)
	}
}
