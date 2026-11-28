package core

// secret_mutation_audit_untagged_test.go — AUDIT-FAILCLOSED-SECRETS-1 (#4719): a
// secret mutation reached WITHOUT WithSecretMutationAudit still commits its audit
// row in its own transaction, or changes nothing.
//
// On main, mutationAuditRowFor returned ok=false for an untagged context, so an
// untagged RotateSecret (the scheduler, the REST bulk rotate) committed a new
// version with no secret.rotated row at all, and copy / bulk delete / folder
// create wrote their row after the commit with the result discarded. Red there:
// the success leg finds no secret.rotated row, and the outage leg finds the
// change committed.
//
// SQLite always; PostgreSQL with KEYORIX_TEST_PG_DSN.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// auditOutage fails every audit append of one event type, including the ones made
// through a transaction-scoped handle (WrapTx), and passes everything else through.
// failLogAuditEventStorage misses those: it does not wrap transactions.
type auditOutage struct {
	mu        sync.Mutex
	eventType string // "" = no outage
	hits      int
}

func (o *auditOutage) arm(eventType string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.eventType, o.hits = eventType, 0
}

// refuse reports whether e is refused, counting the refusals.
func (o *auditOutage) refuse(e *models.AuditEvent) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.eventType == "" || e.EventType != o.eventType {
		return false
	}
	o.hits++
	return true
}

func (o *auditOutage) fired() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits
}

func failAuditTxStorage(inner storage.Storage, o *auditOutage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if o.refuse(e) {
				return fmt.Errorf("fault-injected: %s audit write failed", e.EventType)
			}
			return next.LogAuditEvent(ctx, e)
		},
		LogAuditEventWithAccessLog: func(next storage.Storage, ctx context.Context, e *models.AuditEvent, l *models.SecretAccessLog) error {
			if o.refuse(e) {
				return fmt.Errorf("fault-injected: %s audit write failed", e.EventType)
			}
			return next.LogAuditEventWithAccessLog(ctx, e, l)
		},
	})
}

// outageWorld is smaWorld with an event-type outage instead of faultstorage, so a
// fault lands on one event even when the operation writes several rows.
type outageWorld struct {
	*smaWorld
	outage *auditOutage
}

func newOutageWorld(t *testing.T, f *ctaReview) *outageWorld {
	t.Helper()
	o := &auditOutage{}
	c := NewKeyorixCore(failAuditTxStorage(localstore.NewLocalStorage(f.dbA), o))
	return &outageWorld{smaWorld: &smaWorld{t: t, f: f, db: f.dbA, c: c, ctx: context.Background()}, outage: o}
}

func outageBackends(t *testing.T, fn func(t *testing.T, w *outageWorld)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newOutageWorld(t, newCTAReviewSQLite(t))) })
	t.Run("postgres", func(t *testing.T) { fn(t, newOutageWorld(t, newCTAReview(t))) })
}

// outageKind is one mutation family: prepare returns the target, mutate runs the
// mutation and returns the id its audit row is keyed on, committed says whether the
// change is visible.
type outageKind struct {
	name      string
	eventType string
	prepare   func(w *outageWorld, tag string) (uint, string)
	mutate    func(w *outageWorld, id uint, name string) (uint, error)
	committed func(w *outageWorld, id uint, name string) bool
	// bulk: the outage is reported per item, not as the call's error.
	bulk bool
	// countOnly: the call reports only a count (ExtendExpiringSecrets), so the
	// refusal shows as nothing done, not as a named error.
	countOnly bool
	// sentinel is the refusal's error (default ErrSecretMutationAuditUnavailable).
	sentinel error
	// projectLevel: the row names the project, not a secret.
	projectLevel bool
}

// changeState fingerprints the change a mutation of (id, name) makes and every row
// of eventType. Rows of other types are left out on purpose: a refused change may
// still record its attempt (the bulk summary, the scheduler's FAILED row, the copy's
// source read), which is correct; what must not exist is the change or its row.
func (w *outageWorld) changeState(id uint, name, eventType string) string {
	w.t.Helper()
	var nodes []models.SecretNode
	require.NoError(w.t, w.db.Unscoped().Where("id = ? OR name = ?", id, name).Order("id").Find(&nodes).Error)
	out := ""
	ids := []uint{}
	for _, n := range nodes {
		ids = append(ids, n.ID)
		out += fmt.Sprintf("node %d %q env=%d desc=%q deleted=%v rotated=%v updated=%d;", n.ID, n.Name, n.EnvironmentID,
			n.Description, n.DeletedAt.Valid, n.LastRotatedAt != nil, n.UpdatedAt.UnixMicro())
	}
	count := func(model any, where string, args ...any) int64 {
		var c int64
		require.NoError(w.t, w.db.Model(model).Where(where, args...).Count(&c).Error)
		return c
	}
	return out + fmt.Sprintf(" versions=%d rows(%s)=%d writelogs=%d", count(&models.SecretVersion{}, "secret_node_id IN ?", append(ids, 0)),
		eventType, count(&models.AuditEvent{}, "event_type = ?", eventType),
		count(&models.SecretAccessLog{}, "action <> ?", "read"))
}

func (w *outageWorld) versions(id uint) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.SecretVersion{}).Where("secret_node_id = ?", id).Count(&n).Error)
	return n
}

func (w *outageWorld) deleted(id uint) bool {
	w.t.Helper()
	var s models.SecretNode
	require.NoError(w.t, w.db.Unscoped().First(&s, id).Error)
	return s.DeletedAt.Valid
}

func (w *outageWorld) nodesNamed(name string) int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.db.Model(&models.SecretNode{}).Where("name = ?", name).Count(&n).Error)
	return n
}

// autoRotating is a secret with auto-rotation enabled (no backend).
func (w *outageWorld) autoRotating(tag string) (uint, string) {
	w.t.Helper()
	s := w.secret("unt-" + tag)
	require.NoError(w.t, w.c.SetSecretAutoRotate(w.ctx, s.ID, AutoRotateSpec{Enabled: true}, w.f.adminID))
	return s.ID, s.Name
}

func (w *outageWorld) env(name string) uint {
	w.t.Helper()
	e, err := w.c.CreateEnvironment(w.ctx, w.f.projectID, name)
	require.NoError(w.t, err)
	return e.ID
}

func bulkRotateErr(res *BulkRotateResult, err error) error {
	if err != nil {
		return err
	}
	if len(res.Failed) > 0 {
		return errors.New(res.Failed[0].Error)
	}
	return nil
}

func untaggedKinds() []outageKind {
	existing := func(w *outageWorld, tag string) (uint, string) {
		s := w.secret("unt-" + tag)
		return s.ID, s.Name
	}
	twoVersions := func(w *outageWorld, id uint, _ string) bool { return w.versions(id) == 2 }
	node := func(w *outageWorld, id uint) models.SecretNode {
		var s models.SecretNode
		require.NoError(w.t, w.db.Unscoped().First(&s, id).Error)
		return s
	}
	var mu sync.Mutex
	related := map[uint]uint{} // secret id -> the folder / new owner its kind moves it to
	relate := func(id, other uint) {
		mu.Lock()
		defer mu.Unlock()
		related[id] = other
	}
	relatedTo := func(id uint) uint {
		mu.Lock()
		defer mu.Unlock()
		return related[id]
	}
	return []outageKind{
		{
			name: "classify", eventType: evtSecretUpdated, prepare: existing,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				_, err := w.c.ClassifySecret(context.Background(), w.f.adminID, "admin", id, ClassificationConfidential)
				return id, err
			},
			committed: func(w *outageWorld, id uint, _ string) bool {
				return node(w, id).Classification == ClassificationConfidential
			},
		},
		{
			name: "bulk-rename", eventType: evtSecretUpdated, prepare: existing, bulk: true,
			mutate: func(w *outageWorld, id uint, name string) (uint, error) {
				rep, err := w.c.BulkRenameSecrets(context.Background(), w.f.projectID,
					[]SecretRename{{ID: id, NewName: name + "-renamed"}}, false, "admin", w.f.adminID, "198.51.100.9", "unt-test")
				if err != nil {
					return id, err
				}
				if rep.Renamed != 1 {
					return id, fmt.Errorf("not renamed: %+v", rep.Outcomes)
				}
				return id, nil
			},
			committed: func(w *outageWorld, id uint, name string) bool { return node(w, id).Name == name+"-renamed" },
		},
		{
			name: "extend-expiring", eventType: evtSecretUpdated, countOnly: true,
			prepare: func(w *outageWorld, tag string) (uint, string) {
				exp := time.Now().Add(24 * time.Hour)
				s, err := w.c.CreateSecret(w.ctx, &CreateSecretRequest{
					Name: "unt-" + tag, Value: []byte("v"), ProjectID: w.f.projectID, EnvironmentID: w.f.envID,
					Type: "generic", CreatedBy: "admin", OwnerID: w.f.adminID, Expiration: &exp,
				})
				require.NoError(w.t, err)
				return s.ID, s.Name
			},
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				n, _, err := w.c.ExtendExpiringSecrets(context.Background(), w.f.projectID, 7, 90, "admin", w.f.adminID)
				if err != nil {
					return id, err
				}
				if n == 0 {
					return id, errors.New("nothing extended")
				}
				return id, nil
			},
			committed: func(w *outageWorld, id uint, _ string) bool {
				e := node(w, id).Expiration
				return e != nil && e.After(time.Now().Add(30*24*time.Hour))
			},
		},
		{
			name: "move", eventType: EventSecretMoved,
			prepare: func(w *outageWorld, tag string) (uint, string) {
				fo, err := w.c.CreateFolder(w.ctx, w.f.adminID, "unt-dir-"+tag, w.f.projectID, w.f.envID, nil)
				require.NoError(w.t, err)
				s := w.secret("unt-" + tag)
				relate(s.ID, fo.ID)
				return s.ID, s.Name
			},
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				dir := relatedTo(id)
				_, err := w.c.MoveSecret(context.Background(), w.f.adminID, id, &dir)
				return id, err
			},
			committed: func(w *outageWorld, id uint, _ string) bool {
				p := node(w, id).ParentID
				return p != nil && *p == relatedTo(id)
			},
		},
		{
			name: "transfer-ownership", eventType: EventSecretOwnerTransferred,
			prepare: func(w *outageWorld, tag string) (uint, string) {
				s := w.secret("unt-" + tag)
				relate(s.ID, w.f.user("unt-owner-"+tag, "project_admin").ID)
				return s.ID, s.Name
			},
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				_, err := w.c.TransferSecretOwnership(context.Background(), id, relatedTo(id), w.f.adminID, ActorTypeUser)
				return id, err
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return node(w, id).OwnerID == relatedTo(id) },
		},
		{
			name: "rotate", eventType: "secret.rotated", prepare: existing, committed: twoVersions,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				_, err := w.c.RotateSecret(context.Background(), id, []byte("rotated"), w.f.adminID, "admin")
				return id, err
			},
		},
		{
			name: "rotate-on-demand", eventType: "secret.rotated", prepare: existing, committed: twoVersions,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				_, err := w.c.RotateSecretOnDemand(context.Background(), id, []byte("rotated"), w.f.adminID, "admin")
				return id, err
			},
		},
		{
			name: "bulk-rotate", eventType: "secret.rotated", bulk: true, committed: twoVersions,
			prepare: func(w *outageWorld, tag string) (uint, string) { return w.autoRotating(tag) },
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				return id, bulkRotateErr(w.c.BulkRotateSecrets(context.Background(), w.f.adminID,
					BulkRotateRequest{ProjectID: w.f.projectID, SecretIDs: []uint{id}, RotatedBy: "admin"}))
			},
		},
		{
			name: "scheduled-auto-rotation", eventType: "secret.rotated", bulk: true, committed: twoVersions,
			prepare: func(w *outageWorld, tag string) (uint, string) { return w.autoRotating(tag) },
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				s, err := w.c.storage.GetSecret(context.Background(), id)
				require.NoError(w.t, err)
				failed := map[uint]rotationFailureDetail{}
				if !w.c.rotateOneSecret(context.Background(), s, &models.RotationPolicy{Name: "unt", IntervalDays: 1}, failed) {
					return id, errors.New(failed[id].Detail)
				}
				return id, nil
			},
		},
		{
			name: "create", eventType: "secret.created",
			prepare: func(_ *outageWorld, tag string) (uint, string) { return 0, "unt-" + tag },
			mutate: func(w *outageWorld, _ uint, name string) (uint, error) {
				s, err := w.c.CreateSecret(context.Background(), &CreateSecretRequest{
					Name: name, Value: []byte("v"), ProjectID: w.f.projectID, EnvironmentID: w.f.envID,
					Type: "generic", CreatedBy: "admin", OwnerID: w.f.adminID,
				})
				if err != nil {
					return 0, err
				}
				return s.ID, nil
			},
			committed: func(w *outageWorld, _ uint, name string) bool { return w.nodesNamed(name) == 1 },
		},
		{
			name: "update", eventType: evtSecretUpdated, prepare: existing,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				d := "changed"
				_, err := w.c.UpdateSecret(context.Background(), &UpdateSecretRequest{ID: id, Description: &d, UpdatedBy: "admin"})
				return id, err
			},
			committed: func(w *outageWorld, id uint, _ string) bool {
				var s models.SecretNode
				require.NoError(w.t, w.db.First(&s, id).Error)
				return s.Description == "changed"
			},
		},
		{
			name: "delete", eventType: "secret.deleted", prepare: existing,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				return id, w.c.DeleteSecret(context.Background(), id)
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return w.deleted(id) },
		},
		{
			name: "bulk-delete", eventType: "secret.deleted", prepare: existing, bulk: true,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				res, err := w.c.BulkDeleteSecrets(context.Background(), BulkDeleteRequest{SecretIDs: []uint{id}},
					w.f.projectID, "admin", w.f.adminID, "198.51.100.9", "unt-test")
				if err != nil {
					return id, err
				}
				if len(res.Failed) > 0 {
					return id, errors.New(res.Failed[0].Error)
				}
				return id, nil
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return w.deleted(id) },
		},
		{
			name: "folder-create", eventType: "folder.created",
			prepare: func(_ *outageWorld, tag string) (uint, string) { return 0, "unt-" + tag },
			mutate: func(w *outageWorld, _ uint, name string) (uint, error) {
				fo, err := w.c.CreateFolder(context.Background(), w.f.adminID, name, w.f.projectID, w.f.envID, nil)
				if err != nil {
					return 0, err
				}
				return fo.ID, nil
			},
			committed: func(w *outageWorld, _ uint, name string) bool { return w.nodesNamed(name) == 1 },
		},
		{
			// CopySecret writes the source's secret.read row first (audit-before-
			// disclosure, already fail-closed) and then the copy's secret.created row,
			// which is the one under test.
			name: "copy", eventType: "secret.created",
			prepare: func(w *outageWorld, tag string) (uint, string) {
				s := w.secret("unt-" + tag)
				return s.ID, s.Name
			},
			mutate: func(w *outageWorld, id uint, name string) (uint, error) {
				dst := w.env("unt-dst-" + name)
				created, err := w.c.CopySecret(context.Background(), id, dst, "", "admin", w.f.adminID, "198.51.100.9", "unt-test")
				if err != nil {
					return 0, err
				}
				return created.ID, nil
			},
			committed: func(w *outageWorld, _ uint, name string) bool { return w.nodesNamed(name) == 2 },
		},
	}
}

func TestSecretMutationAudit_UntaggedCallCommitsItsRowOrNothing(t *testing.T) {
	runOutageKinds(t, untaggedKinds())
}

func runOutageKinds(t *testing.T, kinds []outageKind) {
	outageBackends(t, func(t *testing.T, w *outageWorld) {
		for _, k := range kinds {
			t.Run(k.name+"/success", func(t *testing.T) {
				id, name := k.prepare(w, k.name+"-ok")
				got, err := k.mutate(w, id, name)
				require.NoError(t, err)
				require.True(t, k.committed(w, got, name), "precondition: the mutation must have committed")
				rows := w.auditRows(k.eventType, got)
				if k.projectLevel {
					require.NoError(t, w.db.Model(&models.AuditEvent{}).
						Where("event_type = ? AND project_id = ?", k.eventType, w.f.projectID).Count(&rows).Error)
				}
				require.EqualValues(t, 1, rows,
					"%s committed, so exactly one %s row must exist when the call returns", k.name, k.eventType)
			})
			t.Run(k.name+"/audit-outage", func(t *testing.T) {
				id, name := k.prepare(w, k.name+"-down")
				before := w.changeState(id, name, k.eventType)
				w.outage.arm(k.eventType)
				got, err := k.mutate(w, id, name)
				fired := w.outage.fired()
				w.outage.arm("")
				require.Positive(t, fired, "%s never appended a %s row", k.name, k.eventType)
				require.Error(t, err, "an untagged %s whose %s row was refused must not report success", k.name, k.eventType)
				switch {
				case k.countOnly:
				case k.bulk:
					require.Contains(t, err.Error(), ErrSecretMutationAuditUnavailable.Error())
				default:
					want := k.sentinel
					if want == nil {
						want = ErrSecretMutationAuditUnavailable
					}
					require.ErrorIs(t, err, want)
				}
				require.False(t, k.committed(w, got, name), "%s committed although its audit row could not be written", k.name)
				require.Equal(t, before, w.changeState(id, name, k.eventType),
					"a refused audit row must leave the secret, its versions, its %s rows and its access logs unchanged", k.eventType)
			})
		}
		v, err := w.c.Storage().VerifyAuditChain(context.Background(), nil)
		require.NoError(t, err)
		require.True(t, v.Valid, "the audit chain must verify after every success and every refused attempt: %s", v.Reason)
	})
}

// TestSecretMutationAudit_UntaggedRotationIsAttributedToItsActor: the row core
// derives for an untagged rotation names the actor and rotatedBy the call carries,
// and a transport's tag still wins over them.
func TestSecretMutationAudit_UntaggedRotationIsAttributedToItsActor(t *testing.T) {
	w := newOutageWorld(t, newCTAReviewSQLite(t))
	s := w.secret("unt-attr")
	_, err := w.c.RotateSecret(context.Background(), s.ID, []byte("rotated-1"), w.f.adminID, "system:auto-rotation")
	require.NoError(t, err)
	var e models.AuditEvent
	require.NoError(t, w.db.Where("event_type = ? AND secret_node_id = ?", "secret.rotated", s.ID).First(&e).Error)
	require.NotNil(t, e.UserID)
	require.Equal(t, w.f.adminID, *e.UserID)
	require.Contains(t, e.Description, "system:auto-rotation")

	tagged := WithSecretMutationAudit(context.Background(), SecretMutationAudit{UserID: w.f.adminID, Username: "alice", IP: "198.51.100.10"})
	_, err = w.c.RotateSecret(tagged, s.ID, []byte("rotated-2"), w.f.adminID, "ignored-label")
	require.NoError(t, err)
	var rows []models.AuditEvent
	require.NoError(t, w.db.Where("event_type = ? AND secret_node_id = ?", "secret.rotated", s.ID).Order("id").Find(&rows).Error)
	require.Len(t, rows, 2)
	require.Contains(t, rows[1].Description, "alice")
	require.Equal(t, "198.51.100.10", rows[1].IPAddress)
}
