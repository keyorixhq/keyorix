// access_request_approve_delete_race_test.go — CORE-ACTOR-RACE-1 items 1 and 2:
// a secret-scoped access-request APPROVAL racing the delete sweeps that close
// approved requests (#2797's closeApprovedSecretAccessRequests, reached from
// DeleteSecret and from the DeleteProject cascade).
//
// The hazard: ApproveSecretAccessRequest checks that the secret is live with a
// GetSecret OUTSIDE its write transaction, and the sweep only closes rows that are
// already 'approved'. A delete that commits between that check and the approval's
// UPDATE sees the request still pending, leaves it alone, and the approval then
// commits 'approved' against a deleted secret. Restoring the secret from the
// recycle bin brings that approval back live with no re-authorization: the exact
// effect #2797 closed for approvals that existed before the delete.
//
// Two connection pools (two *gorm.DB, two *KeyorixCore) on one database, so the
// two sides are genuinely independent replicas. The interleaving is forced, never
// raced: either a one-shot hook on the approver's own pool that runs the whole
// delete right after the approval's secret read, or interleave_sync_points_test.go's
// driver for the complete set of six (check, act) orderings.
//
// The assertions are on the effect (CLAUDE.md: "assert the effect, not the return
// value"): after the race and a restore, the requester's read of the restricted
// secret must still be refused and the request must not read as approved.
package core

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// approveRaceWorld is one database seen through two replicas: A approves, B deletes
// and restores. Everything is seeded through A before either side runs.
type approveRaceWorld struct {
	dbA, dbB  *gorm.DB
	coreA     *KeyorixCore
	coreB     *KeyorixCore
	projectID uint
	secretID  uint
	requester uint
	approver  uint
	requestID uint
}

// newApproveRaceWorld seeds a project with one environment and one restricted
// secret owned by a project-viewer requester, a global admin approver, and one
// PENDING secret-scoped access request from the requester.
func newApproveRaceWorld(t *testing.T, dbA, dbB *gorm.DB) *approveRaceWorld {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	ctx := context.Background()
	stA := localstore.NewLocalStorage(dbA)
	w := &approveRaceWorld{dbA: dbA, dbB: dbB, coreA: NewKeyorixCore(stA), coreB: NewKeyorixCore(localstore.NewLocalStorage(dbB))}
	w.coreA.SetBootstrapToken("race-bootstrap-token")
	_, err := w.coreA.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "race-bootstrap-token",
	})
	require.NoError(t, err)
	for _, c := range []*KeyorixCore{w.coreA, w.coreB} {
		c.SetClassificationRestrictedRequiresApproval(true)
	}

	proj, err := stA.CreateProject(ctx, &models.Project{Name: "approve-race"})
	require.NoError(t, err)
	w.projectID = proj.ID
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, dbA.Create(env).Error)

	requester, err := stA.CreateUser(ctx, foldedTestUser(t, "requester", "requester@example.com"))
	require.NoError(t, err)
	w.requester = requester.ID
	viewer, err := stA.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, stA.AssignRole(ctx, requester.ID, viewer.ID, storage.Scope{ProjectID: proj.ID}))

	approver, err := stA.CreateUser(ctx, foldedTestUser(t, "approver", "approver@example.com"))
	require.NoError(t, err)
	w.approver = approver.ID
	admin, err := stA.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, stA.AssignRole(ctx, approver.ID, admin.ID, storage.Scope{}))

	secret, err := stA.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
		IsSecret: true, OwnerID: requester.ID, Status: "active", Classification: ClassificationRestricted,
	})
	require.NoError(t, err)
	w.secretID = secret.ID
	_, err = stA.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t-value"),
	})
	require.NoError(t, err)

	req, err := w.coreA.RequestSecretAccess(ctx, secret.ID, requester.ID, "incident")
	require.NoError(t, err)
	w.requestID = req.ID
	return w
}

func (w *approveRaceWorld) approve() error {
	_, err := w.coreA.ApproveSecretAccessRequest(context.Background(), w.requestID, w.approver)
	return err
}

func (w *approveRaceWorld) deleteSecret() error {
	return w.coreB.DeleteSecret(context.Background(), w.secretID)
}

func (w *approveRaceWorld) restoreSecret() error {
	return w.coreB.RestoreSecret(context.Background(), w.approver, w.secretID)
}

func (w *approveRaceWorld) deleteProject() error {
	return w.coreB.DeleteProject(context.Background(), w.approver, w.projectID, true)
}

func (w *approveRaceWorld) restoreProject() error {
	return w.coreB.RestoreProject(context.Background(), w.approver, w.projectID)
}

// requestState reads the request row through replica B (a different pool from the
// approver's, so nothing is answered from the approver's own connection).
func (w *approveRaceWorld) requestState(t *testing.T) string {
	t.Helper()
	var req models.AccessRequest
	require.NoError(t, w.dbB.First(&req, w.requestID).Error)
	return req.State
}

func (w *approveRaceWorld) secretDeleted(t *testing.T) bool {
	t.Helper()
	var n models.SecretNode
	require.NoError(t, w.dbB.Unscoped().First(&n, w.secretID).Error)
	return n.DeletedAt.Valid
}

// requireNoRevivedApproval is the invariant: once the secret has been deleted and
// restored, the requester has no approval that predates the delete. Checked as the
// effect (the gated read is refused) and as the row.
func (w *approveRaceWorld) requireNoRevivedApproval(t *testing.T, ctxMsg string) {
	t.Helper()
	require.False(t, w.secretDeleted(t), "%s: the restore must have brought the secret back", ctxMsg)
	require.NotEqual(t, AccessRequestApproved, w.requestState(t),
		"%s: an approval that raced the delete came back live on restore (#2797 class)", ctxMsg)
	_, err := w.coreB.GetSecretValueWithPermissionCheck(context.Background(), w.secretID, w.requester)
	require.Error(t, err, "%s: the restricted read must still need a fresh approval after the restore", ctxMsg)
}

// afterFirstQueryOn registers a one-shot callback on db that runs fn right after the
// first read of table on that pool, and reports how often it fired. On the
// approver's pool the first secret_nodes read of ApproveSecretAccessRequest is its
// liveness check (GetSecret), so fn lands between the check and the approval's
// write transaction; the approval has no transaction open at that point, so fn's
// own writes cannot block on it.
//
// GetSecret has two read shapes and both are covered: a cache miss is a model
// query (Query callbacks, Statement.Table set), a cache hit is confirmed by the raw
// cache_epoch stamp read (readLiveNodeStamp: Raw+Scan, Row callbacks, no
// Statement.Table, so it is matched on the SQL text).
func afterFirstQueryOn(t *testing.T, db *gorm.DB, table string, fn func()) *atomic.Int32 {
	t.Helper()
	var hits atomic.Int32
	var once sync.Once
	cb := func(tx *gorm.DB) {
		if tx.Statement.Table != table && !strings.Contains(tx.Statement.SQL.String(), "FROM "+table+" ") {
			return
		}
		once.Do(func() {
			hits.Add(1)
			fn()
		})
	}
	name := "core-actor-race-1:after-" + table + "-read"
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(name, cb))
	require.NoError(t, db.Callback().Row().After("gorm:row").Register(name, cb))
	t.Cleanup(func() {
		_ = db.Callback().Query().Remove(name)
		_ = db.Callback().Row().Remove(name)
	})
	return &hits
}

// approveRaceDeleter is one delete sweep that closes approved secret requests, with
// its inverse and the statement the six-ordering driver pauses it at (the first
// write of its secret soft-delete).
type approveRaceDeleter struct {
	name         string
	del, restore func(w *approveRaceWorld) error
	syncKind     string
	syncTable    string
	syncFunction string
}

var approveRaceDeleters = []approveRaceDeleter{
	{
		name: "DeleteSecret", del: (*approveRaceWorld).deleteSecret, restore: (*approveRaceWorld).restoreSecret,
		// The soft delete is GORM's Delete callback family even though it emits an UPDATE.
		syncFunction: "DeleteSecret", syncKind: "delete", syncTable: "secret_nodes",
	},
	{
		name: "DeleteProject", del: (*approveRaceWorld).deleteProject, restore: (*approveRaceWorld).restoreProject,
		// The cascade soft-deletes the project's secrets with a bulk Update on secret_nodes.
		syncFunction: "DeleteProject", syncKind: "update", syncTable: "secret_nodes",
	},
}

// runDeleteInApprovalWindow forces the bad interleaving: the whole delete commits
// after the approval read the secret as live and before the approval writes.
func runDeleteInApprovalWindow(t *testing.T, w *approveRaceWorld, d approveRaceDeleter) {
	t.Helper()
	var delErr error
	hits := afterFirstQueryOn(t, w.dbA, "secret_nodes", func() { delErr = d.del(w) })
	approveErr := w.approve()
	require.Equal(t, int32(1), hits.Load(), "the hook must have fired inside the approval, or nothing was forced")
	require.NoError(t, delErr, "%s must succeed", d.name)
	require.True(t, w.secretDeleted(t))
	if approveErr == nil {
		// Only legal if the sweep still reached the row afterwards; it cannot have.
		require.NotEqual(t, AccessRequestApproved, w.requestState(t),
			"approval committed 'approved' against a secret %s had already deleted", d.name)
	}
	require.Error(t, approveErr, "an approval whose secret was deleted before it wrote must be refused")
	require.Contains(t, approveErr.Error(), "no longer exists")
	require.Equal(t, AccessRequestPending, w.requestState(t), "the refused approval must roll back")

	require.NoError(t, d.restore(w))
	w.requireNoRevivedApproval(t, d.name+" in the approval window")
}

func pgApproveRaceWorld(t *testing.T) *approveRaceWorld {
	t.Helper()
	dsn := pgMigratedDatabaseDSN(t, pgTestDSN(t))
	return newApproveRaceWorld(t, pgOpen(t, dsn), pgOpen(t, dsn))
}

// sqliteApproveRaceWorld opens one file-backed SQLite database through two
// independent pools. SQLite admits one writer at a time (BEGIN IMMEDIATE), which
// serialises the two write transactions but not the approval's read-before-write.
func sqliteApproveRaceWorld(t *testing.T) *approveRaceWorld {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "approve_race.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	open := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
		require.NoError(t, err)
		sqlDB, err := db.DB()
		require.NoError(t, err)
		t.Cleanup(func() { _ = sqlDB.Close() })
		return db
	}
	dbA := open()
	require.NoError(t, kxstorage.MigrateExisting(dbA))
	return newApproveRaceWorld(t, dbA, open())
}

// Item 1 (DeleteSecret) and item 2 (DeleteProject cascade), Postgres: the delete
// commits inside the approval's check-to-write window.
func TestApproveSecretAccessRequest_DeleteInApprovalWindow_Postgres(t *testing.T) {
	for _, d := range approveRaceDeleters {
		t.Run(d.name, func(t *testing.T) {
			runDeleteInApprovalWindow(t, pgApproveRaceWorld(t), d)
		})
	}
}

// The SQLite twin: the single-writer gate must give the same outcome.
func TestApproveSecretAccessRequest_DeleteInApprovalWindow_SQLite(t *testing.T) {
	for _, d := range approveRaceDeleters {
		t.Run(d.name, func(t *testing.T) {
			runDeleteInApprovalWindow(t, sqliteApproveRaceWorld(t), d)
		})
	}
}

// All six (check, act) orderings of approval (A, paused before its access_requests
// UPDATE) against each delete sweep (B, paused before its secret soft-delete), on
// Postgres. Whatever the order, the request is never approved on a deleted secret
// and nothing comes back on restore.
func TestApproveSecretAccessRequest_DeleteSweep_AllOrderings_Postgres(t *testing.T) {
	for _, d := range approveRaceDeleters {
		for _, order := range allInterleavings {
			t.Run(d.name+"/"+string(order), func(t *testing.T) {
				w := pgApproveRaceWorld(t)
				spA := newSyncPoint(t, w.dbA, "ApproveSecretAccessRequest", "update", "access_requests")
				spB := newSyncPoint(t, w.dbB, d.syncFunction, d.syncKind, d.syncTable)
				res := runInterleaving(t, order, spA, spB, w.approve, func() error { return d.del(w) })
				t.Log(res.String())
				require.True(t, res.Forced, "ordering not forced: %s", res.Degraded)
				require.NoError(t, res.ErrB, "%s must succeed in every ordering", d.name)
				require.True(t, w.secretDeleted(t))
				require.NotEqual(t, AccessRequestApproved, w.requestState(t),
					"approved request on a deleted secret after %s", order)
				require.NoError(t, d.restore(w))
				w.requireNoRevivedApproval(t, string(order))
			})
		}
	}
}

// The mirror case: approval racing RESTORE of an already-deleted secret, all six
// orderings on Postgres. An approval whose liveness check ran while the secret was
// still deleted is refused; one whose check ran after the restore committed is a
// normal approval of a live secret. Either way the end state is consistent:
// approved exactly when the approval call succeeded, and never on a deleted secret.
func TestApproveSecretAccessRequest_RestoreRace_AllOrderings_Postgres(t *testing.T) {
	for _, order := range allInterleavings {
		t.Run(string(order), func(t *testing.T) {
			w := pgApproveRaceWorld(t)
			require.NoError(t, w.deleteSecret())
			spA := newSyncPoint(t, w.dbA, "ApproveSecretAccessRequest", "update", "access_requests")
			spB := newSyncPoint(t, w.dbB, "RestoreSecret", "update", "secret_nodes")
			res := runInterleaving(t, order, spA, spB, w.approve, w.restoreSecret)
			t.Log(res.String())
			require.NoError(t, res.ErrB, "the restore must succeed in every ordering")
			require.False(t, w.secretDeleted(t))
			approved := w.requestState(t) == AccessRequestApproved
			require.Equal(t, res.ErrA == nil, approved, "row state must match the approval's answer (errA=%v)", res.ErrA)
			if order == orderSerialAB || order == orderABAcAa || order == orderABBaAa {
				// A checked before B restored: it saw a deleted secret.
				require.Error(t, res.ErrA, "an approval that checked a deleted secret must be refused")
			}
		})
	}
}

// Delete AND restore both land in the approval's window. The approval was decided
// against a live secret and commits against a live secret, so it stands: this is
// the same end state as an approval made right after the restore, and the delete
// had nothing approved to sweep. Pinned so a later change to it is a decision, not
// an accident. Postgres and SQLite.
func TestApproveSecretAccessRequest_DeleteAndRestoreInApprovalWindow(t *testing.T) {
	worlds := map[string]func(*testing.T) *approveRaceWorld{
		"Postgres": pgApproveRaceWorld,
		"SQLite":   sqliteApproveRaceWorld,
	}
	for name, mk := range worlds {
		t.Run(name, func(t *testing.T) {
			w := mk(t)
			var delErr, restoreErr error
			hits := afterFirstQueryOn(t, w.dbA, "secret_nodes", func() {
				delErr = w.deleteSecret()
				restoreErr = w.restoreSecret()
			})
			require.NoError(t, w.approve())
			require.Equal(t, int32(1), hits.Load())
			require.NoError(t, delErr)
			require.NoError(t, restoreErr)
			require.Equal(t, AccessRequestApproved, w.requestState(t))
		})
	}
}
