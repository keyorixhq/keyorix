// cta_review_updaterole_explicit_scope_postgres_test.go — #3919: an UpdateRole
// with an EXPLICIT assignable scope classifies its change (widening: fail closed;
// narrowing: owed) and writes its audit text "(assignable_scope a -> b)" from
// the role as read inside its transaction. On PostgreSQL READ COMMITTED a plain
// GetRole locks nothing, so another replica's narrowing any -> project could
// commit between A's read ("any") and A's UPDATE: A then wrote global over
// project, a widening, but classified and audited it as an any -> global
// narrowing on the owed path (not blocked by an audit outage).
//
// The interleaving is forced with GORM callbacks on replica A's own *gorm.DB, the
// sibling of TestCTAReview_UpdateRoleKeepScope_vs_NarrowScope_CrossReplicaPostgres
// (the keep-scope half, #3909) and of SHARE-CAS-1's share-update race: replica
// B's real UpdateRole (its own pool, its own transaction) starts right before
// A's roles UPDATE. Unfixed, B commits inside A's window. Fixed
// (tx.LockRoleForUpdate as the transaction's first statement), B waits on A's
// row lock, detected through pg_blocking_pids, and applies after A commits.
//
// The assertion is the one that holds under every legal interleaving: some order
// of the role.updated rows walks the scope from its initial value to the stored
// one, each row starting where the previous one left it (auditChainExplains,
// SHARE-CAS-1). SQLite is not tested: its write transactions are BEGIN
// IMMEDIATE, so no second writer can commit inside A's transaction.
package core

import (
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// beforeARoleUpdate starts concurrent in a goroutine right before A's first
// roles UPDATE and holds A there until concurrent has finished (it committed
// inside A's window: the unfixed interleaving) or a backend is blocked by A's
// own backend (B waits on A's row lock). Call waitB after A returns.
func (f *ctaReview) beforeARoleUpdate(concurrent func()) (fired func() bool, waitB func()) {
	f.t.Helper()
	var once sync.Once
	hit := false
	done := make(chan struct{})
	require.NoError(f.t, f.dbA.Callback().Update().Before("gorm:update").Register("role-scope-3919:before-update", func(tx *gorm.DB) {
		if tx.Statement.Table != "roles" {
			return
		}
		once.Do(func() {
			hit = true
			var pidA int64
			require.NoError(f.t, tx.Statement.ConnPool.QueryRowContext(tx.Statement.Context, "SELECT pg_backend_pid()").Scan(&pidA))
			go func() {
				defer close(done)
				concurrent()
			}()
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				select {
				case <-done:
					return
				default:
				}
				var blocked int64
				require.NoError(f.t, f.setupDB.Raw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", pidA).
					Scan(&blocked).Error)
				if blocked > 0 {
					return
				}
			}
			f.t.Errorf("B neither finished nor blocked on A within 10s")
		})
	}))
	return func() bool { return hit }, func() {
		if hit {
			<-done
		}
	}
}

// beforeAInTxRoleRead runs concurrent to completion right before A's first read
// of roles inside a transaction. A holds no lock on the row yet, so B never
// waits here.
func (f *ctaReview) beforeAInTxRoleRead(concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	require.NoError(f.t, f.dbA.Callback().Query().Before("gorm:query").Register("role-scope-3919:before-tx-read", func(tx *gorm.DB) {
		if tx.Statement.Table != "roles" {
			return
		}
		if _, inTx := tx.Statement.ConnPool.(gorm.TxCommitter); !inTx {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}))
	return func() bool { return hit }
}

// Where B starts, relative to A.
const (
	roleBBeforeAUpdate   = "before A's roles UPDATE"                    // after A's in-transaction read
	roleBBeforeAInTxRead = "before A's in-transaction read of the role" // A holds no row lock yet
)

var roleScopeFromTo = regexp.MustCompile(`\(assignable_scope (\w+) -> (\w+)\)`)

func TestCTAReview_UpdateRoleExplicitScope_vs_NarrowScope_CrossReplicaPostgres(t *testing.T) {
	for _, tc := range []struct {
		when      string
		auditDown bool
		refused   bool
	}{
		{when: roleBBeforeAUpdate},
		// Control: B commits before A's in-transaction read, so A reads project and
		// classifies project -> global as the widening it is; with the audit log down
		// it is refused. Green with or without the fix: the invariant is not met by
		// refusing everything.
		{when: roleBBeforeAInTxRead, auditDown: true, refused: true},
	} {
		t.Run(fmt.Sprintf("%s/audit-down=%v", tc.when, tc.auditDown), func(t *testing.T) {
			t.Parallel()
			f := newCTAReview(t)
			require.Equal(t, "postgres", f.dbA.Dialector.Name(), "this race exists only on PostgreSQL")
			down := &atomic.Bool{}
			coreA := NewKeyorixCore((&auditOutageStorage{inner: localstore.NewLocalStorage(f.dbA), down: down}).store())
			coreA.SetAuthEncryptor(f.enc)

			name := "cta-explicit-scope"
			role, _, err := f.setup.CreateRoleWithScope(f.ctx, f.adminID, name, "before", nil, models.RoleAssignableAny)
			require.NoError(t, err)

			var errB error
			runB := func() {
				narrow := *role
				narrow.AssignableScope = models.RoleAssignableProject
				_, _, errB = f.coreB.UpdateRole(f.ctx, f.adminID, &narrow, nil)
			}
			var fired func() bool
			waitB := func() {}
			switch tc.when {
			case roleBBeforeAUpdate:
				fired, waitB = f.beforeARoleUpdate(runB)
			case roleBBeforeAInTxRead:
				fired = f.beforeAInTxRoleRead(runB)
			default:
				t.Fatalf("unknown interleaving %q", tc.when)
			}

			// Replica A sets the scope to global explicitly.
			global := *role
			global.AssignableScope = models.RoleAssignableGlobal
			global.Description = "A makes it global"
			down.Store(tc.auditDown)
			_, _, errA := coreA.UpdateRole(f.ctx, f.adminID, &global, nil)
			down.Store(false)
			waitB()
			t.Logf("B started %s; A (audit down=%v) err=%v, B err=%v", tc.when, tc.auditDown, errA, errB)
			require.True(t, fired(), "the hook must have started B's update %s", tc.when)
			require.NoError(t, errB, "replica B's narrowing")
			if tc.refused {
				require.ErrorIs(t, errA, ErrMutationAuditUnavailable, "project -> global widens: it must fail closed with the audit log down")
			} else {
				require.NoError(t, errA, "replica A's explicit scope change")
			}

			var stored models.Role
			require.NoError(t, f.setupDB.First(&stored, role.ID).Error)
			var descs []string
			require.NoError(t, f.setupDB.Model(&models.AuditEvent{}).
				Where("event_type = ? AND description LIKE ?", EventRoleUpdated, "%"+name+"%").
				Pluck("description", &descs).Error)
			rows := make([][2]string, 0, len(descs))
			for _, d := range descs {
				if m := roleScopeFromTo.FindStringSubmatch(d); m != nil {
					rows = append(rows, [2]string{m[1], m[2]})
				}
			}
			t.Logf("stored scope %q, role.updated scope rows %v", stored.AssignableScope, rows)
			assert.True(t, auditChainExplains(models.RoleAssignableAny, stored.AssignableScope, rows),
				"the audit trail cannot explain the role's scope (any -> %q) from rows %v: an update classified "+
					"from a stale read changed the scope without a true row", stored.AssignableScope, rows)
		})
	}
}
