package core

import (
	"context"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_ApproveAccessRequestWithExpiry_CrossReplicaPostgres_SubThresholdStraddle
// is the #G04-HA regression test: the dual-control race variant that neither
// constraint #1646 relied on can catch.
//
// #1646's own race test (concurrency_dual_control_approval_postgres_test.go)
// deliberately seeds one approval first, so BOTH racers cross the threshold and
// both reach AssignUserRole -- where UserRole's composite primary key resolves the
// race structurally. That seeding is what hides this variant. Here the racers
// STRADDLE the K-th approval instead: a 2-of-N request with NO prior approvals,
// approved by two distinct people at the same instant. Both read approvals=[],
// both compute received=1 < 2, and both take recordPartialApproval -- granting no
// role, so UserRole's primary key is never consulted, and being distinct
// approvers, so AccessRequestApproval's ux_access_request_approver unique index is
// never consulted either. Neither guard fires.
//
// The pre-fix outcome is not a double-grant but a STRANDED request: two valid
// approvals recorded against a 2-of-N policy, state still pending, and nothing
// that ever reconciles it (the only sweep over pending requests expires them at
// their TTL). The threshold silently becomes 3-of-N and a legitimately-approved
// break-glass grant lapses instead of landing. It fails closed, never open --
// approval rows are unique per approver and the finalizing caller is by
// construction not already among them, so distinct approvers at finalize is always
// len(approvals)+1 >= K -- but availability and the A.5.3/SOX evidence trail both
// suffer: each racer also emits the same "approval 1 of 2" audit ordinal, and the
// 2nd is never recorded at all.
//
// Two independent replicas (own *gorm.DB, own LocalStorage, own KeyorixCore) share
// one real Postgres schema, exactly as the #1646 test does, so the per-request
// WithNamedLock advisory lock is what has to serialize them -- there is no shared
// in-process mutex left to accidentally paper over the gap.
func TestConcurrency_ApproveAccessRequestWithExpiry_CrossReplicaPostgres_SubThresholdStraddle(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(dualControlModels...))
	setupStorage := localstore.NewLocalStorage(setupDB)
	setupCore := NewKeyorixCore(setupStorage)
	setupCore.SetBootstrapToken("dual-control-straddle-token")
	setupCore.SetDualControlPolicy(2)
	ctx := context.Background()

	bootRes, err := setupCore.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "dual-control-straddle-token",
	})
	require.NoError(t, err)
	projectID := bootRes.Project.ID

	target, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dcs-target", Email: "dcs-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	approverA, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dcs-approver-a", Email: "dcs-approver-a@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	approverB, err := setupCore.CreateUser(ctx, &CreateUserRequest{
		Username: "dcs-approver-b", Email: "dcs-approver-b@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	// Grant ceiling: each approver must already hold project_viewer's own
	// permissions at this project to be eligible to approve granting it to someone
	// else (authz.go). Same fixture requirement as the #1646 race test.
	viewerRoleForApprovers, err := setupCore.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	for _, u := range []*models.User{approverA, approverB} {
		require.NoError(t, setupCore.Storage().AssignRole(ctx, u.ID, viewerRoleForApprovers.ID, Scope{ProjectID: projectID}))
	}

	req, err := setupCore.RequestProjectAccess(ctx, projectID, target.ID, "project_viewer", "need read access")
	require.NoError(t, err)

	// No approval is seeded: the request sits at received=0, required=2. A and B
	// racing next each independently compute received=1 -- one short of the
	// threshold -- which is precisely the straddle #1646's seeding skipped.
	dbA := pgOpen(t, dsn)
	coreA := NewKeyorixCore(localstore.NewLocalStorage(dbA))
	coreA.SetDualControlPolicy(2)
	dbB := pgOpen(t, dsn)
	coreB := NewKeyorixCore(localstore.NewLocalStorage(dbB))
	coreB.SetDualControlPolicy(2)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, errA = coreA.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, approverA.ID, 0, "", 0)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, errB = coreB.ApproveAccessRequestWithExpiry(ctx, projectID, req.ID, approverB.ID, 0, "", 0)
	}()
	close(start)
	wg.Wait()

	t.Logf("approver A result: %v", errA)
	t.Logf("approver B result: %v", errB)

	// Both approvals are legitimate and distinct: neither may be rejected. Under
	// the lock one records the partial sign-off and the other, reading it, crosses
	// the threshold and finalizes.
	require.NoError(t, errA, "approver A's legitimate sign-off was rejected")
	require.NoError(t, errB, "approver B's legitimate sign-off was rejected")

	// Verify from a fresh connection, independent of either racing replica.
	verifierDB := pgOpen(t, dsn)
	verifier := localstore.NewLocalStorage(verifierDB)

	finalReq, err := verifier.GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	approvals, err := verifier.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	viewerRole, err := verifier.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	grantCount := countUserRoleGrants(t, verifierDB, target.ID, viewerRole.ID, projectID)
	t.Logf("final state=%s approvals=%d grants=%d", finalReq.State, len(approvals), grantCount)

	// (1) The defect itself: two distinct approvers satisfied a 2-of-N policy, so
	// the request must be APPROVED. Left pending, it now needs a third approver
	// policy never asked for and will lapse at its TTL instead of granting.
	assert.Equal(t, AccessRequestApproved, finalReq.State,
		"SUB-THRESHOLD STRADDLE: both racers recorded a partial approval and neither crossed the threshold -- a 2-of-N request with 2 distinct approvals is stranded pending, silently requiring a 3rd approver")

	// (2) The grant the approvals authorized must actually be live, exactly once.
	assert.Equal(t, 1, grantCount,
		"SUB-THRESHOLD STRADDLE: the target does not hold the granted role exactly once after a fully-approved 2-of-N request")

	// (3) The evidence trail must show exactly the two sign-offs that happened --
	// no inflation, and no missing K-th record.
	assert.Equal(t, 2, len(approvals),
		"SUB-THRESHOLD STRADDLE: the recorded approval count does not match the two distinct sign-offs that occurred")
}
