// remote_storage_misc_proxy_atomic_test.go — the concurrency/atomicity
// regression test for #531's CreateUserWithRoleGrants fix, the one sub-item of
// the four that needed a genuinely NEW atomic storage primitive (not a naive
// multi-call proxy) — see remote_users.go's CreateUserWithRoleGrants doc and
// server/http/handlers/misc_remote_proxy.go's CreateUserWithRoleGrantsProxy doc
// for the full atomicity analysis. Mirrors
// TestRemoteStorageMachineIdentities_TransitionState_ConcurrentRaceIsSerialized_RealServer's
// structure: N goroutines on the SAME downstream (storage.type: remote)
// core.KeyorixCore race a create that can only ever have ONE winner (here: N
// creates racing the identical email), proving the atomic guarantee holds
// under real concurrent load against a REAL upstream server, not a mock.
package http

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorageCreateUserWithRoleGrants_ConcurrentDuplicateEmailRace_RealServer
// fires N concurrent CreateUserWithRoleGrants calls at the SAME email (each
// with a distinct username, each requesting TWO role grants) over real HTTP
// against the real upstream router, and asserts:
//
//  1. Exactly ONE create wins (the real uniq_users_email_active partial unique
//     index — the same DB-level guarantee CreateUser's #117 race fix relies
//     on — still serializes concurrent creates correctly via
//     storage.type: remote, not just sequentially).
//  2. The winner's user row carries BOTH of its role grants — the atomic
//     primitive's core guarantee.
//  3. Every LOSING attempt leaves NO trace at all: no user row under its own
//     (unique) username, proving the transaction genuinely rolled back rather
//     than leaving a half-provisioned account behind. A naive "create user,
//     then POST each grant separately" proxy would not exhibit this failure
//     mode under a duplicate-email race specifically (the loser's user INSERT
//     itself would still fail atomically even naively) — the real risk a
//     naive proxy reopens is a grant-insert failure LATER in the sequence
//     leaving an already-committed user with partial grants, which is why
//     TestRemoteStorageCreateUserWithRoleGrants_RealServer above additionally
//     proves both grants land together on an uncontested create.
func TestRemoteStorageCreateUserWithRoleGrants_ConcurrentDuplicateEmailRace_RealServer(t *testing.T) {
	upstream, _, srv, _, _ := newUpstreamDownstreamForMiscProxy(t)
	ctx := context.Background()

	// See TestRemoteStorageCreateUserWithRoleGrants_RealServer's comment
	// (remote_storage_misc_proxy_test.go): CreateUserWithRoleGrantsProxy
	// (#G79) requires a real authenticated actor, not a node credential, to
	// pass its escalation-ceiling/SoD authority check.
	adminToken := createTestToken(t, upstream)
	downstream := newDownstreamRemoteStorage(t, srv, adminToken)

	viewerRole, err := upstream.Storage().GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	adminRole, err := upstream.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)

	const n = 8
	const raceEmail = "atomic-race@example.com"
	var successCount atomic.Int64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			user := &models.User{
				Username:     fmt.Sprintf("atomic-race-user-%d", i),
				Email:        raceEmail,
				DisplayName:  "Atomic Race",
				PasswordHash: "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0", // 60 chars: isPlausibleBcryptHash requires exactly 60
				IsActive:     true,
				AccountState: "active",
			}
			grants := []corestorage.RoleGrant{{RoleID: viewerRole.ID}, {RoleID: adminRole.ID}}
			if _, err := downstream.Storage().CreateUserWithRoleGrants(ctx, user, grants); err == nil {
				successCount.Add(1)
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int64(1), successCount.Load(),
		"exactly one concurrent create must win the duplicate-email race — the rest must cleanly lose, never a double create")

	// Exactly one of the N candidate usernames exists on the upstream, and it
	// carries BOTH role grants.
	var winners int
	for i := 0; i < n; i++ {
		username := fmt.Sprintf("atomic-race-user-%d", i)
		u, err := upstream.Storage().GetUserByUsername(ctx, username)
		if err != nil {
			continue // this racer lost — must have left no trace, checked below
		}
		winners++
		roleIDs, err := upstream.Storage().GetUserRoleIDsAt(ctx, u.ID, corestorage.Scope{})
		require.NoError(t, err)
		assert.Contains(t, roleIDs, viewerRole.ID, "the winner must carry BOTH of its intended role grants, not a partial subset")
		assert.Contains(t, roleIDs, adminRole.ID, "the winner must carry BOTH of its intended role grants, not a partial subset")
	}
	assert.Equal(t, 1, winners, "exactly one of the N candidate usernames must have been persisted")
}
