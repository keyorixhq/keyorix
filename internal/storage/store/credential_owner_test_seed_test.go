package store

// credential_owner_test_seed_test.go — shared fixture support for #2701.
//
// CreateSession / CreatePersonalAccessToken / RotateSession now re-read their
// owning user inside the insert's transaction and roll back if it is not a live,
// login-capable account (requireLiveCredentialOwner). Several fixtures in this
// package created credentials with no `users` table at all — a state production
// cannot be in, since a session or PAT whose owner does not exist can never
// authenticate (ValidateSessionToken / ValidatePATToken both GetUser first). The
// fixtures only got away with it because the insert used to be unconditional.
//
// Called PER TEST, by the tests that actually create a credential — NOT from the
// shared store fixtures. Seeding in a fixture was the obvious first move and it
// was wrong: these helpers are shared with tests that COUNT or LIST users
// (TestListUsers_*, TestStats_GetStatsAndHealthCheck asserts "GetStats on empty
// tables"), and pre-seeding changed their expected totals. A fixture fix must
// not perturb unrelated tests to satisfy its own.
//
// This is deliberately a FIXTURE fix rather than a weakening of the re-check:
// the re-check's whole job is to refuse a credential whose owner is not usable,
// and "the owner does not exist" is the strongest case of that. Loosening it to
// tolerate a missing owner would make the guard pass on exactly the shape it
// exists to catch.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// credentialOwnerSeedIDs is the user-id range the credential tests in this
// package reference (they hardcode small ids like 1, 2, 7). Seeded generously so
// a new test picking an id in range needs no change here.
const credentialOwnerSeedIDs = 20

// seedCredentialOwners migrates `users` and inserts active, login-capable rows
// for ids 1..credentialOwnerSeedIDs, so a fixture that creates a session or PAT
// for "user 1" has a user 1 to own it. Idempotent: safe to call on a DB that
// already has the table or the rows.
func seedCredentialOwners(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	for id := uint(1); id <= credentialOwnerSeedIDs; id++ {
		var n int64
		require.NoError(t, db.Model(&models.User{}).Where("id = ?", id).Count(&n).Error)
		if n > 0 {
			continue
		}
		u := &models.User{
			ID:           id,
			Username:     credentialOwnerName(id),
			Email:        credentialOwnerName(id) + "@example.test",
			IsActive:     true,
			AccountState: "active",
		}
		u.UsernameFolded = u.Username
		u.EmailFolded = u.Email
		require.NoError(t, db.Create(u).Error)
	}
}

func credentialOwnerName(id uint) string {
	return "cred-owner-" + string(rune('a'+(id-1)%26)) + "-" + itoaUint(id)
}

func itoaUint(n uint) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
