package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmailPartialUniqueIndex pins #117: users.email carried no DB constraint at
// all — two concurrent CreateUser calls with the same address could both
// succeed, leaving duplicate-email accounts with ambiguous SSO/SCIM/password-
// reset targeting. The partial unique index rejects a second LIVE user with the
// same email, while still allowing a soft-deleted user's email to be reused
// (matching the username precedent) and allowing multiple users with NO email
// (empty is excluded from the constraint).
func TestEmailPartialUniqueIndex(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "email-index.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	alice, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@x.io", IsActive: true})
	require.NoError(t, err)

	// A second LIVE user with the same email is rejected.
	_, err = st.CreateUser(ctx, &models.User{Username: "alice2", Email: "alice@x.io", IsActive: true})
	require.Error(t, err, "two live users may not share an email")

	// Soft-deleting alice frees her email for reuse.
	require.NoError(t, st.DeleteUser(ctx, alice.ID))
	reAlice, err := st.CreateUser(ctx, &models.User{Username: "alice-again", Email: "alice@x.io", IsActive: true})
	require.NoError(t, err, "a soft-deleted user's email must be reusable on re-provisioning")
	assert.NotEqual(t, alice.ID, reAlice.ID)

	// Multiple LIVE users with NO email at all is allowed (empty is excluded).
	_, err = st.CreateUser(ctx, &models.User{Username: "svc-1", Email: "", IsActive: true})
	require.NoError(t, err)
	_, err = st.CreateUser(ctx, &models.User{Username: "svc-2", Email: "", IsActive: true})
	require.NoError(t, err, "multiple users with no email must not collide with each other")
}

// TestExternalIDPartialUniqueIndex pins #117: external_id was indexed but not
// unique — two DIFFERENT users sharing the same non-empty external_id makes SSO/
// SCIM identity resolution (GetUserByExternalID) ambiguous. Native (local)
// accounts, which always have an empty external_id, must not collide with each
// other.
func TestExternalIDPartialUniqueIndex(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "external-id-index.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = st.CreateUser(ctx, &models.User{Username: "bob", Email: "bob@x.io", ExternalID: "okta|bob", IsActive: true})
	require.NoError(t, err)

	// A second LIVE user claiming the same external_id is rejected.
	_, err = st.CreateUser(ctx, &models.User{Username: "bob2", Email: "bob2@x.io", ExternalID: "okta|bob", IsActive: true})
	require.Error(t, err, "two live users may not share a non-empty external_id")

	// Multiple native (local) users with an empty external_id must not collide.
	_, err = st.CreateUser(ctx, &models.User{Username: "native-1", Email: "n1@x.io", ExternalID: "", IsActive: true})
	require.NoError(t, err)
	_, err = st.CreateUser(ctx, &models.User{Username: "native-2", Email: "n2@x.io", ExternalID: "", IsActive: true})
	require.NoError(t, err, "multiple native users with no external_id must not collide with each other")
}
