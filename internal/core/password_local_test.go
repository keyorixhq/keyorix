// password_local_test.go — regression coverage for #484: applyNewPassword (shared by
// self-service ChangePassword and the setup-token consume flow) must persist via the
// narrow SetPasswordHash/SetAccountState primitives, not the generic UpdateUser.
// Originally paired with a RemoteStorage hard-fail case (RemoteStorage could never
// carry password_hash over the wire); that half was deleted in ADR-108 Phase 6
// step 14b-2 along with RemoteStorage itself. This is what's left: proof the
// LocalStorage path still works correctly.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestChangePassword_LocalStoragePersistsHashAndClearsRestriction proves LocalStorage
// performs the real column update via SetPasswordHash/SetAccountState.
func TestChangePassword_LocalStoragePersistsHashAndClearsRestriction(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.PersonalAccessToken{}, &models.PasswordHistory{}))
	oldHash, err := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.User{
		ID: 1, Username: "carol", PasswordHash: string(oldHash), AccountState: AccountPasswordResetRequired,
	}).Error)

	c := &KeyorixCore{
		storage:        store.NewLocalStorage(db),
		now:            func() time.Time { return time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC) },
		passwordPolicy: DefaultPasswordPolicy(),
	}

	const newPw = "Brandnew#Passw0rd!"
	require.NoError(t, c.ChangePassword(context.Background(), 1, "oldpassword", newPw, ""))

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(newPw)),
		"the new hash must actually be persisted, not silently dropped")
	assert.Equal(t, AccountActive, u.AccountState, "restricted state must clear to active")
}
