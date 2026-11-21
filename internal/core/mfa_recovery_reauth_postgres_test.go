package core

// mfa_recovery_reauth_postgres_test.go — #4224 cross-replica: two "replicas"
// (own *gorm.DB connection, own LocalStorage, own KeyorixCore, so no shared
// loginFailureMu) present the SAME unused recovery code to DisableMFA or
// RegenerateMFARecoveryCodes at once. Only the LockUserForUpdate row lock and
// the conditional ConsumeMFARecoveryCode can serialize them; exactly one may
// succeed. Skips without KEYORIX_TEST_PG_DSN.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

const recoveryReauthPGTrials = 8

func TestRecoveryReauth_ConcurrentSameCode_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.InitializeForTesting())
	base := pgTestDSN(t)
	for _, op := range []string{"disable", "regenerate"} {
		for trial := range recoveryReauthPGTrials {
			dsn := pgIsolatedSchemaDSN(t, base)
			setup := pgOpen(t, dsn)
			require.NoError(t, setup.AutoMigrate(&models.User{}, &models.MFASecret{}, &models.MFARecoveryCode{},
				&models.Session{}, &models.AuditEvent{}, &models.PendingAuditEvent{}, &models.SystemMetadata{},
				&models.MFAStepUpGrant{}, &models.MFAStepupToken{}))
			user := models.User{Username: "rc-user", UsernameFolded: "rc-user", IsActive: true, AccountState: AccountActive, MFAEnabled: true}
			require.NoError(t, setup.Create(&user).Error)
			require.NoError(t, setup.Create(&models.MFASecret{UserID: user.ID, SecretEnc: []byte("x"), Activated: true}).Error)
			codes, hashes, err := generateRecoveryCodes(2)
			require.NoError(t, err)
			for _, h := range hashes {
				require.NoError(t, setup.Create(&models.MFARecoveryCode{UserID: user.ID, CodeHash: h}).Error)
			}
			closePG(setup)

			dbA, dbB := pgOpen(t, dsn), pgOpen(t, dsn)
			cores := []*KeyorixCore{
				NewKeyorixCore(localstore.NewLocalStorage(dbA)),
				NewKeyorixCore(localstore.NewLocalStorage(dbB)),
			}
			ctx := context.Background()
			errs := make([]error, len(cores))
			start := make(chan struct{})
			done := make(chan int)
			for i, c := range cores {
				go func() {
					<-start
					if op == "disable" {
						errs[i] = c.DisableMFA(ctx, user.ID, codes[0], "")
					} else {
						_, errs[i] = c.RegenerateMFARecoveryCodes(ctx, user.ID, codes[0])
					}
					done <- i
				}()
			}
			close(start)
			<-done
			<-done
			closePG(dbA)
			closePG(dbB)

			ok := 0
			for _, e := range errs {
				require.False(t, isConnectionError(e), "%s trial %d: connection failure, not a verdict: %v", op, trial, e)
				if e == nil {
					ok++
				}
			}
			assert.Equal(t, 1, ok, "%s trial %d: exactly one replica may use the code (errors: %v)", op, trial, errs)
		}
	}
}
