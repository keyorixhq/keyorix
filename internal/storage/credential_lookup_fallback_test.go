package storage

// credential_lookup_fallback_test.go — #3464: a test that really reaches the
// GORM fallback of GetMachineIdentityCredentialWithIdentityStateByHash.
//
// The method answers from the folded statement or the hand-written prepared
// statement (credential_lookup_raw.go) and only otherwise runs the GORM query with
// modelColumns' explicit column list. The only production caller reads through the
// root store, so the fallback runs only on a store without rawStmts: a
// transaction-scoped clone (WithTransaction). Nothing reached it:
// TestCredentialLookupRaw_MatchesGORM_Fuzz compares the raw path with a verbatim
// copy of the pre-H3 query (`SELECT c.*`), not with the production fallback, and
// every other test of the method calls the root store. A coverage profile of
// local_machine_credentials.go under `-tags nplus1` showed the fallback block at
// zero hits.
//
// The fallback is the branch that must survive a schema one column ahead
// (docs/rolling-upgrade-columns.md): it is where an explicit column list matters
// and where a `SELECT *` regression would hide. This test lives in package
// storage, not store, because only the factory's migration runs the nplus1 hook
// that adds the unknown column to every table; store's own tests build their
// schema with AutoMigrate. Run it as
//
//	go test -tags nplus1 -run TestCredentialLookup_TxScopedFallback ./internal/storage/
//
// and it is the same test, with the extra column present, as in a plain run.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestCredentialLookup_TxScopedFallback(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	st, err := NewStorageFactory().CreateStorage(&config.Config{
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: sqlitetest.FactoryPath(t, "credfallback_")}},
	})
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "%T", st)
	t.Cleanup(func() { _ = ls.Close() })
	db := ls.DB()

	var mu sync.Mutex
	var stmts []string
	record := func(d *gorm.DB) {
		mu.Lock()
		defer mu.Unlock()
		stmts = append(stmts, d.Statement.SQL.String())
	}
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("credfallback:q", record))
	require.NoError(t, db.Callback().Row().After("gorm:row").Register("credfallback:row", record))
	// ranGORMLookup: the GORM statement of the fallback, the only one that reads
	// the credential joined with its identity under the alias `c`.
	ranGORMLookup := func(fn func()) bool {
		mu.Lock()
		stmts = nil
		mu.Unlock()
		fn()
		mu.Lock()
		defer mu.Unlock()
		for _, s := range stmts {
			if strings.Contains(s, "machine_identity_credentials AS c") && strings.Contains(s, "machine_identities AS m") {
				return true
			}
		}
		return false
	}

	mi := &models.MachineIdentity{Name: "fallback-identity", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(mi).Error)
	expires := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	want := &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID, Name: "fallback-cred", TokenHash: "fallback-hash", TokenPrefix: "kx_machine_fall",
		AllowedCIDRs: `["10.0.0.0/8"]`, ExpiresAt: &expires, Classification: "confidential",
	}
	require.NoError(t, db.Create(want).Error)

	ctx := context.Background()
	require.NoError(t, db.Model(&models.MachineIdentity{}).Where("id = ?", mi.ID).Update("state", "suspended").Error)

	assertSame := func(t *testing.T, got *models.MachineIdentityCredential, state string) {
		t.Helper()
		require.Equal(t, "suspended", state)
		require.Equal(t, want.ID, got.ID)
		require.Equal(t, mi.ID, got.MachineIdentityID)
		require.Equal(t, want.Name, got.Name)
		require.Equal(t, want.TokenHash, got.TokenHash)
		require.Equal(t, want.TokenPrefix, got.TokenPrefix)
		require.Equal(t, want.AllowedCIDRs, got.AllowedCIDRs)
		require.Equal(t, want.Classification, got.Classification)
		require.False(t, got.Revoked)
		require.NotNil(t, got.ExpiresAt)
		require.True(t, expires.Equal(*got.ExpiresAt), "ExpiresAt %v != %v", *got.ExpiresAt, expires)
	}

	t.Run("root store answers from the prepared statement, not GORM", func(t *testing.T) {
		var got *models.MachineIdentityCredential
		var state string
		ran := ranGORMLookup(func() {
			var err error
			got, state, err = ls.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, want.TokenHash)
			require.NoError(t, err)
		})
		require.False(t, ran, "the root store must take the raw path; if it runs the GORM query this test no longer separates the two paths")
		assertSame(t, got, state)
	})

	t.Run("tx-scoped store runs the GORM fallback and answers the same", func(t *testing.T) {
		require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
			var got *models.MachineIdentityCredential
			var state string
			ran := ranGORMLookup(func() {
				var err error
				got, state, err = tx.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, want.TokenHash)
				require.NoError(t, err)
			})
			require.True(t, ran, "a transaction-scoped store has no prepared statement: the GORM fallback must run")
			assertSame(t, got, state)
			return nil
		}))
	})

	t.Run("tx-scoped store: no such hash is the not-found error", func(t *testing.T) {
		_, _, rootErr := ls.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, "no-such-hash")
		require.Error(t, rootErr)
		require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
			_, _, err := tx.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, "no-such-hash")
			require.Error(t, err)
			require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "the fallback wraps the row-not-found error: %v", err)
			require.Equal(t, rootErr.Error()[:strings.Index(rootErr.Error(), ":")], err.Error()[:strings.Index(err.Error(), ":")],
				"root and fallback share the same caller-visible not-found prefix")
			return nil
		}))
	})
}
