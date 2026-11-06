package handlers

// pat_revoke_gone_midway_test.go -- CORE-FAULT-TAILS-1 item 3: a token deleted between
// RevokeOwnPAT's ownership read and its revoke write (the retention purge, an
// out-of-band delete) is gone: 404, not the 500 of a failed write.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestRevokePAT_DeletedMidRevokeIs404(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxpatrevokegone_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	// suReq authenticates as user 1.
	mine := &models.PersonalAccessToken{UserID: 1, Name: "mine", TokenHash: "pat-gone-midway", TokenPrefix: "kx_pat_"}
	require.NoError(t, db.Create(mine).Error)
	deleteFirst := storagetest.Hooked(store.NewLocalStorage(db), &storagetest.StoreHooks{
		WithTransaction: func(next corestorage.Storage, ctx context.Context, fn func(corestorage.Storage) error) error {
			require.NoError(t, db.Unscoped().Delete(&models.PersonalAccessToken{}, mine.ID).Error)
			return next.WithTransaction(ctx, fn)
		},
	})

	w := httptest.NewRecorder()
	NewPATHandler(core.NewKeyorixCore(deleteFirst)).RevokePAT(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(mine.ID)}))
	assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
}
