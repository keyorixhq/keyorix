package handlers

// pat_revoke_write_fault_test.go — STORAGE-ERR-CLASS-5 item 3.
//
// DELETE /auth/tokens/{id} answered 404 "Token not found" for EVERY error after the
// token read, including a failed revoke write: the caller was told the token was gone
// while it still authenticated. Only a token that does not exist (or is another user's)
// is 404; a failed write is a server error and the token is still there.

import (
	"context"
	"errors"
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

// failingTxStorage refuses to open a transaction, which is where RevokeOwnPAT writes.
func failingTxStorage(inner corestorage.Storage) corestorage.Storage {
	return storagetest.Hooked(inner, &storagetest.StoreHooks{
		WithTransaction: func(corestorage.Storage, context.Context, func(corestorage.Storage) error) error {
			return errors.New("driver: could not begin transaction")
		},
	})
}

func TestRevokePAT_WriteFaultIsNot404(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxpatrevokewrite_")
	require.NoError(t, db.AutoMigrate(kxstorage.AllModels()...))
	// withUserCtx authenticates as user 1.
	mine := &models.PersonalAccessToken{UserID: 1, Name: "mine", TokenHash: "pat-write-fault-mine", TokenPrefix: "kx_pat_"}
	require.NoError(t, db.Create(mine).Error)
	theirs := &models.PersonalAccessToken{UserID: 2, Name: "theirs", TokenHash: "pat-write-fault-theirs", TokenPrefix: "kx_pat_"}
	require.NoError(t, db.Create(theirs).Error)

	patH := NewPATHandler(core.NewKeyorixCore(failingTxStorage(store.NewLocalStorage(db))))

	w := httptest.NewRecorder()
	patH.RevokePAT(w, suReq(http.MethodDelete, "", map[string]string{"id": suID(mine.ID)}))
	assert.Equal(t, http.StatusInternalServerError, w.Code, "a failed revoke write must not read as \"not found\": %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "driver:", "the driver cause must not reach the client")

	// A token that does not exist, and another user's token, stay the one uniform 404.
	for name, id := range map[string]string{"absent": "9999999", "another user's": suID(theirs.ID)} {
		w = httptest.NewRecorder()
		patH.RevokePAT(w, suReq(http.MethodDelete, "", map[string]string{"id": id}))
		assert.Equal(t, http.StatusNotFound, w.Code, "%s token: %s", name, w.Body.String())
	}
}
