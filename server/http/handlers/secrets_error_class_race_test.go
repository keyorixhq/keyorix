// secrets_error_class_race_test.go — the "nothing to restore / deleted between
// the read and the write" refusals of the secret routes answer 404 from the KIND
// of failure, in every locale (ERRLOSS-SENTINELS-1 task 3.3, review
// REVIEW-3787-DEEP-1 F1/F2). These returns used to be untyped
// fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil)): English matched the
// handler's text check, a translated locale did not, and once the handlers
// matched on the sentinel instead they became 500 everywhere. Like the other
// locale tests these flip the process-global localizer and are deliberately NOT
// t.Parallel().
package handlers

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// softDeleteSecretBeforeUpdate arms a one-shot hook that soft-deletes the secret
// right before the next column-scoped UPDATE of secret_nodes, so the write
// matches no row: the "deleted between the read and the write" race, made
// deterministic.
func softDeleteSecretBeforeUpdate(t *testing.T, db *gorm.DB, secretID uint) {
	t.Helper()
	const name = "race:soft-delete-secret"
	fired := false
	require.NoError(t, db.Callback().Update().Before("gorm:update").Register(name, func(tx *gorm.DB) {
		if fired || tx.Statement.Table != "secret_nodes" {
			return
		}
		fired = true
		require.NoError(t, tx.Session(&gorm.Session{NewDB: true}).
			Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now(), secretID).Error)
	}))
	t.Cleanup(func() { _ = db.Callback().Update().Remove(name) })
}

// Restoring a secret that is not deleted (a double click, or two operators) is
// 404 in every locale, as the OpenAPI document says; never a 500.
func TestSecretRestore_LiveSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, fx := newSecretsHandlerWithDB(t, lang)
			w := secretsDo(h.RestoreSecret, http.MethodPost, "", fx.id(), secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
	}
}

// Restoring a secret that never existed is 404 too.
func TestSecretRestore_MissingSecretIs404InEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			h, _, _ := newSecretsHandlerWithDB(t, lang)
			w := secretsDo(h.RestoreSecret, http.MethodPost, "", secretsMissingID, secretsAdminID)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
		})
	}
}

// A storage failure while restoring is a 5xx, never a 404.
func TestSecretRestore_StorageFaultIs5xxInEveryLocale(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), &faultstorage.FaultSpec{
				Method: "GetSecretIncludingDeleted", NthCall: 1, Kind: faultstorage.KindError,
				Err: errors.New("injected: GetSecretIncludingDeleted"),
			})
			fh, err := NewSecretHandler(core.NewKeyorixCore(faulty))
			require.NoError(t, err)
			w := secretsDo(fh.RestoreSecret, http.MethodPost, "", fx.id(), secretsAdminID)
			require.True(t, faulty.Fired())
			assert.GreaterOrEqual(t, w.Code, 500, "body: %s", w.Body.String())
			assert.NotContains(t, w.Body.String(), "injected")
		})
	}
}

// The secret is deleted after core read it and before the column write: the
// write matches no row, and the route answers 404 (classify, and update with a
// value, which takes the versioned path).
func TestSecretRoutes_DeletedBetweenReadAndWriteIs404InEveryLocale(t *testing.T) {
	routes := []struct {
		name string
		call func(h *SecretHandler, id string) int
	}{
		{"ClassifySecret", func(h *SecretHandler, id string) int {
			return secretsDo(h.ClassifySecret, http.MethodPatch, `{"classification":"internal"}`, id, secretsAdminID).Code
		}},
		{"UpdateSecretWithValue", func(h *SecretHandler, id string) int {
			return secretsDo(h.UpdateSecret, http.MethodPut, `{"value":"v2"}`, id, secretsAdminID).Code
		}},
	}
	for _, lang := range errorClassLocales {
		for _, rt := range routes {
			t.Run(lang+"/"+rt.name, func(t *testing.T) {
				h, db, fx := newSecretsHandlerWithDB(t, lang)
				softDeleteSecretBeforeUpdate(t, db, fx.secretID)
				assert.Equal(t, http.StatusNotFound, rt.call(h, fx.id()))
			})
		}
	}
}

// Storage level: the three typed returns match the sentinel under errors.Is, so
// no caller has to read the message.
func TestLocalStorage_NothingToDeleteOrRestoreIsTypedNotFound(t *testing.T) {
	for _, lang := range errorClassLocales {
		t.Run(lang, func(t *testing.T) {
			_, db, fx := newSecretsHandlerWithDB(t, lang)
			ls := store.NewLocalStorage(db)
			ctx := context.Background()

			// restore of a live secret: no deleted row matches
			err := ls.RestoreSecret(ctx, fx.secretID)
			require.Error(t, err)
			assert.ErrorIs(t, err, coreStorage.ErrSecretNotFound, "restore of a live secret")

			// restore of an id that never existed
			err = ls.RestoreSecret(ctx, 99999)
			require.Error(t, err)
			assert.ErrorIs(t, err, coreStorage.ErrSecretNotFound, "restore of a missing secret")

			// delete of an id that never existed: the transaction's delete matched no row
			err = ls.DeleteSecret(ctx, 99999)
			require.Error(t, err)
			assert.ErrorIs(t, err, coreStorage.ErrSecretNotFound, "delete of a missing secret")
		})
	}
}
