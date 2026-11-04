package handlers

// audit_checkpoint_refusal_class_test.go — ERR-CLASS-LEFTOVERS-1 item 4.
//
// WriteAuditCheckpoint decided whether a core error is safe to show the client by looking
// for "refusing to checkpoint" in err.Error(). It now asks errors.Is(err,
// core.ErrAuditCheckpointRefused), as the gRPC service does: a real refusal is surfaced
// as a 409 with its reason, and any other error (here a storage error that happens to
// contain the phrase) gets the generic body with the detail in the log only.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

func TestWriteAuditCheckpoint_RefusalClassIsBySentinelNotText(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db := sqlitetest.Open(t, "kxhandlers_cp_class_")
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.SystemMetadata{}))
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1")

	t.Run("a storage error that echoes the phrase is not shown to the client", func(t *testing.T) {
		faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
		leak := errors.New("pq: refusing to checkpoint: password authentication failed for user \"keyorix_prod\" at db-primary.internal:5432")
		faulty.Arm(&faultstorage.FaultSpec{Method: "WithAuditCheckpointLock", NthCall: 1, Kind: faultstorage.KindError, Err: leak})
		c := core.NewKeyorixCore(faulty)
		c.SetAuditCheckpointKey(key, "v1")
		h := NewAuditHandler(c)
		logs := captureLogBuf(t)

		w := httptest.NewRecorder()
		h.WriteAuditCheckpoint(w, withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil)))

		require.True(t, faulty.Fired(), "the checkpoint lock must be reached")
		assert.Equal(t, http.StatusConflict, w.Code)
		for _, leaked := range []string{"keyorix_prod", "db-primary", "5432", "password authentication", "refusing to checkpoint"} {
			assert.NotContains(t, w.Body.String(), leaked, "the response must not carry the raw error text")
		}
		assert.Contains(t, logs.String(), "db-primary.internal", "the detail is logged")
	})

	t.Run("a real refusal keeps its reason", func(t *testing.T) {
		tru := true
		require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.read", Description: "tampered", Success: &tru,
			ActorType: "user", EntryHash: "deadbeefdeadbeefdeadbeefdeadbeef"}).Error)
		require.NoError(t, db.Create(&models.AuditEvent{EventType: "secret.read", Description: "second", Success: &tru,
			ActorType: "user", EntryHash: "cafecafecafecafecafecafecafecafe", PrevHash: "wrongwrongwrongwrongwrongwrongwrong"}).Error)
		c := core.NewKeyorixCore(store.NewLocalStorage(db))
		c.SetAuditCheckpointKey(key, "v1")
		h := NewAuditHandler(c)

		w := httptest.NewRecorder()
		h.WriteAuditCheckpoint(w, withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil)))

		assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "refusing to checkpoint", "the operator is told why")
	})
}
