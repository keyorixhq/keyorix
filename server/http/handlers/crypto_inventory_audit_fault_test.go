package handlers

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #3716 (audit-before-disclosure): the crypto inventory names where every key
// lives, so a read whose compliance.crypto_inventory_read row did not land must
// disclose nothing: 503 with the audit-unavailable code and Retry-After, and not
// one byte of the inventory (no asset id, no key location). It used to be built,
// "audited" through a writer that swallowed the failure, and sent anyway.
func TestCryptoInventoryHandler_AuditWriteFails_DisclosesNothing(t *testing.T) {
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		for _, q := range []string{"", "?format=cbom"} {
			t.Run(kind.String()+q, func(t *testing.T) {
				f := newCryptoInvFixture(t)
				faulty := faultstorage.NewFaultyStorage(store.NewLocalStorage(f.db), &faultstorage.FaultSpec{
					Method: "LogAuditEvent", NthCall: 1, Kind: kind, Err: errors.New("injected: audit store down"),
				})
				f.h = MakeCryptoInventoryHandler(f.cfg, core.NewKeyorixCore(faulty))

				w := f.get(t, q, true)
				require.True(t, faulty.Fired(), "the audit write was never attempted")
				require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
				assert.NotEmpty(t, w.Header().Get("Retry-After"))
				assert.NotContains(t, w.Header().Get("Content-Type"), "cyclonedx", "no CBOM headers on a refused read")
				assert.Empty(t, w.Header().Get("Content-Disposition"))
				body := w.Body.String()
				assert.Contains(t, body, auditUnavailableCode)
				for _, leak := range []string{
					f.cfg.Storage.Encryption.DEKPath, filepath.Base(f.cfg.Storage.Encryption.DEKPath),
					f.cfg.Server.HTTP.TLS.CertFile, "tls.http", "ECDSA", "bomFormat", "assets", "quantum",
				} {
					assert.False(t, strings.Contains(body, leak), "a refused read disclosed %q: %s", leak, body)
				}

				var n int64
				require.NoError(t, f.db.Model(&models.AuditEvent{}).Where("event_type = ?", core.EventCryptoInventoryRead).Count(&n).Error)
				assert.Zero(t, n)
			})
		}
	}
}
