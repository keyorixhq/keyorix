package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #2951 review (3): the JSON export (GET /api/v1/audit/export) carries the
// ADR-029 chain links, so an off-box verifier re-derives each entry_hash from the
// exported fields. actor_type is a hash input: it must be exported as STORED,
// never as the displayed kind, or every row whose kind differs from its stored
// value (a scheduler row storing "user" with no actor, displayed "system") fails
// re-verification. The displayed kind travels separately as actor_kind_display.
//
// This test re-hashes every exported row with the independent verifier
// (auditverify.ComputeEntryHash) and checks the chain links. Rows here are not
// impersonated: the export carries impersonated_by/acting_as as usernames, not
// the hashed ids, so an impersonated row cannot be re-hashed from the export
// (pre-existing, unchanged by this test).
func TestExportAuditLogs_RehashesWithStoredActorTypeAndShowsKindSeparately(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))
	alice := &models.User{Username: "alice", Email: "alice@example.com"}
	require.NoError(t, db.Create(alice).Error)

	ls := store.NewLocalStorage(db)
	ctx := context.Background()
	tru, fls := true, false
	pid := uint(3)
	seed := []struct {
		e    models.AuditEvent
		kind string
	}{
		{models.AuditEvent{EventType: "secret.read", ActorType: "user", UserID: &alice.ID, ProjectID: &pid, IPAddress: "192.0.2.1", Success: &tru}, "user"},
		{models.AuditEvent{EventType: "secret.auto_rotated", ActorType: "user", ProjectID: &pid, Success: &tru, Description: "scheduler"}, "system"},
		{models.AuditEvent{EventType: "data.retention_purged", ActorType: "system", Success: &tru}, "system"},
		{models.AuditEvent{EventType: "auth.login_failed", ActorType: "user", IPAddress: "198.51.100.7", Success: &fls, Description: "Failed login attempt for username: bob"}, "user"},
		{models.AuditEvent{EventType: "secret.updated", ActorType: "user", UserID: &alice.ID, Success: &tru, Diff: `{"name":{"from":"a","to":"b"}}`}, "user"},
	}
	base := time.Now().UTC()
	for i := range seed {
		e := seed[i].e
		e.EventTime = base.Add(time.Duration(i) * time.Second)
		require.NoError(t, ls.LogAuditEvent(ctx, &e))
	}

	h := NewAuditHandler(core.NewKeyorixCore(ls))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/export", nil)))
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			Events []struct {
				ID               uint64          `json:"id"`
				EventType        string          `json:"event_type"`
				Timestamp        time.Time       `json:"timestamp"`
				UserID           *uint64         `json:"user_id"`
				ProjectID        *uint64         `json:"project_id"`
				SecretID         *uint64         `json:"secret_id"`
				Description      string          `json:"description"`
				IPAddress        string          `json:"ip_address"`
				ActorType        string          `json:"actor_type"`
				ActorKindDisplay string          `json:"actor_kind_display"`
				Success          bool            `json:"success"`
				Diff             json.RawMessage `json:"diff"`
				Impersonation    bool            `json:"impersonation"`
				PrevHash         string          `json:"prev_hash"`
				EntryHash        string          `json:"entry_hash"`
			} `json:"events"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Events, len(seed))

	prev := auditverify.GenesisHash
	for i, x := range resp.Data.Events {
		assert.Equal(t, seed[i].e.ActorType, x.ActorType, "%s: actor_type must be the stored value", x.EventType)
		assert.Equal(t, seed[i].kind, x.ActorKindDisplay, "%s: actor_kind_display", x.EventType)

		success := x.Success
		row := &auditverify.AuditEventRow{
			ID: x.ID, EventType: x.EventType, UserID: x.UserID, SecretNodeID: x.SecretID,
			ProjectID: x.ProjectID, IPAddress: x.IPAddress, Description: x.Description,
			Success: &success, EventTime: x.Timestamp, Diff: string(x.Diff),
			Impersonation: x.Impersonation, ActorType: x.ActorType,
			PrevHash: x.PrevHash, EntryHash: x.EntryHash,
		}
		require.NotEmpty(t, x.EntryHash, "%s: chained row", x.EventType)
		assert.Equal(t, prev, x.PrevHash, "%s: prev_hash links to the previous entry_hash", x.EventType)
		assert.True(t, auditverify.EntryHashMatchesAnyKnownEncoding(row),
			"%s: entry_hash must re-derive from the exported fields (stored actor_type %q, kind %q)", x.EventType, x.ActorType, x.ActorKindDisplay)
		prev = x.EntryHash
	}
}
