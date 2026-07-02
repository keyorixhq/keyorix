package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/notary"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// fakeAnchorNotary is a minimal notary.Notary stand-in so the handler test doesn't
// need a real RFC 3161 TSA — the round-trip crypto is covered in internal/notary.
type fakeAnchorNotary struct {
	token []byte
	at    time.Time
}

func (f *fakeAnchorNotary) Anchor(_ context.Context, _ []byte) (*notary.Receipt, error) {
	return &notary.Receipt{Token: f.token, Time: f.at, Provider: "fake"}, nil
}
func (f *fakeAnchorNotary) Provider() string { return "fake" }

// #182: VerifyCheckpointAnchor's raw receipt must be reachable from the
// operator-facing surfaces (GET /api/v1/audit/verify and POST /api/v1/audit/checkpoint),
// not just recorded on the DB row where nothing external can reach it.
func TestAuditHandler_CheckpointAndVerify_SurfaceRawAnchorToken(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}))

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	coreService.SetAuditCheckpointKey(bytes.Repeat([]byte{0x7}, 32), "v1")
	fn := &fakeAnchorNotary{token: []byte("opaque-tsa-token"), at: time.Date(2026, 6, 15, 9, 0, 0, 0, time.UTC)}
	coreService.SetCheckpointNotary(fn)

	tr := true
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", Description: "e", Success: &tr, ActorType: "user",
		EventTime: time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC),
	}).Error)

	h := NewAuditHandler(coreService)

	// Write a checkpoint — its response should carry the raw anchor token.
	wReq := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	wRec := httptest.NewRecorder()
	h.WriteAuditCheckpoint(wRec, wReq)
	require.Equal(t, http.StatusOK, wRec.Code)

	var writeResp struct {
		Data struct {
			AnchorToken    string `json:"anchor_token"`
			AnchorProvider string `json:"anchor_provider"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(wRec.Body.Bytes(), &writeResp))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("opaque-tsa-token")), writeResp.Data.AnchorToken)
	require.Equal(t, "fake", writeResp.Data.AnchorProvider)

	// The verify endpoint — the surface an operator actually polls — must ALSO
	// surface it (checkpoints are normally written by the background scheduler, so
	// the write response above is not always available to the operator).
	vReq := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	vRec := httptest.NewRecorder()
	h.VerifyAuditChain(vRec, vReq)
	require.Equal(t, http.StatusOK, vRec.Code)

	var verifyResp struct {
		Data struct {
			AnchorToken    string `json:"anchor_token"`
			AnchorProvider string `json:"anchor_provider"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(vRec.Body.Bytes(), &verifyResp))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("opaque-tsa-token")), verifyResp.Data.AnchorToken)
	require.Equal(t, "fake", verifyResp.Data.AnchorProvider)
}
