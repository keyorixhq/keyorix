package core

// share_list_elevation_audit_test.go — #3456: GET /shares (ListUserShareViews) names
// each secret the caller may read, and for a recipient whose role does not grant
// secrets.read that read is a share elevation. It used to write one
// share_access_elevated row per such secret on the page; a list call now writes ONE
// summary row (action shares.list) naming how many secrets the shares made readable
// and which shares. An elevated read of one secret still writes its own row.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type shareListAuditWorld struct {
	w         *c4World
	recipient uint
	reader    uint
	secrets   []uint
	shares    []uint
}

// newShareListAuditWorld: project P, an owner, a recipient who is a member of P with a
// role that grants nothing (so every read of a shared secret is a share elevation), a
// reader whose role grants secrets.read at P (no elevation), and n secrets in P each
// read-shared to both.
func newShareListAuditWorld(t *testing.T, n int) *shareListAuditWorld {
	t.Helper()
	w := newC4World(t, "sqlite")
	db := w.db
	rNone := w.role(false)
	rRead := w.role(false, w.permission(permSecretsRead))
	p := w.project()
	e := w.env(p.ID)
	owner, recipient, reader := w.user(), w.user(), w.user()
	require.NoError(t, db.Create(&models.UserRole{UserID: recipient.ID, RoleID: rNone.ID, ProjectID: p.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: reader.ID, RoleID: rRead.ID, ProjectID: p.ID}).Error)
	sw := &shareListAuditWorld{w: w, recipient: recipient.ID, reader: reader.ID}
	for i := range n {
		s := &models.SecretNode{
			Name: fmt.Sprintf("shared-%d", i), ProjectID: p.ID, EnvironmentID: e.ID, IsSecret: true, Type: "generic",
			Status: "active", OwnerID: owner.ID, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		require.NoError(t, db.Create(s).Error)
		sw.secrets = append(sw.secrets, s.ID)
		for _, to := range []uint{recipient.ID, reader.ID} {
			sh := &models.ShareRecord{SecretID: s.ID, OwnerID: owner.ID, RecipientID: to, Permission: "read"}
			require.NoError(t, db.Create(sh).Error)
			if to == recipient.ID {
				sw.shares = append(sw.shares, sh.ID)
			}
		}
	}
	return sw
}

func (sw *shareListAuditWorld) elevationRows(t *testing.T, after uint) []models.AuditEvent {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, sw.w.db.Where("id > ? AND event_type = ?", after, string(ShareAuditEventAccessElevated)).Order("id").Find(&rows).Error)
	return rows
}

func TestListUserShareViews_WritesOneElevationRowPerListCall(t *testing.T) {
	const n = 5
	sw := newShareListAuditWorld(t, n)
	ctx := context.Background()

	before := sbAuditHighWater(t, sw.w.db)
	views, err := sw.w.core.ListUserShareViews(ctx, sw.recipient)
	require.NoError(t, err)
	require.Len(t, views, n)
	for _, v := range views {
		assert.NotEmpty(t, v.SecretName, "the share makes the secret readable, so the list names it")
	}

	rows := sw.elevationRows(t, before)
	require.Len(t, rows, 1, "one list call writes one share_access_elevated row, not one per shared secret")
	r := rows[0]
	require.NotNil(t, r.UserID)
	assert.Equal(t, sw.recipient, *r.UserID)
	assert.Nil(t, r.SecretNodeID, "the summary row covers several secrets")
	// Decoded by its wire names, so the payload a SIEM or the audit UI reads is pinned.
	var d struct {
		Action     string `json:"action"`
		Count      int    `json:"count"`
		Truncated  bool   `json:"truncated"`
		Elevations []struct {
			SecretID uint `json:"secret_id"`
			ShareID  uint `json:"share_id"`
		} `json:"elevations"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.Diff), &d), r.Diff)
	assert.Equal(t, "shares.list", d.Action)
	assert.Equal(t, n, d.Count)
	assert.False(t, d.Truncated)
	gotShares := make([]uint, 0, len(d.Elevations))
	gotSecrets := make([]uint, 0, len(d.Elevations))
	for _, e := range d.Elevations {
		gotShares = append(gotShares, e.ShareID)
		gotSecrets = append(gotSecrets, e.SecretID)
	}
	assert.ElementsMatch(t, sw.shares, gotShares)
	assert.ElementsMatch(t, sw.secrets, gotSecrets)

	// A second list call is a second action: one more row.
	_, err = sw.w.core.ListUserShareViews(ctx, sw.recipient)
	require.NoError(t, err)
	assert.Len(t, sw.elevationRows(t, before), 2)
}

// A caller whose role already grants the read writes no elevation row at all.
func TestListUserShareViews_RoleReaderWritesNoElevationRow(t *testing.T) {
	sw := newShareListAuditWorld(t, 3)
	before := sbAuditHighWater(t, sw.w.db)
	views, err := sw.w.core.ListUserShareViews(context.Background(), sw.reader)
	require.NoError(t, err)
	require.Len(t, views, 3)
	assert.Empty(t, sw.elevationRows(t, before))
}

// An elevated read of ONE secret (no request recorder: the core-internal read path)
// still writes its own row, naming the secret and the share.
func TestShareElevatedSecretRead_StillWritesItsOwnRow(t *testing.T) {
	sw := newShareListAuditWorld(t, 2)
	before := sbAuditHighWater(t, sw.w.db)
	ok, err := sw.w.core.AuthorizeSecret(context.Background(), sw.recipient, sw.secrets[0], permSecretsRead)
	require.NoError(t, err)
	require.True(t, ok)
	rows := sw.elevationRows(t, before)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].SecretNodeID)
	assert.Equal(t, sw.secrets[0], *rows[0].SecretNodeID)
	var d shareElevationDetail
	require.NoError(t, json.Unmarshal([]byte(rows[0].Diff), &d))
	assert.Equal(t, sw.shares[0], d.ShareID)
}
