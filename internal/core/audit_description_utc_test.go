package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUDIT-UX-3 item 4 (#2969 finding): two audit writers formatted a local-zone
// time into the event description (setup_token.issued "expires=", and
// system.audit_purge "cutoff "), so the stored text carried the server's zone
// ("+02:00"). Every API timestamp is UTC; new rows now format the time in UTC
// (RFC 3339, "Z"). Existing rows are untouched. The clock is injected in a
// non-UTC zone, which is what time.Now() yields on a non-UTC server.
var utcTestZone = time.FixedZone("UTC+2", 2*60*60)

func TestSetupTokenIssuedDescription_FormatsExpiryInUTC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	local := time.Date(2026, 6, 5, 14, 0, 0, 0, utcTestZone) // 12:00:00Z
	c.now = func() time.Time { return local }

	var audit *models.AuditEvent
	ms.On("LogAuditEvent", mock.Anything, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { audit = args.Get(1).(*models.AuditEvent) }).Return(nil)
	ms.On("SupersedeActiveSetupTokens", ctx, SetupPurposeAccountSetup, "a@b.io", (*uint)(nil)).Return(nil)
	ms.On("CreateSetupToken", ctx, mock.AnythingOfType("*models.SetupToken")).
		Return(&models.SetupToken{ID: 1, SubjectEmail: "a@b.io", ExpiresAt: local.Add(DefaultSetupTokenTTL)}, nil)

	_, err := c.IssueSetupToken(ctx, IssueSetupTokenRequest{
		Purpose: SetupPurposeAccountSetup, SubjectEmail: "a@b.io",
	})
	require.NoError(t, err)
	require.NotNil(t, audit)
	assert.Equal(t, "setup_token.issued", audit.EventType)
	assert.Contains(t, audit.Description, "expires=2026-06-06T12:00:00Z)", audit.Description)
	assert.NotContains(t, audit.Description, "+02:00", "no local-zone offset in the stored text")
}

func TestAuditPurgeDescription_FormatsCutoffInUTC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, _, _ := newReanchorTestCore(t)
	local := time.Date(2026, 8, 1, 14, 0, 0, 0, utcTestZone) // 12:00:00Z
	c.now = func() time.Time { return local }

	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	et := "system.audit_purge"
	events, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{Action: &et, PageSize: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Description, "(cutoff 2026-07-02T12:00:00Z)", events[0].Description)
	assert.NotContains(t, events[0].Description, "+02:00")
}
