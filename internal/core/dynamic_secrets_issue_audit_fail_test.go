// dynamic_secrets_issue_audit_fail_test.go — #4716 red/green proof.
//
// IssueLease used to discard the result of its dynamic_lease.issued audit write and
// return the username and password either way: a credential disclosed with no audit
// record. It must now follow audit-before-disclosure like the secret-value reads: no
// committed event, no credential, the minted role revoked and no `active` lease row left.
//
// The faults reuse failLogAuditEventStorage / hooked (dynamic_secrets_revoke_audit_fail_test.go):
// a storage decorator that fails or panics LogAuditEvent for one event type, with no
// production hook.
package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const issuedEvent = "dynamic_lease.issued"

func panicLogAuditEventStorage(inner storage.Storage, eventType string) storage.Storage {
	return hooked(inner, &storeHooks{
		LogAuditEvent: func(next storage.Storage, ctx context.Context, event *models.AuditEvent) error {
			if event.EventType == eventType {
				panic("fault-injected: " + eventType + " audit write panicked")
			}
			return next.LogAuditEvent(ctx, event)
		},
	})
}

func countIssueAuditEvents(t *testing.T, db *gorm.DB, eventType string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
	return n
}

func leaseStatuses(t *testing.T, c *KeyorixCore, configID uint) []string {
	t.Helper()
	var out []string
	for _, l := range listLeases(t, c, configID) {
		out = append(out, l.Status)
	}
	return out
}

// (a) The audit write fails: no credential, an error that does not carry it, the minted
// role revoked, no active lease row.
func TestIssueLease_AuditWriteFails_NoCredentialRoleRevoked(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	c.storage = failLogAuditEventStorage(c.storage, issuedEvent)
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)

	require.Error(t, err, "#4716: a credential must not be returned when its audit event was not committed")
	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	assert.Nil(t, issued)
	require.Len(t, fake.Issued, 1, "the credential was minted before the audit write")
	assert.NotContains(t, err.Error(), fake.Issued[0], "the error must not carry the username")
	assert.Equal(t, fake.Issued, fake.Revoked, "the minted role must be revoked through the engine")
	assert.NotContains(t, leaseStatuses(t, c, cfg.ID), "active", "no active lease row for a credential nobody received")
	assert.Equal(t, []string{"revoked"}, leaseStatuses(t, c, cfg.ID))
	assert.EqualValues(t, 0, countIssueAuditEvents(t, db, issuedEvent))
}

// (b) The audit write fails and so does the revoke: a revoke_failed row and its audit
// event exist (cleanupOrphanedRole's handling), and no row stays active.
func TestIssueLease_AuditWriteFailsAndRevokeFails_RevokeFailedRowAndEvent(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	c.storage = failLogAuditEventStorage(c.storage, issuedEvent)
	fake.FailRevoke = true
	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)

	require.ErrorIs(t, err, ErrMutationAuditUnavailable)
	assert.Nil(t, issued)
	require.Len(t, fake.Issued, 1)
	assert.NotContains(t, err.Error(), fake.Issued[0])
	statuses := leaseStatuses(t, c, cfg.ID)
	assert.NotContains(t, statuses, "active")
	assert.NotEmpty(t, statuses)
	for _, s := range statuses {
		assert.Equal(t, "revoke_failed", s, "the role is still live: every row naming it says so")
	}
	for _, l := range listLeases(t, c, cfg.ID) {
		assert.Equal(t, fake.Issued[0], l.RoleName)
	}
	assert.EqualValues(t, 1, countIssueAuditEvents(t, db, "dynamic_lease.revoke_failed"))
	assert.EqualValues(t, 0, countIssueAuditEvents(t, db, issuedEvent))
}

// (c) Success path unchanged: the credential is returned, one event, one active row, no revoke.
func TestIssueLease_AuditCommitted_ReturnsCredentialUnchanged(t *testing.T) {
	t.Parallel()
	c, db, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	issued, err := c.IssueLease(ctx, cfg.ID, 0, 7)

	require.NoError(t, err)
	require.NotNil(t, issued)
	assert.Equal(t, fake.Issued[0], issued.Username)
	assert.NotEmpty(t, issued.Password)
	assert.NotEmpty(t, issued.LeaseID)
	assert.Empty(t, fake.Revoked)
	assert.Equal(t, []string{"active"}, leaseStatuses(t, c, cfg.ID))
	assert.EqualValues(t, 1, countIssueAuditEvents(t, db, issuedEvent))
}

// (d) The audit write panics: the writer family recovers it to "not persisted", so the
// credential is not returned and the same abort runs. The panic must not escape.
func TestIssueLease_AuditWritePanics_NoCredential(t *testing.T) {
	t.Parallel()
	c, _, fake, _ := newDynamicTestCore(t)
	ctx := context.Background()
	cfg := mkConfig(t, c, ctx)

	c.storage = panicLogAuditEventStorage(c.storage, issuedEvent)
	var issued *IssuedLease
	var err error
	require.NotPanics(t, func() { issued, err = c.IssueLease(ctx, cfg.ID, 0, 7) })

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMutationAuditUnavailable), fmt.Sprint(err))
	assert.Nil(t, issued)
	require.Len(t, fake.Issued, 1)
	assert.NotContains(t, err.Error(), fake.Issued[0])
	assert.Equal(t, fake.Issued, fake.Revoked)
	assert.NotContains(t, leaseStatuses(t, c, cfg.ID), "active")
}
