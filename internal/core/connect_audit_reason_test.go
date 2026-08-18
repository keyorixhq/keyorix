// connect_audit_reason_test.go — ADR-082 branch 3: asserts the exact
// "reason=<value>" token ReadFederatedSecret's audit Description carries for
// every allow and deny outcome, plus Success and ProjectID population. The
// fixed token format (documented in ADR-082 §E) is what lets a future
// structured column be a parse-and-backfill rather than a rewrite, so these
// tests pin the literal values, not just "an event was written."
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// lastConnectSecretReadEvent returns the most recently written
// connect.secret_read audit row.
func lastConnectSecretReadEvent(t *testing.T, db *gorm.DB) models.AuditEvent {
	t.Helper()
	var event models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventConnectSecretRead).Order("id DESC").First(&event).Error)
	return event
}

// TestReadFederatedSecret_AuditReasons_Allow covers the three allow reasons
// (ADR-082 §E: project_membership, global_scope, platform_scope) plus
// delegation (§F) — each must produce Success=true, the exact reason= token,
// and a ProjectID matching the connector's OWNING project (nil for a
// platform-scoped connector, per ConnectOwnership's own doc comment).
func TestReadFederatedSecret_AuditReasons_Allow(t *testing.T) {
	t.Run("project_membership", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUserAtProject(t, db, 1, 10, "project-member", 42)

		val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
		require.NoError(t, err)
		assert.Equal(t, "v", val)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.True(t, *event.Success)
		require.NotNil(t, event.ProjectID)
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=project_membership")
	})

	t.Run("global_scope", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUser(t, db, 2, 20, "global-role")

		val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 2, "aws", "ref")
		require.NoError(t, err)
		assert.Equal(t, "v", val)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.True(t, *event.Success)
		require.NotNil(t, event.ProjectID)
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=global_scope")
	})

	t.Run("platform_scope", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "shared-vault", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"shared-vault": {Scope: "platform"}})
		seedRoleForUser(t, db, 999, 50, "platform-caller")
		seedConnectPlatformUsePermission(t, db, 50) // ADR-082 branch 4: platform scope now requires this

		val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 999, "shared-vault", "ref")
		require.NoError(t, err)
		assert.Equal(t, "v", val)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.True(t, *event.Success)
		assert.Nil(t, event.ProjectID, "a platform-scoped connector's ProjectID is meaningless and must not be audited as a real project")
		assert.Contains(t, event.Description, "reason=platform_scope")
	})

	t.Run("delegation", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUserAtProject(t, db, 5, 30, "borrower", 99) // NOT owner (different project)
		seedGrant(t, c, 30, "aws", "prod/")

		val, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 5, "aws", "prod/db")
		require.NoError(t, err)
		assert.Equal(t, "v", val)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.True(t, *event.Success)
		require.NotNil(t, event.ProjectID, "delegation still audits the connector's OWNING project, not the caller's")
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=delegation")
	})
}

// TestReadFederatedSecret_AuditReasons_Deny covers every deny path (ADR-082
// branch 3): all must be Success=false, and each must carry its own distinct
// reason= token — ownership_denied and delegation_denied in particular are
// the ONLY place these two outcomes are distinguishable at all, since both
// return the identical opaque unknown-connector error to the caller.
func TestReadFederatedSecret_AuditReasons_Deny(t *testing.T) {
	t.Run("connect_disabled", func(t *testing.T) {
		ms := new(MockStorage)
		var got *models.AuditEvent
		ms.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
			got = e
			return true
		})).Return(nil)
		c := &KeyorixCore{storage: ms}

		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "ref")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConnectDisabled)

		require.NotNil(t, got)
		require.NotNil(t, got.Success)
		assert.False(t, *got.Success)
		assert.Nil(t, got.ProjectID)
		assert.Contains(t, got.Description, "reason=connect_disabled")
	})

	t.Run("unknown_connector", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "nope", "ref")
		require.Error(t, err)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.False(t, *event.Success)
		assert.Nil(t, event.ProjectID)
		assert.Contains(t, event.Description, "reason=unknown_connector")
	})

	t.Run("ref_not_permitted", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUserAtProject(t, db, 1, 10, "project-member", 42)
		seedGrant(t, c, 10, "aws", "prod/") // scopes the connector to prod/ only

		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "aws", "dev/db")
		require.Error(t, err)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.False(t, *event.Success)
		require.NotNil(t, event.ProjectID)
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=ref_not_permitted")
	})

	t.Run("ownership_denied_no_grants_at_all", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUserAtProject(t, db, 6, 31, "not-owner", 99) // different project, no grant seeded

		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 6, "aws", "ref")
		require.Error(t, err)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.False(t, *event.Success)
		require.NotNil(t, event.ProjectID)
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=ownership_denied")
	})

	t.Run("delegation_denied_grants_exist_but_no_match", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
		c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
		seedRoleForUserAtProject(t, db, 5, 30, "borrower", 99) // not owner
		seedGrant(t, c, 30, "aws", "prod/")                    // a grant exists...

		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 5, "aws", "dev/db") // ...but ref is outside it
		require.Error(t, err)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.False(t, *event.Success)
		require.NotNil(t, event.ProjectID)
		assert.EqualValues(t, 42, *event.ProjectID)
		assert.Contains(t, event.Description, "reason=delegation_denied")
	})

	t.Run("backend_error", func(t *testing.T) {
		c, db := connectRBACCore(t, fakeConnector{name: "shared-vault", err: assert.AnError})
		c.SetConnectOwnership(map[string]ConnectOwnership{"shared-vault": {Scope: "platform"}})
		seedRoleForUser(t, db, 1, 50, "platform-caller")
		seedConnectPlatformUsePermission(t, db, 50) // ADR-082 branch 4: must clear the platform gate to reach the backend call and fail there instead

		_, err := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 1, "shared-vault", "ref")
		require.Error(t, err)

		event := lastConnectSecretReadEvent(t, db)
		require.NotNil(t, event.Success)
		assert.False(t, *event.Success)
		assert.Contains(t, event.Description, "reason=backend_error")
	})
}

// TestReadFederatedSecret_OwnershipDenialProducesAuditEventDespiteOpaqueHTTPShape
// proves the exact property ADR-082 branch 3 exists for: the RETURNED ERROR is
// identical (ErrConnectUnknownConnector) for an ownership denial and a
// genuinely unknown connector — but the audit trail still records which one
// actually happened, distinctly and correctly.
func TestReadFederatedSecret_OwnershipDenialProducesAuditEventDespiteOpaqueHTTPShape(t *testing.T) {
	c, db := connectRBACCore(t, fakeConnector{name: "aws", val: "v"})
	c.SetConnectOwnership(map[string]ConnectOwnership{"aws": {Scope: "project", ProjectID: 42}})
	seedRoleForUserAtProject(t, db, 6, 31, "not-owner", 99)

	_, ownershipDenialErr := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 6, "aws", "ref")
	require.Error(t, ownershipDenialErr)
	require.ErrorIs(t, ownershipDenialErr, ErrConnectUnknownConnector)

	_, unknownConnectorErr := c.ReadFederatedSecret(context.Background(), ActorTypeUser, 6, "does-not-exist", "ref")
	require.Error(t, unknownConnectorErr)
	require.ErrorIs(t, unknownConnectorErr, ErrConnectUnknownConnector)

	// The two errors are indistinguishable to the caller...
	assert.ErrorIs(t, ownershipDenialErr, ErrConnectUnknownConnector)
	assert.ErrorIs(t, unknownConnectorErr, ErrConnectUnknownConnector)

	// ...but the audit trail is not: two distinct events, with distinct reasons.
	var events []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", EventConnectSecretRead).Order("id ASC").Find(&events).Error)
	require.Len(t, events, 2)
	assert.Contains(t, events[0].Description, "reason=ownership_denied")
	assert.Contains(t, events[1].Description, "reason=unknown_connector")
}
