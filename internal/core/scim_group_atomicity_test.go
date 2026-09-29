package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failOnceAddUserToGroupStorage makes AddUserToGroup fail once for a specific
// userID, mirroring the failOnceStorage idiom from #2295.
type failOnceAddUserToGroupStorage struct {
	storage.Storage
	failUserID uint
	armed      *bool
}

func (s *failOnceAddUserToGroupStorage) WithTransaction(ctx context.Context, fn func(storage.Storage) error) error {
	return s.Storage.WithTransaction(ctx, func(tx storage.Storage) error {
		return fn(&failOnceAddUserToGroupStorage{Storage: tx, failUserID: s.failUserID, armed: s.armed})
	})
}

func (s *failOnceAddUserToGroupStorage) AddUserToGroup(ctx context.Context, userID, groupID, projectID uint) error {
	if *s.armed && userID == s.failUserID {
		*s.armed = false
		return errors.New("injected fault: AddUserToGroup")
	}
	return s.Storage.AddUserToGroup(ctx, userID, groupID, projectID)
}

// TestProvisionSCIMGroup_PartialMemberFailureRollsBackGroup is the red-proof
// for Session O's O3 SCIM group fix: a failure adding one of several initial
// members must roll back the group creation too -- not the pre-fix behavior
// where a partially-populated group was created with no signal to the IdP,
// and (since POST is not retry-safe) a retry would create a SECOND duplicate
// group.
func TestProvisionSCIMGroup_PartialMemberFailureRollsBackGroup(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)

	base := c.storage
	armed := true
	c.storage = &failOnceAddUserToGroupStorage{Storage: base, failUserID: 2, armed: &armed}

	_, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1, 2})
	require.Error(t, err)
	require.False(t, armed, "the injected fault must actually have fired")

	var groupCount int64
	require.NoError(t, db.Model(&models.Group{}).Where("name = ?", "Engineering").Count(&groupCount).Error)
	assert.Zero(t, groupCount, "a failed partial-membership apply must roll back the group row too -- no partially-populated group")

	// Retry (fault disarmed) succeeds with BOTH members, and does not create a
	// duplicate group (the failed attempt left nothing behind to duplicate).
	group, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1, 2})
	require.NoError(t, err)
	members, err := base.ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	assert.Len(t, members, 2)

	require.NoError(t, db.Model(&models.Group{}).Where("name = ?", "Engineering").Count(&groupCount).Error)
	assert.Equal(t, int64(1), groupCount, "exactly one group must exist after the clean retry")
}
