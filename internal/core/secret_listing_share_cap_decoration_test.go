package core

// secret_listing_share_cap_decoration_test.go — #3943: anyone able to share enough
// secrets with a user (10000, the storage fetch cap) turned that user's secret listing
// (GET /api/v1/secrets, gRPC ListSecrets) into an error, because the role-scoped
// listing refused a received-share fetch at the cap. There the shares only decorate
// rows the role already makes visible, so the listing must answer with every row and
// at most a partial decoration (IsShared/UserPermission under-reported: fails safe).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListReadableSecrets_ViewerOverTheInboundShareCapStillLists(t *testing.T) {
	t.Parallel()
	shares := shareRecords(1, maxShareViewBatchSize+1)
	shares[0].SecretID, shares[0].Permission = 1, "write"
	for _, s := range shares[1:] {
		s.SecretID = 2
	}
	c := shareCapTierFixture(t, shares, func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	})
	ctx := context.Background()

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{})
	require.NoError(t, err, "a viewer over the inbound share cap must still be able to list secrets")
	require.Equal(t, int64(3), resp.Total, "every role-visible row is listed")
	perm := map[uint]string{}
	for _, s := range resp.Secrets {
		perm[s.ID] = s.UserPermission
	}
	assert.Equal(t, map[uint]string{1: "write", 2: "read", 3: ""}, perm,
		"the shares that came back still decorate their rows; the role-only row stays undecorated")

	owned, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{ShowOwnedOnly: true})
	require.NoError(t, err, "the owned-only view is unaffected")
	assert.Equal(t, int64(0), owned.Total, "user 1 owns none of project 1's secrets")
}
