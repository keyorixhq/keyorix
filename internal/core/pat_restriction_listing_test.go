package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The edges of pat_restriction_listing.go's filters that the HTTP sweep's fixture
// does not produce: a notification with no project, a nil row, and the no-op for an
// unrestricted request.
func TestPATRestrictionListingFilters_Edges(t *testing.T) {
	t.Parallel()
	pid := func(v uint) *uint { return &v }
	plain := context.Background()
	confined := WithPATRestriction(plain, &PATRestriction{ProjectID: 7})
	envConfined := WithPATRestriction(plain, &PATRestriction{ProjectID: 7, EnvironmentID: 70})
	noSecretsRead := WithPATRestriction(plain, &PATRestriction{Permissions: []string{"users.read"}})
	cidrOnly := WithPATRestriction(plain, &PATRestriction{AllowedCIDRs: []string{"10.0.0.0/8"}})

	t.Run("notifications", func(t *testing.T) {
		inProject := &models.Notification{ProjectID: pid(7)}
		otherProject := &models.Notification{ProjectID: pid(8)}
		noProject := &models.Notification{}

		for _, n := range []*models.Notification{inProject, otherProject, noProject} {
			assert.True(t, patAllowsNotification(plain, n), "no restriction: everything is visible")
		}
		assert.True(t, patAllowsNotification(confined, inProject))
		assert.False(t, patAllowsNotification(confined, otherProject))
		assert.False(t, patAllowsNotification(confined, noProject), "fail closed: no project to check against")
		assert.False(t, patAllowsNotification(envConfined, inProject), "a project-level row is outside an environment confinement, as in Allows")
		assert.False(t, patAllowsNotification(noSecretsRead, inProject))
		assert.False(t, patAllowsNotification(cidrOnly, noProject), "any restriction fails closed on a project-less row")
		assert.True(t, patAllowsNotification(cidrOnly, inProject), "a CIDR-only restriction narrows nothing by scope")
		assert.False(t, patAllowsNotification(confined, nil))
	})

	t.Run("secrets", func(t *testing.T) {
		in := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 1, ProjectID: 7, EnvironmentID: 70}}
		other := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 2, ProjectID: 8, EnvironmentID: 80}}
		otherEnv := &models.SecretWithSharingInfo{SecretNode: &models.SecretNode{ID: 3, ProjectID: 7, EnvironmentID: 71}}
		rows := []*models.SecretWithSharingInfo{in, other, otherEnv, nil, {}}

		assert.Equal(t, rows, filterSecretsByPATRestriction(plain, rows), "no restriction: input returned unchanged")
		assert.Equal(t, []*models.SecretWithSharingInfo{in, otherEnv}, filterSecretsByPATRestriction(confined, rows))
		assert.Equal(t, []*models.SecretWithSharingInfo{in}, filterSecretsByPATRestriction(envConfined, rows))
		assert.Empty(t, filterSecretsByPATRestriction(noSecretsRead, rows))
	})
}
