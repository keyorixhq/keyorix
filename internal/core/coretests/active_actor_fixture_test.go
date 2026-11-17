package coretests

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// seedActiveActor creates an active account for actorID unless one exists: a
// mutating core entry point refuses an actor whose account is missing or not
// active (#4159), as no transport-authenticated actor can be.
func seedActiveActor(t *testing.T, db *gorm.DB, actorID uint) {
	t.Helper()
	name := fmt.Sprintf("seeded-actor-%d", actorID)
	require.NoError(t, db.Where(models.User{ID: actorID}).
		Attrs(models.User{Username: name, UsernameFolded: name, Email: name + "@example.com", EmailFolded: name + "@example.com", IsActive: true}).
		FirstOrCreate(&models.User{}).Error)
}
