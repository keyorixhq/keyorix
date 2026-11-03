package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedLiveProjects creates a live projects row for each id (an existing row is
// kept), for fixtures that grant roles at bare project ids: since #2795 a scoped
// grant whose project has no row does not authorize.
func seedLiveProjects(t *testing.T, db *gorm.DB, ids ...uint) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, db.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&models.Project{ID: id, Name: fmt.Sprintf("live-project-%d", id)}).Error)
	}
}
