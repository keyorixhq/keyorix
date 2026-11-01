package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedLiveScopeProjects makes sure a live projects row exists for each id (creating
// it when absent, keeping one that is there). A scoped role grant authorizes only
// while its project row exists and is live (INV-STORE-scoped-grant-needs-live-scope-row),
// so a fixture that writes a user_roles/group_roles row at project N needs project N.
func seedLiveScopeProjects(t testing.TB, db *gorm.DB, ids ...uint) {
	t.Helper()
	for _, id := range ids {
		if id == 0 { // global: no row
			continue
		}
		require.NoError(t, db.Where(models.Project{ID: id}).
			Attrs(models.Project{Name: fmt.Sprintf("scope-proj-%d", id)}).
			FirstOrCreate(&models.Project{}).Error)
	}
}
