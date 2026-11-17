// cta_review_suspend_marker_old_binary_postgres_test.go — STORE-STALE-NOV-2 item 2
// (#3362) on PostgreSQL: the old-binary writer is a raw UPDATE of status and
// updated_at. Cases: cta_review_suspend_marker_old_binary_cases_test.go.
package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestCTAReview_SuspendMarker_OldBinaryResumeThenPlainSuspend_CrossReplicaPostgres(t *testing.T) {
	f := newCTAReview(t)
	// newCTAReviewOn migrates with AutoMigrate only; the marker trigger is
	// installed by the storage factory in production. Install it the same way.
	requireSuspendMarkerTrigger(t, f)
	runSuspendMarkerFourSteps(t, f, oldBinaryStatusWrite)
}

// requireSuspendMarkerTrigger installs trg_secret_nodes_suspend_marker the way the
// storage factory does on start, and checks it is there.
func requireSuspendMarkerTrigger(t *testing.T, f *ctaReview) {
	t.Helper()
	require.NoError(t, localstore.EnsureSecretSuspendMarkerTrigger(f.setupDB))
	var n int64
	require.NoError(t, f.setupDB.Raw("SELECT count(*) FROM pg_trigger WHERE tgname = ?", localstore.SecretSuspendMarkerTrigger).Scan(&n).Error)
	require.EqualValues(t, 1, n, "fixture: the suspend-marker trigger is not installed")
}
