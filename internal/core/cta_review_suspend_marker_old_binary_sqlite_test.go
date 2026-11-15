// cta_review_suspend_marker_old_binary_sqlite_test.go — the SQLite twin of the
// #3362 four-step sequence. SQLite has no older binary beside this one (one
// process, and the schema-epoch floor refuses a pre-#3215 binary), so the resume
// and the plain suspend are this binary's own, on replica B.
package core

import "testing"

func TestSuspendMarker_ResumeThenPlainSuspend_CrossReplicaSQLite(t *testing.T) {
	runSuspendMarkerFourSteps(t, newCTAReviewSQLite(t), newBinaryStatusWrite)
}
