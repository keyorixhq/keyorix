// cta_review_user_row_narrow_sqlite_test.go — the SQLite twin of
// cta_review_user_row_narrow_postgres_test.go: one SQLite file, three
// independent pools with the production pragmas (newCTAReviewSQLite), so the
// #2653/#2654 interleavings run in default CI. The hook runs B after A's
// unlocked read, when A holds no transaction, so B never waits on A's write
// lock.
package core

import "testing"

func TestUserRowNarrow_CompetingWriteSurvives_CrossReplicaSQLite(t *testing.T) {
	runUserRowNarrowMatrix(t, newCTAReviewSQLite)
}

func TestUserRowNarrow_OwnProfileEmailChangedBetweenReads_CrossReplicaSQLite(t *testing.T) {
	runUserRowNarrowEmailBetweenReads(t, newCTAReviewSQLite(t))
}

func TestUserRowNarrow_ConcurrentDeactivationStillDetected_CrossReplicaSQLite(t *testing.T) {
	runUserRowNarrowActiveConflict(t, newCTAReviewSQLite(t))
}
