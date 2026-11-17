// cta_review_user_row_narrow_postgres_test.go — FIX-USER-ROW-NARROW-1 (#2653,
// #2654) on Postgres, two replicas on independent connection pools. The cases
// and the hook are in cta_review_user_row_narrow_cases_test.go.
//
// Bug origin (#2653/#2654 residue):
//
//	Introduced-by: UpdateUser's default branch persisting the unlocked GetUser
//	               snapshot (#2785 narrowed the write to the 7 profile columns,
//	               but still wrote all of them from that snapshot)
//	Detected-by:   review (FIX-USER-ROW-NARROW-1)
//	Class:         race (cross-replica check-then-act, stale-snapshot lost update)
//	Severity:      high (a session-only profile edit reverts an email change, the
//	               password-reset anchor; the web shape changes the email with no
//	               re-auth)
//	Guard:         these tests (pg-gated) + the SQLite twin (default CI) +
//	               TestUserProfileWrites_AreColumnScoped
package core

import "testing"

func TestCTAReview_UserRowNarrow_CompetingWriteSurvives_CrossReplicaPostgres(t *testing.T) {
	pgTestDSN(t)
	runUserRowNarrowMatrix(t, func(t *testing.T) *ctaReview { return newCTAReview(t) })
}

func TestCTAReview_UserRowNarrow_OwnProfileEmailChangedBetweenReads_CrossReplicaPostgres(t *testing.T) {
	runUserRowNarrowEmailBetweenReads(t, newCTAReview(t))
}

func TestCTAReview_UserRowNarrow_ConcurrentDeactivationStillDetected_CrossReplicaPostgres(t *testing.T) {
	runUserRowNarrowActiveConflict(t, newCTAReview(t))
}
