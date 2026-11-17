// cta_review_legal_hold_lift_sqlite_test.go — the SQLite twin of
// cta_review_legal_hold_lift_postgres_test.go (one SQLite file, independent
// pools with the production pragmas), so the #4210 interleaving runs in default
// CI. B runs after A's unlocked read, when A holds no transaction.
package core

import "testing"

func TestLegalHoldLift_SecondLifterRefused_CrossReplicaSQLite(t *testing.T) {
	runLegalHoldLiftRace(t, newCTAReviewSQLite(t))
}
