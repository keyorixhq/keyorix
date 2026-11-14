// cta_review_legal_hold_lift_postgres_test.go — STORE-STALE-NOV-2 item 1 (#4210)
// on Postgres, two replicas on independent connection pools. The case and the
// hook are in cta_review_legal_hold_lift_cases_test.go.
//
// Bug origin (#4210):
//
//	Introduced-by: UpdateLegalHold, an unconditional full-row Save (legal-hold
//	               feature, ISO 27001 A.5.34)
//	Detected-by:   review (TEST-GUARDS-NOV-1, #4179)
//	Class:         race (cross-replica stale-snapshot lost update)
//	Severity:      medium (a stale struct can re-activate a lifted hold; the live
//	               caller only lost the first lifter's attribution and double-audited)
//	Guard:         TestFullRowWriteGuard_NoStaleFullRowWriteOnSecurityStateModels
//	               (the Save is gone, its exemption rows deleted) +
//	               TestReleaseLegalHold_StaleUnreleasedWriteCannotReactivate +
//	               these tests
package core

import "testing"

func TestCTAReview_LegalHoldLift_SecondLifterRefused_CrossReplicaPostgres(t *testing.T) {
	runLegalHoldLiftRace(t, newCTAReview(t))
}
