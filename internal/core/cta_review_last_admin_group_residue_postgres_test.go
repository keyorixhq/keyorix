package core

import "testing"

// TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted_Postgres
// is the two-replica Postgres run of the #2658 cases: replica B neutralises
// the other admin route, replica A then removes the direct admin's own grant
// and must be refused. It exercises RemoveGlobalAdminRoleGuarded's live-holder
// resolution (and its FOR UPDATE reads) on the dialect HA deployments use.
// Skips when KEYORIX_TEST_PG_DSN is unset.
func TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted_Postgres(t *testing.T) {
	for _, tc := range lastAdminResidueCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCTAReview(t)
			runLastAdminResidueCase(t, tc, f.coreB, f.coreA, f.setup.Storage())
		})
	}
}
