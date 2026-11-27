// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

import "github.com/keyorixhq/keyorix/internal/faultstorage"

func init() {
	// ROLE-SHAPE-1 (flagEnvironmentWithoutProjectGrants, internal/core/env_without_project_grants.go):
	// a failed lookup of the grants that apply in the project through an environment
	// DEGRADES the access review ("the completeness of the review is then unknown")
	// instead of failing it, and OpenAccessReviewCampaign snapshots that report, so the
	// campaign row carries Degraded + its reason where the fault-free run's does not. The
	// lookup reads ListAllUserRoleGrants, ListAllGroupRoleGrants, ListRoles and
	// GetEnvironment, one row each (post_projects_id_access_review_campaigns_*). Found
	// by FuzzIOFaultOperations: ENOSPC on the user_roles read.
	registerOpScopedBestEffort("post_projects_id_access_review_campaigns_listalluserrolegrants", opScopedBestEffortTable{op: "REST POST /api/v1/projects/{id}/access-review/campaigns", method: "ListAllUserRoleGrants", tables: []string{"AccessReviewCampaign"}, acceptState: accessReviewCampaignDegradedState, pinnedKinds: []faultstorage.FaultKind{faultstorage.KindError}})
}
