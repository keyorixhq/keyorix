// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// See post_projects_id_access_review_campaigns_listalluserrolegrants (ROLE-SHAPE-1).
	registerOpScopedBestEffort("post_projects_id_access_review_campaigns_listroles", opScopedBestEffortTable{op: "REST POST /api/v1/projects/{id}/access-review/campaigns", method: "ListRoles", tables: []string{"AccessReviewCampaign"}})
}
