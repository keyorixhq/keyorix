// One file per entry; never append to a shared list. See registry_entries_test.go.
package faultops

func init() {
	// Not pinned: a storage-level fault on this method never fires during the op in
	// driveFaultCase's world (TestOpScopedBestEffort_PinnedEntriesAreLoadBearing: "fault
	// never fired"), so that check cannot cover this row; acceptState still bounds it.
	// See post_projects_id_access_review_campaigns_listalluserrolegrants (ROLE-SHAPE-1).
	registerOpScopedBestEffort("post_projects_id_access_review_campaigns_getenvironment", opScopedBestEffortTable{op: "REST POST /api/v1/projects/{id}/access-review/campaigns", method: "GetEnvironment", tables: []string{"AccessReviewCampaign"}, acceptState: accessReviewCampaignDegradedState})
}
