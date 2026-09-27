// inventory_overrides_test.go is the ONLY hand-maintained classification file in
// this package. inventory_registry_generated_test.go is the closed set of live
// mutating operation keys (regenerate via REGEN_INVENTORY=1); every key defaults
// to StatusPending unless it appears here. Promote a key to StatusFuzzed only
// once it is actually driven by FuzzStorageFaultOperations' operation catalog
// (opcatalog_test.go); use StatusExcluded only for a key that is NOT a real
// application-level mutation, with a one-line reason — per CLAUDE.md's "no
// silent caps" principle, StatusPending is the honest default for "a real
// mutation, not yet wired in," not something to route around by mislabeling it
// Excluded.
package faultops

// OpStatus classifies one entry in the operation-table ratchet.
type OpStatus int

const (
	// StatusPending: a real mutating operation, not yet driven by the fuzz
	// harness's operation catalog. A tracked, visible gap — see the REPORT for
	// the running count — never a silently-dropped one.
	StatusPending OpStatus = iota
	// StatusFuzzed: FuzzStorageFaultOperations' operation catalog drives this
	// operation through its real transport (REST/system/gRPC dispatch).
	StatusFuzzed
	// StatusExcluded: not an application-level mutation this harness's oracles
	// apply to. Note explains why.
	StatusExcluded
)

type overrideEntry struct {
	Status OpStatus
	Note   string
}

var operationOverrides = map[string]overrideEntry{
	// --- StatusExcluded: not real application mutations ---
	"REST DELETE /metrics":   {StatusExcluded, "the /metrics endpoint responds to any HTTP method identically (Prometheus text exposition, no state); chi.Walk sees it once per registered method, not once per real behavior — see TestEveryMutatingRouteDeniesReadOnly's own /sw.js precedent for the same catch-all-handler shape"},
	"REST PATCH /metrics":    {StatusExcluded, "see REST DELETE /metrics"},
	"REST POST /metrics":     {StatusExcluded, "see REST DELETE /metrics"},
	"REST PUT /metrics":      {StatusExcluded, "see REST DELETE /metrics"},
	"REST POST /system/init": {StatusExcluded, "bootstrap-only, single-fire before any admin/RBAC state exists — every fuzz world already calls this once during setup (see newFaultWorld); there is no meaningful 'faulted' state to snapshot around a call that only succeeds on a virgin database"},

	// --- StatusFuzzed: wired into the operation catalog (opcatalog_test.go) ---
	// F3: replaceRolePermissions drops GetRolePermissions/RemovePermissionFromRole
	// errors and always replies 200 — confirmed live on main (STEP 0 report).
	"REST PUT /api/v1/roles/{id}": {StatusFuzzed, "opCatalog[\"UpdateRole\"] — F3's replaceRolePermissions call chain"},
	// Representative gRPC mutating call, driven in-process via the real
	// *RoleGRPCService (no core.* bypass here — included to prove the harness
	// generalizes across transports, not just REST).
	"GRPC keyorix.v1.RoleService.AssignRole": {StatusFuzzed, "opCatalog[\"GRPCAssignRole\"]"},
	// Ordinary multi-call CRUD, one per major resource type, to prove the
	// mechanism generalizes beyond the three known bug sites.
	"REST POST /api/v1/secrets/":       {StatusFuzzed, "opCatalog[\"CreateSecret\"]"},
	"REST PUT /api/v1/secrets/{id}":    {StatusFuzzed, "opCatalog[\"UpdateSecret\"]"},
	"REST DELETE /api/v1/secrets/{id}": {StatusFuzzed, "opCatalog[\"DeleteSecret\"]"},
	"REST POST /api/v1/projects":       {StatusFuzzed, "opCatalog[\"CreateProject\"]"},
	"REST POST /api/v1/users/":         {StatusFuzzed, "opCatalog[\"CreateUser\"]"},
	// Coverage batch 2: ordinary REST CRUD.
	"REST POST /api/v1/groups/":       {StatusFuzzed, "opCatalog[\"CreateGroup\"] — batch 2"},
	"REST DELETE /api/v1/groups/{id}": {StatusFuzzed, "opCatalog[\"DeleteGroup\"] — batch 2"},
	"REST POST /api/v1/roles/":        {StatusFuzzed, "opCatalog[\"CreateRole\"] — batch 2"},
	"REST DELETE /api/v1/roles/{id}":  {StatusFuzzed, "opCatalog[\"DeleteRole\"] — batch 2"},
	// Coverage batch 3: gRPC group/role CRUD.
	"GRPC keyorix.v1.GroupService.CreateGroup": {StatusFuzzed, "opCatalog[\"GRPCCreateGroup\"] — batch 3"},
	"GRPC keyorix.v1.RoleService.DeleteRole":   {StatusFuzzed, "opCatalog[\"GRPCDeleteRole\"] — batch 3"},
	// Coverage batch 4: group membership.
	"REST POST /api/v1/groups/{id}/members":            {StatusFuzzed, "opCatalog[\"AddGroupMember\"] — batch 4"},
	"REST DELETE /api/v1/groups/{id}/members/{userId}": {StatusFuzzed, "opCatalog[\"RemoveGroupMember\"] — batch 4"},
	// Coverage batch 5: rotation policies.
	"REST POST /api/v1/rotation-policies/":       {StatusFuzzed, "opCatalog[\"CreateRotationPolicy\"] — batch 5"},
	"REST DELETE /api/v1/rotation-policies/{id}": {StatusFuzzed, "opCatalog[\"DeleteRotationPolicy\"] — batch 5"},
	// Coverage batch 7 (2026-09-24, fuzz/new-surfaces): the ordinary
	// break-glass revoke path (the /system proxy sibling this once compared
	// against was removed in ADR-108 Phase 6 step 14c).
	"REST POST /api/v1/projects/{id}/break-glass/{activationId}/revoke": {StatusFuzzed, "opCatalog[\"RevokeBreakGlass\"] — batch 7"},
	// Coverage batch 8 (2026-09-24, fuzz/new-surfaces): the secret-scoped access
	// request family (server/http/handlers/secret_access_requests.go,
	// internal/core/classification_gate.go) — introduced by #2032, previously
	// entirely absent from this catalog. Create, self-service withdraw, and the
	// admin approve/reject decision (the requester-cannot-approve-their-own,
	// admin-authority-ceiling-gated state transition).
	"REST POST /api/v1/secret-access-requests":                      {StatusFuzzed, "opCatalog[\"CreateSecretAccessRequest\"] — batch 8"},
	"REST POST /api/v1/secret-access-requests/{requestId}/withdraw": {StatusFuzzed, "opCatalog[\"WithdrawSecretAccessRequest\"] — batch 8"},
	"REST PUT /api/v1/secret-access-requests/{requestId}":           {StatusFuzzed, "opCatalog[\"ResolveSecretAccessRequest\"] — batch 8"},
	// Coverage batch 10 (FAULTOPS-SPEED STEP 2, wiring batch 2, 2026-09-27):
	// gRPC siblings of already-REST-wired core CRUD (project/user/group/role/
	// secret) — proves the harness generalizes across transports for the same
	// resource families batch 9 covered for REST.
	"GRPC keyorix.v1.ProjectService.UpdateProject":   {StatusFuzzed, "opCatalog[\"GRPCUpdateProject\"] — batch 10"},
	"GRPC keyorix.v1.ProjectService.DeleteProject":   {StatusFuzzed, "opCatalog[\"GRPCDeleteProject\"] — batch 10"},
	"GRPC keyorix.v1.UserService.UpdateUser":         {StatusFuzzed, "opCatalog[\"GRPCUpdateUser\"] — batch 10"},
	"GRPC keyorix.v1.UserService.DeleteUser":         {StatusFuzzed, "opCatalog[\"GRPCDeleteUser\"] — batch 10"},
	"GRPC keyorix.v1.GroupService.UpdateGroup":       {StatusFuzzed, "opCatalog[\"GRPCUpdateGroup\"] — batch 10"},
	"GRPC keyorix.v1.GroupService.DeleteGroup":       {StatusFuzzed, "opCatalog[\"GRPCDeleteGroup\"] — batch 10"},
	"GRPC keyorix.v1.GroupService.RestoreGroup":      {StatusFuzzed, "opCatalog[\"GRPCRestoreGroup\"] — batch 10"},
	"GRPC keyorix.v1.GroupService.AddGroupMember":    {StatusFuzzed, "opCatalog[\"GRPCAddGroupMember\"] — batch 10"},
	"GRPC keyorix.v1.GroupService.RemoveGroupMember": {StatusFuzzed, "opCatalog[\"GRPCRemoveGroupMember\"] — batch 10"},
	"GRPC keyorix.v1.RoleService.UpdateRole":         {StatusFuzzed, "opCatalog[\"GRPCUpdateRole\"] — batch 10"},
	"GRPC keyorix.v1.RoleService.RemoveRole":         {StatusFuzzed, "opCatalog[\"GRPCRemoveRole\"] — batch 10"},
	"GRPC keyorix.v1.SecretService.CreateSecret":     {StatusFuzzed, "opCatalog[\"GRPCCreateSecret\"] — batch 10"},
	"GRPC keyorix.v1.SecretService.UpdateSecret":     {StatusFuzzed, "opCatalog[\"GRPCUpdateSecret\"] — batch 10"},
	"GRPC keyorix.v1.SecretService.DeleteSecret":     {StatusFuzzed, "opCatalog[\"GRPCDeleteSecret\"] — batch 10"},
	// Coverage batch 11 (FAULTOPS-SPEED STEP 2, wiring batch 3, 2026-09-27):
	// ordinary secret PATCH/PUT variants (classification/description/
	// retention/tags/schedule) plus the 11 admin-job on-demand triggers
	// (plain no-body POSTs, no precondition beyond the bootstrapped admin).
	"REST PATCH /api/v1/secrets/{id}/classification":       {StatusFuzzed, "opCatalog[\"ClassifySecret\"] — batch 11"},
	"REST PATCH /api/v1/secrets/{id}/description":          {StatusFuzzed, "opCatalog[\"DescribeSecret\"] — batch 11"},
	"REST PATCH /api/v1/secrets/{id}/retention":            {StatusFuzzed, "opCatalog[\"SetRetentionOverride\"] — batch 11"},
	"REST PUT /api/v1/secrets/{id}/tags":                   {StatusFuzzed, "opCatalog[\"SetTags\"] — batch 11"},
	"REST PUT /api/v1/secrets/{id}/schedule":               {StatusFuzzed, "opCatalog[\"SetSecretSchedule\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/anomaly-alerts":          {StatusFuzzed, "opCatalog[\"RunAnomalyAlerts\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/rotation-reminders":      {StatusFuzzed, "opCatalog[\"RunRotationReminders\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/expiry-reminders":        {StatusFuzzed, "opCatalog[\"RunExpiryReminders\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/compliance-digest":       {StatusFuzzed, "opCatalog[\"RunComplianceDigest\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/record-hygiene-snapshot": {StatusFuzzed, "opCatalog[\"RecordHygieneSnapshot\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/role-expiry-check":       {StatusFuzzed, "opCatalog[\"RunRoleExpiryCheck\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/check-read-quotas":       {StatusFuzzed, "opCatalog[\"RunReadQuotaCheck\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/run-alert-escalation":    {StatusFuzzed, "opCatalog[\"RunAlertEscalation\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/token-expiry-check":      {StatusFuzzed, "opCatalog[\"RunTokenExpiryCheck\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/suspend-inactive-users":  {StatusFuzzed, "opCatalog[\"SuspendInactiveUsers\"] — batch 11"},
	"REST POST /api/v1/admin/jobs/purge-audit-logs":        {StatusFuzzed, "opCatalog[\"PurgeAuditLogsJob\"] — batch 11"},

	"REST POST /api/v1/admin/impersonate":      {StatusFuzzed, "opCatalog[\"StartImpersonation\"] — batch 12"},
	"REST POST /api/v1/auth/end-impersonation": {StatusFuzzed, "opCatalog[\"EndImpersonation\"] — batch 12"},

	"REST POST /api/v1/projects/{id}/access-review/campaigns":                                    {StatusFuzzed, "opCatalog[\"OpenAccessReviewCampaign\"] — batch 13"},
	"REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close":                 {StatusFuzzed, "opCatalog[\"CloseAccessReviewCampaign\"] — batch 13"},
	"REST POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide": {StatusFuzzed, "opCatalog[\"DecideAccessReviewCampaignItem\"] — batch 13"},
	"REST POST /api/v1/projects/{id}/access-review/attest":                                       {StatusFuzzed, "opCatalog[\"AttestProjectAccessReview\"] — batch 13"},
	"REST POST /api/v1/projects/{id}/access-review/revoke":                                       {StatusFuzzed, "opCatalog[\"RevokeProjectAccessReview\"] — batch 13"},
}

func statusOf(key string) overrideEntry {
	if e, ok := operationOverrides[key]; ok {
		return e
	}
	return overrideEntry{Status: StatusPending}
}
