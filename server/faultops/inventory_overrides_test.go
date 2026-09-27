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
	// Coverage batch 9 (FAULTOPS-SPEED STEP 2, 2026-09-27): secret
	// ACL/share/rotation family — highest security value per the STEP 1 plan.
	// /system routes were deliberately skipped this batch: PR #2171 (ADR-108
	// Phase 6 step 14c-1) deletes the entire /system route tier, so wiring
	// more of it would be wasted work.
	"REST POST /api/v1/secrets/{id}/acl":                 {StatusFuzzed, "opCatalog[\"GrantSecretACL\"] — batch 9"},
	"REST DELETE /api/v1/secrets/{id}/acl/{aclId}":       {StatusFuzzed, "opCatalog[\"RevokeSecretACL\"] — batch 9"},
	"GRPC keyorix.v1.SecretService.GrantSecretACL":       {StatusFuzzed, "opCatalog[\"GRPCGrantSecretACL\"] — batch 9"},
	"GRPC keyorix.v1.SecretService.RevokeSecretACL":      {StatusFuzzed, "opCatalog[\"GRPCRevokeSecretACL\"] — batch 9"},
	"REST PATCH /api/v1/secrets/{id}/auto-rotate":        {StatusFuzzed, "opCatalog[\"SetAutoRotate\"] — batch 9"},
	"GRPC keyorix.v1.SecretService.SetSecretAutoRotate":  {StatusFuzzed, "opCatalog[\"GRPCSetSecretAutoRotate\"] — batch 9"},
	"REST POST /api/v1/secrets/{id}/rotate":              {StatusFuzzed, "opCatalog[\"RotateSecret\"] — batch 9"},
	"REST POST /api/v1/secrets/{id}/rollback":            {StatusFuzzed, "opCatalog[\"RollbackSecret\"] — batch 9"},
	"REST POST /api/v1/secrets/{id}/share":               {StatusFuzzed, "opCatalog[\"ShareSecret\"] — batch 9"},
	"REST PUT /api/v1/shares/{id}":                       {StatusFuzzed, "opCatalog[\"UpdateSharePermission\"] — batch 9"},
	"REST DELETE /api/v1/shares/{id}":                    {StatusFuzzed, "opCatalog[\"RevokeShare\"] — batch 9"},
	"GRPC keyorix.v1.ShareService.ShareSecret":           {StatusFuzzed, "opCatalog[\"GRPCShareSecret\"] — batch 9"},
	"GRPC keyorix.v1.ShareService.UpdateSharePermission": {StatusFuzzed, "opCatalog[\"GRPCUpdateSharePermission\"] — batch 9"},
	"GRPC keyorix.v1.ShareService.RevokeShare":           {StatusFuzzed, "opCatalog[\"GRPCRevokeShare\"] — batch 9"},
}

func statusOf(key string) overrideEntry {
	if e, ok := operationOverrides[key]; ok {
		return e
	}
	return overrideEntry{Status: StatusPending}
}
