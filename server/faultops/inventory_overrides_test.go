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
	// /system proxy bypass class: TransitionMachineIdentityStateProxy calls
	// coreService.Storage() directly, skipping core.* — same bypass shape as F3.
	"REST PUT /api/v1/system/machine-identities/{id}/transition": {StatusFuzzed, "opCatalog[\"TransitionMachineIdentityProxy\"] — /system direct-Storage() bypass class"},
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
	// Coverage batch 1 (of the 67 /system proxy routes): plain CRUD proxies
	// with straightforward wire shapes, picked first per the "wire /system
	// proxy routes before REST+gRPC resource CRUD" priority order.
	"REST POST /api/v1/system/machine-identities": {StatusFuzzed, "opCatalog[\"CreateMachineIdentityProxy\"] — batch 1"},
	"REST POST /api/v1/system/groups":             {StatusFuzzed, "opCatalog[\"CreateGroupProxy\"] — batch 1"},
	"REST DELETE /api/v1/system/groups/{id}":      {StatusFuzzed, "opCatalog[\"DeleteGroupProxy\"] — batch 1"},
	"REST DELETE /api/v1/system/projects/{id}":    {StatusFuzzed, "opCatalog[\"DeleteProjectProxy\"] — batch 1"},
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
}

func statusOf(key string) overrideEntry {
	if e, ok := operationOverrides[key]; ok {
		return e
	}
	return overrideEntry{Status: StatusPending}
}
