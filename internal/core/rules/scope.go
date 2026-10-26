package rules

// Moved verbatim from internal/core/storage/types_rbac.go
// (CORE-PURE-AUTH-LEAVES-1) so PATRestriction.Allows can stay here; storage
// and core keep the name as an alias.

// Scope identifies the project/environment a role assignment or an
// authorization check applies to. It uses a 0 = global/unspecified sentinel,
// matching the stored user_roles/group_roles columns:
//
//	{0, 0}  global — every project and environment
//	{P, 0}  all environments in project P
//	{P, E}  only environment E of project P
//
// A stored assignment authorizes a target scope when its project is global or
// equal AND its environment is global or equal (see GetUserRoleIDsAt).
type Scope struct {
	ProjectID     uint
	EnvironmentID uint
}
