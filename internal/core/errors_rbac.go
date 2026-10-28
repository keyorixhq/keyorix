package core

import "errors"

// Typed RBAC refusals. Each renders exactly the text the refusal always had and
// is matched with errors.Is; handlers must not classify these by message text
// (the leading part of the message is a translated i18n string).
var (
	// ErrActorLacksPermission: the actor is bundling a permission into a role
	// that they do not hold themselves (#169). Matches ErrPermissionDenied.
	ErrActorLacksPermission = newPermissionSentinel("you do not hold it yourself")

	// ErrBuiltinRole: the target is a built-in role, which cannot be updated or
	// deleted through the API. Matches ErrPermissionDenied.
	ErrBuiltinRole = newPermissionSentinel("built-in role")

	// ErrRoleNameReserved: CreateRole refused a name that collides with a
	// built-in role name (#294). Not a permission refusal; the handler answers
	// 409.
	ErrRoleNameReserved = errors.New("this role name is reserved and cannot be created")
)
