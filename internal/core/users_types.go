// users_types.go — Request/response types shared by users.go and groups.go.
package core

// CreateUserRequest represents a request to create a new user.
//
// G38: the `validate:"..."` tags below are documentation only — no validator
// library in this codebase resolves struct tags on this type (that reflection
// convention exists only in server/validation, and is never invoked here); the
// actual enforcement is validateCreateUserRequest (users.go), called from every
// creation path (CreateUser, CreateUserWithSetupLink, CreateUserWithOneTimePassword,
// CreateUserWithAssignments) via the shared buildUserForCreate. Username's tag
// previously claimed `alphanum`, a rule the live HTTP handlers never actually
// enforce (server/http/handlers/users_handler.go, users_crud.go: `min=3,max=50`
// only) — corrected here to match what's genuinely enforced, not what the tag
// merely aspired to.
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50"`
	Email       string `json:"email" validate:"required,email"`
	DisplayName string `json:"display_name" validate:"required,min=1,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	IsActive    *bool  `json:"is_active,omitempty"`
	// AccountState optionally sets the initial lifecycle state (ADR-025). Empty
	// normalizes to "active". Setup-link provisioning sets pending_first_login so the
	// account is confined from creation — no separate write that could leave it active.
	AccountState string `json:"-"`
}

// UpdateUserRequest represents a request to update an existing user.
type UpdateUserRequest struct {
	ID          uint
	Username    string
	Email       string
	DisplayName string
	IsActive    *bool
}

// CreateGroupRequest represents a request to create a new group.
type CreateGroupRequest struct {
	Name        string
	Description string
}

// UpdateGroupRequest represents a request to update an existing group.
type UpdateGroupRequest struct {
	ID          uint
	Name        string
	Description string
}
