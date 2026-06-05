// users_types.go — Request/response types shared by users.go and groups.go.
package core

// CreateUserRequest represents a request to create a new user.
type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=50,alphanum"`
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
