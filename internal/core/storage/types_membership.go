package storage

type MembershipCounts struct {
	Active int
	Total  int
}

// ProjectMember is a user who holds a role at a project's scope (ADR-021).
type ProjectMember struct {
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	RoleID      uint   `json:"role_id"`
	RoleName    string `json:"role_name"`
}
