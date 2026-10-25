package storage

// UserGroupMembership is one user→group membership row, as returned by
// ListAllUserGroupMemberships.
type UserGroupMembership struct {
	UserID  uint `json:"user_id"`
	GroupID uint `json:"group_id"`
}
