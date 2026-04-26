package storage

// GroupFilter defines filtering options for group queries
type GroupFilter struct {
	Name     *string
	UserID   *uint
	Page     int
	PageSize int
}

// These methods should be added to the Storage interface in interface.go
// They are defined here separately for clarity, but will need to be integrated
// into the main interface.

// Group Management Methods
// CreateGroup creates a new group
// CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error)

// GetGroup retrieves a group by ID
// GetGroup(ctx context.Context, groupID uint) (*models.Group, error)

// UpdateGroup updates an existing group
// UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error)

// DeleteGroup deletes a group
// DeleteGroup(ctx context.Context, groupID uint) error

// ListGroups lists all groups with optional filtering
// ListGroups(ctx context.Context, filter *GroupFilter) ([]*models.Group, int64, error)

// Group Membership Methods
// AddUserToGroup adds a user to a group
// AddUserToGroup(ctx context.Context, userID, groupID uint) error

// RemoveUserFromGroup removes a user from a group
// RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error

// IsGroupMember checks if a user is a member of a group
// IsGroupMember(ctx context.Context, userID, groupID uint) (bool, error)

// ListGroupMembers lists all members of a group
// ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error)

// ListUserGroups lists all groups a user is a member of
// ListUserGroups(ctx context.Context, userID uint) ([]*models.Group, error)

// Group Sharing Methods
// ShareSecretWithGroup shares a secret with a group
// ShareSecretWithGroup(ctx context.Context, secretID, ownerID, groupID uint, permission string) (*models.ShareRecord, error)

// ListGroupSharedSecrets lists all secrets shared with a group
// ListGroupSharedSecrets(ctx context.Context, groupID uint) ([]*models.SecretNode, error)

// CheckGroupSharePermission checks if a group has permission to access a secret
// CheckGroupSharePermission(ctx context.Context, secretID, groupID uint) (string, error)

// CheckUserGroupPermission checks if a user has permission to access a secret via group membership
// CheckUserGroupPermission(ctx context.Context, secretID, userID uint) (bool, string, error)
