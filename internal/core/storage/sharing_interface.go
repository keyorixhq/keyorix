package storage

// ShareFilter defines filtering options for share queries
type ShareFilter struct {
	SecretID    *uint
	OwnerID     *uint
	RecipientID *uint
	IsGroup     *bool
	Permission  *string
	Page        int
	PageSize    int
}

// These methods should be added to the Storage interface in interface.go
// They are defined here separately for clarity, but will need to be integrated
// into the main interface.

// Share Management Methods
// CreateShareRecord creates a new share record
// CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)

// GetShareRecord retrieves a share record by ID
// GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error)

// UpdateShareRecord updates an existing share record
// UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error)

// DeleteShareRecord deletes a share record
// DeleteShareRecord(ctx context.Context, shareID uint) error

// ListSharesBySecret lists all share records for a secret
// ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error)

// ListSharesByUser lists all share records where the user is the recipient
// ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error)

// ListSharesByGroup lists all share records where the group is the recipient
// ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error)

// ListSharedSecrets lists all secrets shared with a user
// ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error)

// CheckSharePermission checks if a user has permission to access a secret
// CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error)
