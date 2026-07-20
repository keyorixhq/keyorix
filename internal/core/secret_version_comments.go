// secret_version_comments.go — free-text annotations on secret versions.
//
// A SecretVersionComment records why a specific version was created or changed,
// providing a human-readable audit trail alongside the cryptographic version history.
package core

import (
	"context"
	"errors"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateVersionCommentRequest carries all fields needed to create a comment.
// The handler resolves the authenticated user from the middleware context and
// populates UserID/Username before calling CreateSecretVersionComment.
type CreateVersionCommentRequest struct {
	SecretID  uint
	VersionID uint
	Comment   string
	UserID    uint
	Username  string
}

// CreateSecretVersionComment annotates a secret version with a free-text comment.
func (k *KeyorixCore) CreateSecretVersionComment(ctx context.Context, req CreateVersionCommentRequest) (*models.SecretVersionComment, error) {
	if req.Comment == "" {
		return nil, errors.New("comment is required")
	}
	c := &models.SecretVersionComment{
		VersionID: req.VersionID,
		SecretID:  req.SecretID,
		UserID:    req.UserID,
		Username:  req.Username,
		Comment:   req.Comment,
	}
	if err := k.storage.CreateSecretVersionComment(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

// ListSecretVersionComments returns all comments for a given version, oldest first.
func (k *KeyorixCore) ListSecretVersionComments(ctx context.Context, versionID uint) ([]models.SecretVersionComment, error) {
	return k.storage.ListSecretVersionComments(ctx, versionID)
}

// DeleteSecretVersionComment removes a comment by ID.
func (k *KeyorixCore) DeleteSecretVersionComment(ctx context.Context, id uint) error {
	return k.storage.DeleteSecretVersionComment(ctx, id)
}
