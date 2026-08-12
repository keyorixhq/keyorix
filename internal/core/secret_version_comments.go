// secret_version_comments.go — free-text annotations on secret versions.
//
// A SecretVersionComment records why a specific version was created or changed,
// providing a human-readable audit trail alongside the cryptographic version history.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
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

// versionBelongsToSecret confirms versionID is actually one of secretID's own
// versions, so a caller authorized on secretID (the router already checked
// that) cannot supply an arbitrary versionID belonging to a different,
// unauthorized secret and reach its comments (#G53 — BOLA via an
// un-cross-checked sub-resource ID).
func (k *KeyorixCore) versionBelongsToSecret(ctx context.Context, secretID, versionID uint) error {
	versions, err := k.GetSecretVersions(ctx, secretID)
	if err != nil {
		return err
	}
	for _, v := range versions {
		if v.ID == versionID {
			return nil
		}
	}
	return fmt.Errorf("%s: version %d does not belong to secret %d", i18n.T("ErrorVersionNotFound", nil), versionID, secretID)
}

// CreateSecretVersionComment annotates a secret version with a free-text comment.
func (k *KeyorixCore) CreateSecretVersionComment(ctx context.Context, req CreateVersionCommentRequest) (*models.SecretVersionComment, error) {
	if req.Comment == "" {
		return nil, errors.New("comment is required")
	}
	if err := k.versionBelongsToSecret(ctx, req.SecretID, req.VersionID); err != nil {
		return nil, err
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

// ListSecretVersionComments returns all comments for versionID, oldest first —
// scoped to secretID so the caller (already authorized on secretID by the
// router) cannot list another secret's comments via its VersionID (#G53).
func (k *KeyorixCore) ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error) {
	if err := k.versionBelongsToSecret(ctx, secretID, versionID); err != nil {
		return nil, err
	}
	return k.storage.ListSecretVersionComments(ctx, secretID, versionID)
}

// DeleteSecretVersionComment removes the comment with the given ID, but only if
// it belongs to secretID/versionID — cross-checked at both this layer and the
// storage layer (#G53).
func (k *KeyorixCore) DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error {
	if err := k.versionBelongsToSecret(ctx, secretID, versionID); err != nil {
		return err
	}
	return k.storage.DeleteSecretVersionComment(ctx, secretID, versionID, id)
}
