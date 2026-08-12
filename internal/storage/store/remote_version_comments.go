// remote_version_comments.go — SecretVersionComment stubs for RemoteStorage.
//
// These operations are always executed server-side (the write path is the
// server's own LocalStorage). A RemoteStorage client never calls these
// directly — the HTTP handlers call the server's core.KeyorixCore, which
// reaches LocalStorage. No REST proxy route exists for them.
// For the local (GORM) equivalent see local_version_comments.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateSecretVersionComment(_ context.Context, _ *models.SecretVersionComment) error {
	return remoteUnsupported("CreateSecretVersionComment")
}

func (rs *RemoteStorage) ListSecretVersionComments(_ context.Context, _, _ uint) ([]models.SecretVersionComment, error) {
	return nil, remoteUnsupported("ListSecretVersionComments")
}

func (rs *RemoteStorage) DeleteSecretVersionComment(_ context.Context, _, _, _ uint) error {
	return remoteUnsupported("DeleteSecretVersionComment")
}
