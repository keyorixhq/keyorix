// remote_secret_templates.go — RemoteStorage stubs for secret template management.
//
// The REST API (/api/v1/secret-templates) is the remote surface; the CLI uses
// common.RemoteClient directly against those endpoints. All six are intentional
// stubs documented in remote_secret_templates_completeness_test.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateSecretTemplate(_ context.Context, _ *models.SecretTemplate) error {
	return remoteUnsupported("CreateSecretTemplate")
}

func (rs *RemoteStorage) GetSecretTemplate(_ context.Context, _ uint) (*models.SecretTemplate, error) {
	return nil, remoteUnsupported("GetSecretTemplate")
}

func (rs *RemoteStorage) GetSecretTemplateByName(_ context.Context, _ string) (*models.SecretTemplate, error) {
	return nil, remoteUnsupported("GetSecretTemplateByName")
}

func (rs *RemoteStorage) ListSecretTemplates(_ context.Context) ([]*models.SecretTemplate, error) {
	return nil, remoteUnsupported("ListSecretTemplates")
}

func (rs *RemoteStorage) UpdateSecretTemplate(_ context.Context, _ *models.SecretTemplate) error {
	return remoteUnsupported("UpdateSecretTemplate")
}

func (rs *RemoteStorage) DeleteSecretTemplate(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretTemplate")
}
