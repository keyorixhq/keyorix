// remote_sso.go — SSO login state for RemoteStorage. The OIDC login flow is
// server-side only; stubs here. See local_sso.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateSSOLoginState(_ context.Context, _ *models.SSOLoginState) error {
	return remoteUnsupported("CreateSSOLoginState")
}

func (rs *RemoteStorage) ConsumeSSOLoginState(_ context.Context, _ string) (*models.SSOLoginState, error) {
	return nil, remoteUnsupported("ConsumeSSOLoginState")
}
