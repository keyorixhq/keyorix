// remote_mfa.go — MFA persistence is server-side only; the remote client never
// manages MFA state directly (enrolment/verify go through the server's REST API).
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error {
	return remoteUnsupported("UpsertMFASecret")
}

func (rs *RemoteStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, remoteUnsupported("GetMFASecret")
}

func (rs *RemoteStorage) ActivateMFASecret(_ context.Context, _ uint) error {
	return remoteUnsupported("ActivateMFASecret")
}

func (rs *RemoteStorage) DeleteMFAForUser(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteMFAForUser")
}

func (rs *RemoteStorage) SetUserMFAEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserMFAEnabled")
}

func (rs *RemoteStorage) CreateMFARecoveryCodes(_ context.Context, _ uint, _ []string) error {
	return remoteUnsupported("CreateMFARecoveryCodes")
}

func (rs *RemoteStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, remoteUnsupported("ConsumeMFARecoveryCode")
}

func (rs *RemoteStorage) CreateMFAChallenge(_ context.Context, _ *models.MFAChallenge) error {
	return remoteUnsupported("CreateMFAChallenge")
}

func (rs *RemoteStorage) ConsumeMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, remoteUnsupported("ConsumeMFAChallenge")
}

func (rs *RemoteStorage) GetActiveMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, remoteUnsupported("GetActiveMFAChallenge")
}

// WebAuthn persistence is server-side only (ADR-036); the remote client manages
// passkeys through the server's REST API, not the storage interface directly.
func (rs *RemoteStorage) CreateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return remoteUnsupported("CreateWebAuthnCredential")
}
func (rs *RemoteStorage) ListWebAuthnCredentials(_ context.Context, _ uint) ([]*models.WebAuthnCredential, error) {
	return nil, remoteUnsupported("ListWebAuthnCredentials")
}
func (rs *RemoteStorage) GetWebAuthnCredentialByCredID(_ context.Context, _ []byte) (*models.WebAuthnCredential, error) {
	return nil, remoteUnsupported("GetWebAuthnCredentialByCredID")
}
func (rs *RemoteStorage) UpdateWebAuthnCredential(_ context.Context, _ *models.WebAuthnCredential) error {
	return remoteUnsupported("UpdateWebAuthnCredential")
}
func (rs *RemoteStorage) DeleteWebAuthnCredential(_ context.Context, _, _ uint) error {
	return remoteUnsupported("DeleteWebAuthnCredential")
}
func (rs *RemoteStorage) CountWebAuthnCredentials(_ context.Context, _ uint) (int64, error) {
	return 0, remoteUnsupported("CountWebAuthnCredentials")
}
func (rs *RemoteStorage) SetUserWebAuthnEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserWebAuthnEnabled")
}
func (rs *RemoteStorage) CreateWebAuthnSession(_ context.Context, _ *models.WebAuthnSession) error {
	return remoteUnsupported("CreateWebAuthnSession")
}
func (rs *RemoteStorage) ConsumeWebAuthnSession(_ context.Context, _ string, _ time.Time) (*models.WebAuthnSession, error) {
	return nil, remoteUnsupported("ConsumeWebAuthnSession")
}
