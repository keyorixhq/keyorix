// azure.go — the Azure dynamic-secret backend (ADR-035, cloud-IAM): mints a
// short-lived Azure AD (Entra) access token for the requested scope via the ambient
// workload identity. Like AWS STS / GCP these are ephemeral — Azure enforces the
// expiry and the token cannot be revoked or renewed, so Revoke is a no-op and Renew
// is refused (issue a fresh lease).
//
// The encrypted "admin DSN" carries this backend's JSON config:
//
//	{"scopes":["https://management.azure.com/.default"]}
//
// scopes is required (an Entra resource scope ending in /.default, or a delegated
// scope). The token is acquired with DefaultAzureCredential (env vars, managed
// identity, workload identity) — never from Keyorix config. This file is the only
// place the Azure identity SDK is used by the dynamic engine.
package dynamic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// azureTokenMinter is the slice of Azure the engine uses — an interface seam so the
// engine is unit-tested with a fake and the SDK stays contained here.
type azureTokenMinter interface {
	mintToken(ctx context.Context, scopes []string) (token string, expiry time.Time, err error)
}

// AzureEngine mints short-lived Azure AD access tokens.
type AzureEngine struct {
	minter azureTokenMinter // nil uses the real DefaultAzureCredential
}

func (e *AzureEngine) BackendType() string        { return "azure" }
func (e *AzureEngine) SupportsNativeExpiry() bool { return true } // Azure enforces the token TTL
func (e *AzureEngine) IsEphemeralBackend() bool   { return true }

type azureConfig struct {
	Scopes []string `json:"scopes"`
}

// Issue acquires an Azure AD token for the configured scopes. roleName is a label
// only — there is nothing to drop on revoke. ttl is not used: Azure fixes the token
// lifetime (the Keyorix lease still expires at now+ttl).
func (e *AzureEngine) Issue(ctx context.Context, adminDSN, _ string, _ time.Duration) (Credential, string, error) {
	var cfg azureConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return Credential{}, "", fmt.Errorf("azure: config must be JSON ({\"scopes\":[...]}): %w", err)
	}
	if len(cfg.Scopes) == 0 {
		return Credential{}, "", fmt.Errorf("azure: scopes is required (e.g. [\"https://management.azure.com/.default\"])")
	}

	minter := e.minter
	if minter == nil {
		m, err := newRealAzureMinter()
		if err != nil {
			return Credential{}, "", err
		}
		minter = m
	}
	token, expiry, err := minter.mintToken(ctx, cfg.Scopes)
	if err != nil {
		return Credential{}, "", fmt.Errorf("azure: acquire token: %w", err)
	}

	suffix, err := randString(12)
	if err != nil {
		return Credential{}, "", err
	}
	fields := map[string]string{"access_token": token}
	if !expiry.IsZero() {
		fields["expiration"] = expiry.UTC().Format(time.RFC3339)
	}
	return Credential{Fields: fields}, "keyorix-dyn-" + suffix, nil
}

// Revoke is a no-op: Azure AD tokens self-expire and cannot be invalidated early.
func (e *AzureEngine) Revoke(_ context.Context, _, _ string) error { return nil }

// Renew is refused: an Azure token's lifetime is fixed at issue. core.RenewLease
// guards on IsEphemeralBackend before reaching here; this is a defensive backstop.
func (e *AzureEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return fmt.Errorf("azure: access tokens are not renewable; issue a new lease instead")
}

// realAzureMinter acquires tokens via DefaultAzureCredential.
type realAzureMinter struct {
	cred *azidentity.DefaultAzureCredential
}

func newRealAzureMinter() (*realAzureMinter, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build default credential: %w", err)
	}
	return &realAzureMinter{cred: cred}, nil
}

func (m *realAzureMinter) mintToken(ctx context.Context, scopes []string) (string, time.Time, error) {
	tok, err := m.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		return "", time.Time{}, err
	}
	return tok.Token, tok.ExpiresOn, nil
}
