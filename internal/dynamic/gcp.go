// gcp.go — the GCP dynamic-secret backend (ADR-035, cloud-IAM): mints a short-lived
// OAuth2 access token for a service account via the IAM Credentials API
// (generateAccessToken). Like AWS STS these are ephemeral — Google enforces the
// expiry and the token cannot be revoked or renewed, so Revoke is a no-op and Renew
// is refused (issue a fresh lease).
//
// The encrypted "admin DSN" carries this backend's JSON config:
//
//	{"service_account":"sa@project.iam.gserviceaccount.com",
//	 "scopes":["https://www.googleapis.com/auth/cloud-platform"],
//	 "lifetime_seconds":3600}
//
// service_account is required; scopes defaults to cloud-platform; lifetime defaults
// to the lease TTL. Caller credentials come from Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS / workload identity) — never from Keyorix config —
// and that ADC identity must hold roles/iam.serviceAccountTokenCreator on the target
// service account. This file is the only place the GCP IAM-credentials SDK is used.
package dynamic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	iamcredentials "google.golang.org/api/iamcredentials/v1"
)

const gcpDefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// gcpTokenMinter is the slice of GCP the engine uses — an interface seam so the
// engine is unit-tested with a fake and the SDK stays contained here.
type gcpTokenMinter interface {
	mintAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (token string, expiry time.Time, err error)
}

// GCPEngine mints short-lived GCP service-account access tokens.
type GCPEngine struct {
	minter gcpTokenMinter // nil uses the real IAM Credentials client
}

func (e *GCPEngine) BackendType() string        { return "gcp" }
func (e *GCPEngine) SupportsNativeExpiry() bool { return true } // Google enforces the token TTL
func (e *GCPEngine) IsEphemeralBackend() bool   { return true }

type gcpConfig struct {
	ServiceAccount  string   `json:"service_account"`
	Scopes          []string `json:"scopes,omitempty"`
	LifetimeSeconds int      `json:"lifetime_seconds,omitempty"`
}

// Issue mints an access token for the configured service account. roleName is a
// label only — there is nothing to drop on revoke.
func (e *GCPEngine) Issue(ctx context.Context, adminDSN, _ string, ttl time.Duration) (Credential, string, error) {
	var cfg gcpConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return Credential{}, "", fmt.Errorf("gcp: config must be JSON ({\"service_account\":...}): %w", err)
	}
	if strings.TrimSpace(cfg.ServiceAccount) == "" {
		return Credential{}, "", fmt.Errorf("gcp: service_account is required")
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{gcpDefaultScope}
	}
	lifetime := ttl
	if cfg.LifetimeSeconds > 0 {
		lifetime = time.Duration(cfg.LifetimeSeconds) * time.Second
	}

	minter := e.minter
	if minter == nil {
		m, err := newRealGCPMinter(ctx)
		if err != nil {
			return Credential{}, "", err
		}
		minter = m
	}
	token, expiry, err := minter.mintAccessToken(ctx, cfg.ServiceAccount, scopes, lifetime)
	if err != nil {
		return Credential{}, "", fmt.Errorf("gcp: generate access token: %w", err)
	}

	suffix, err := randString(12)
	if err != nil {
		return Credential{}, "", err
	}
	fields := map[string]string{"access_token": token, "service_account": cfg.ServiceAccount}
	if !expiry.IsZero() {
		fields["expiration"] = expiry.UTC().Format(time.RFC3339)
	}
	return Credential{Fields: fields}, "keyorix-dyn-" + suffix, nil
}

// Revoke is a no-op: GCP access tokens self-expire and cannot be invalidated early.
func (e *GCPEngine) Revoke(_ context.Context, _, _ string) error { return nil }

// Renew is refused: a GCP token's lifetime is fixed at issue. core.RenewLease guards
// on IsEphemeralBackend before reaching here; this is a defensive backstop.
func (e *GCPEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return fmt.Errorf("gcp: access tokens are not renewable; issue a new lease instead")
}

// realGCPMinter calls the GCP IAM Credentials API via Application Default Credentials.
type realGCPMinter struct{ svc *iamcredentials.Service }

func newRealGCPMinter(ctx context.Context) (*realGCPMinter, error) {
	svc, err := iamcredentials.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: create IAM credentials client (check ADC): %w", err)
	}
	return &realGCPMinter{svc: svc}, nil
}

func (m *realGCPMinter) mintAccessToken(ctx context.Context, serviceAccount string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
	name := "projects/-/serviceAccounts/" + serviceAccount
	req := &iamcredentials.GenerateAccessTokenRequest{Scope: scopes}
	if lifetime > 0 {
		req.Lifetime = fmt.Sprintf("%ds", int(lifetime.Seconds()))
	}
	resp, err := m.svc.Projects.ServiceAccounts.GenerateAccessToken(name, req).Context(ctx).Do()
	if err != nil {
		return "", time.Time{}, err
	}
	var expiry time.Time
	if resp.ExpireTime != "" {
		expiry, _ = time.Parse(time.RFC3339, resp.ExpireTime)
	}
	return resp.AccessToken, expiry, nil
}
