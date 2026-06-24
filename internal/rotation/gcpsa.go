// gcpsa.go — the GCP service-account key rotation executor (ADR-047), a GENERATE-upstream
// backend: it rotates a service account's key by minting a fresh user-managed key (GCP
// generates it — Keyorix does not supply it) and deleting the account's prior
// user-managed keys, then returns the new key file (JSON) for Keyorix to store.
// Credentials come from Application Default Credentials, never from Keyorix config.
package rotation

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	iam "google.golang.org/api/iam/v1"
)

// gcpServiceAccountMaxKeys is GCP's per-account limit on user-managed keys; free a slot
// before creating when already at the limit.
const gcpServiceAccountMaxKeys = 10

// gcpKeyAPI is the high-level slice of the IAM key API the executor uses — an interface
// seam so the SDK stays contained here and tests inject a fake. saName is the resource
// name "projects/-/serviceAccounts/<email>"; keyName is a full key resource name.
type gcpKeyAPI interface {
	ListKeyNames(ctx context.Context, saName string) ([]string, error)
	CreateKey(ctx context.Context, saName string) (keyName, privateKeyJSON string, err error)
	DeleteKey(ctx context.Context, keyName string) error
}

// GCPServiceAccountKeyExecutor rotates a GCP service account's user-managed key. The
// stored value is the new key file as JSON.
type GCPServiceAccountKeyExecutor struct {
	name        string
	allowedRefs []string
	newClient   func(ctx context.Context) (gcpKeyAPI, error)
}

// NewGCPServiceAccountKeyExecutor builds a GCP service-account key rotation executor.
// allowedRefs restricts which service-account emails it may rotate (prefix allowlist) —
// required (fail-closed).
func NewGCPServiceAccountKeyExecutor(name string, allowedRefs []string) *GCPServiceAccountKeyExecutor {
	return &GCPServiceAccountKeyExecutor{name: name, allowedRefs: allowedRefs}
}

func (e *GCPServiceAccountKeyExecutor) Name() string { return e.name }
func (e *GCPServiceAccountKeyExecutor) Type() string { return "gcp-service-account" }

// Rotate is not the path for a generate-upstream backend: the key is minted by GCP.
func (e *GCPServiceAccountKeyExecutor) Rotate(_ context.Context, _, _ string) error {
	return fmt.Errorf("gcp-service-account: backend mints the new key upstream; use GenerateUpstream")
}

func (e *GCPServiceAccountKeyExecutor) client(ctx context.Context) (gcpKeyAPI, error) {
	if e.newClient != nil {
		return e.newClient(ctx)
	}
	svc, err := iam.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-service-account: new client: %w", err)
	}
	return &gcpIAMClient{svc: svc}, nil
}

// GenerateUpstream rotates service account `ref` (its email): free a slot if at the
// key limit, mint a fresh user-managed key, delete the prior user-managed keys, and
// return the new key file JSON.
func (e *GCPServiceAccountKeyExecutor) GenerateUpstream(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("gcp-service-account: service-account email (ref) is required")
	}
	// ref is concatenated into the SA resource name; an email never contains '/', so
	// reject one defensively (it cannot then introduce extra path segments).
	if strings.ContainsRune(ref, '/') {
		return "", fmt.Errorf("gcp-service-account: ref %q must be a service-account email, not a resource path", ref)
	}
	if len(e.allowedRefs) == 0 {
		return "", fmt.Errorf("gcp-service-account: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return "", fmt.Errorf("gcp-service-account: account %q is not permitted by this backend's allowed_refs", ref)
	}
	cl, err := e.client(ctx)
	if err != nil {
		return "", err
	}

	saName := "projects/-/serviceAccounts/" + ref
	prior, err := cl.ListKeyNames(ctx, saName)
	if err != nil {
		return "", fmt.Errorf("gcp-service-account: list keys for %q: %w", ref, err)
	}
	if len(prior) >= gcpServiceAccountMaxKeys {
		if err := cl.DeleteKey(ctx, prior[0]); err != nil {
			return "", fmt.Errorf("gcp-service-account: free key slot for %q: %w", ref, err)
		}
		prior = prior[1:]
	}

	_, keyJSON, err := cl.CreateKey(ctx, saName)
	if err != nil {
		return "", fmt.Errorf("gcp-service-account: create key for %q: %w", ref, err)
	}
	if keyJSON == "" {
		return "", fmt.Errorf("gcp-service-account: create key for %q returned no key material", ref)
	}

	// Remove every prior user-managed key so only the freshly-minted one remains.
	// Security-critical (rotation must INVALIDATE the old, possibly compromised key),
	// so a delete failure must not be swallowed and reported as success. Attempt every
	// deletion; if any survived, return a PartialRotationError carrying the new key
	// material — the caller MUST still store it (GCP returns the private key only once,
	// so discarding it would orphan a live key) while recording the rotation incomplete
	// and alerting an operator to remove the leftover key.
	var undeleted []string
	var lastErr error
	for _, kn := range prior {
		if derr := cl.DeleteKey(ctx, kn); derr != nil {
			undeleted = append(undeleted, kn)
			lastErr = derr
		}
	}
	if len(undeleted) > 0 {
		return "", &PartialRotationError{
			Value: keyJSON,
			Err: fmt.Errorf("gcp-service-account: rotated %q but failed to delete prior key(s) %v (the old key is still live and must be removed manually): %w",
				ref, undeleted, lastErr),
		}
	}
	return keyJSON, nil
}

// gcpIAMClient adapts *iam.Service to the gcpKeyAPI seam.
type gcpIAMClient struct{ svc *iam.Service }

func (g *gcpIAMClient) ListKeyNames(ctx context.Context, saName string) ([]string, error) {
	resp, err := g.svc.Projects.ServiceAccounts.Keys.List(saName).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		names = append(names, k.Name)
	}
	return names, nil
}

func (g *gcpIAMClient) CreateKey(ctx context.Context, saName string) (string, string, error) {
	key, err := g.svc.Projects.ServiceAccounts.Keys.Create(saName, &iam.CreateServiceAccountKeyRequest{}).Context(ctx).Do()
	if err != nil {
		return "", "", err
	}
	// PrivateKeyData is the base64-encoded key file; decode to the JSON credentials.
	raw, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
	if err != nil {
		return "", "", fmt.Errorf("decode private key data: %w", err)
	}
	return key.Name, string(raw), nil
}

func (g *gcpIAMClient) DeleteKey(ctx context.Context, keyName string) error {
	_, err := g.svc.Projects.ServiceAccounts.Keys.Delete(keyName).Context(ctx).Do()
	return err
}
