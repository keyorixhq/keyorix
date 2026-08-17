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
	"time"

	iam "google.golang.org/api/iam/v1"
)

// gcpServiceAccountMaxKeys is GCP's per-account limit on user-managed keys; free a slot
// before creating when already at the limit.
const gcpServiceAccountMaxKeys = 10

// gcpKeyAPI is the high-level slice of the IAM key API the executor uses — an interface
// seam so the SDK stays contained here and tests inject a fake. saName is the resource
// name "projects/-/serviceAccounts/<email>"; keyName is a full key resource name.
type gcpKeyAPI interface {
	ListKeys(ctx context.Context, saName string) ([]gcpServiceAccountKeyInfo, error)
	CreateKey(ctx context.Context, saName string) (keyName, privateKeyJSON string, err error)
	DeleteKey(ctx context.Context, keyName string) error
}

// gcpServiceAccountKeyInfo carries just enough per-key metadata to pick a safe eviction
// candidate (see evictableServiceAccountKey) without exposing the full iam.ServiceAccountKey
// SDK type through the gcpKeyAPI seam.
type gcpServiceAccountKeyInfo struct {
	Name           string
	Disabled       bool
	ValidAfterTime string // RFC3339; GCP's closest equivalent to AWS IAM's CreateDate
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
	// ref is concatenated into the SA resource name; a service-account email never
	// contains any of "/?#%", so reject them defensively (they cannot then introduce
	// extra path segments or otherwise reshape the resource name). This is layer TWO of
	// defense in depth: layer ONE is core.validateRotationRef
	// (internal/core/rotation_executor.go), which already rejects this same "/?#%" class
	// (plus SQL metacharacters and control characters) at configuration time, before the
	// ref is ever persisted. Keep both — this check must not be removed just because the
	// earlier layer also covers it.
	if strings.ContainsAny(ref, "/?#%") {
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
	prior, err := cl.ListKeys(ctx, saName)
	if err != nil {
		return "", fmt.Errorf("gcp-service-account: list keys for %q: %w", ref, err)
	}
	if len(prior) >= gcpServiceAccountMaxKeys {
		victim := evictableServiceAccountKey(prior)
		if err := cl.DeleteKey(ctx, victim); err != nil {
			return "", fmt.Errorf("gcp-service-account: free key slot for %q: %w", ref, err)
		}
		prior = removeKeyByName(prior, victim)
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
		if derr := cl.DeleteKey(ctx, kn.Name); derr != nil {
			undeleted = append(undeleted, kn.Name)
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

// evictableServiceAccountKey picks the safest key to remove when freeing a slot at the
// per-service-account key cap: a Disabled key if any (returned as soon as one is seen,
// regardless of order), otherwise the oldest by ValidAfterTime — the same
// disabled/inactive-first, then-oldest principle awsiam.go's evictableAccessKey uses for
// AWS IAM access keys, adapted to the fields GCP's ServiceAccountKey actually exposes
// (Disabled instead of an Active/Inactive status enum; ValidAfterTime, an RFC3339
// timestamp, instead of CreateDate). Returns "" when no candidate has a name.
func evictableServiceAccountKey(keys []gcpServiceAccountKeyInfo) string {
	victim := ""
	var oldest time.Time
	haveOldest := false
	for _, k := range keys {
		if k.Name == "" {
			continue
		}
		if k.Disabled {
			return k.Name
		}
		t, err := time.Parse(time.RFC3339, k.ValidAfterTime)
		if !haveOldest || (err == nil && t.Before(oldest)) {
			victim = k.Name
			if err == nil {
				oldest = t
				haveOldest = true
			}
		}
	}
	return victim
}

// removeKeyByName returns keys with the entry named victim removed (at most one, since
// key names are unique). Used after evicting a slot so the caller's local view of
// remaining prior keys stays in sync with what was actually deleted.
func removeKeyByName(keys []gcpServiceAccountKeyInfo, victim string) []gcpServiceAccountKeyInfo {
	out := make([]gcpServiceAccountKeyInfo, 0, len(keys))
	removed := false
	for _, k := range keys {
		if !removed && k.Name == victim {
			removed = true
			continue
		}
		out = append(out, k)
	}
	return out
}

// gcpIAMClient adapts *iam.Service to the gcpKeyAPI seam.
type gcpIAMClient struct{ svc *iam.Service }

func (g *gcpIAMClient) ListKeys(ctx context.Context, saName string) ([]gcpServiceAccountKeyInfo, error) {
	resp, err := g.svc.Projects.ServiceAccounts.Keys.List(saName).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	keys := make([]gcpServiceAccountKeyInfo, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, gcpServiceAccountKeyInfo{
			Name:           k.Name,
			Disabled:       k.Disabled,
			ValidAfterTime: k.ValidAfterTime,
		})
	}
	return keys, nil
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
