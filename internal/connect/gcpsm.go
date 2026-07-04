// gcpsm.go — the GCP Secret Manager read-through connector. GetSecret resolves a
// reference (the secret VERSION resource name, e.g.
// projects/PROJECT/secrets/NAME/versions/latest) to its current value via
// AccessSecretVersion. Credentials come from Application Default Credentials (ADC) /
// the workload identity — never from Keyorix config — mirroring the GCP KMS and STS
// integrations.
//
// Unlike the Vault connector (pinned to one address) and the Azure connector (pinned
// to one vaultURL), the GCP project ID lives entirely inside the caller-supplied ref
// — so an unpinned connector can address secrets in any project the ambient identity
// can reach. Setting projectID (#431) pins the connector to a single project and
// rejects any ref embedding a different one.
package connect

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
)

// gcpSMAccessAPI is the slice of the Secret Manager client the connector uses — an
// interface seam so it is unit-tested with a fake and the SDK stays contained here.
// Close releases the underlying gRPC connection.
type gcpSMAccessAPI interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// GCPSecretManagerConnector reads secrets from GCP Secret Manager.
type GCPSecretManagerConnector struct {
	name        string
	projectID   string
	allowedRefs []string
	// newClient builds an SM client; nil uses the real client (ADC). Tests inject a fake.
	newClient func(ctx context.Context) (gcpSMAccessAPI, error)
}

// NewGCPSecretManagerConnector builds a GCP Secret Manager connector. projectID,
// when non-empty, pins the connector to a single GCP project — mirroring how the
// Vault connector pins an address and the Azure connector pins a vaultURL: every ref
// passed to GetSecret must embed this exact project ID (`projects/PROJECT/...`), or
// the read is rejected before ever reaching the backend. Unlike Vault/Azure, a GCP
// ref carries its own project ID, so without this pin a single configured connector
// (and the ambient ADC identity it runs under) can address secrets in ANY project
// that identity can reach, with only allowedRefs standing in the way — leave
// projectID empty only for backward compatibility with an existing config that
// intentionally spans multiple projects. allowedRefs, when non-empty, restricts
// readable references to those with one of the given prefixes (a guardrail on top of
// the workload identity's IAM scope).
func NewGCPSecretManagerConnector(name, projectID string, allowedRefs []string) *GCPSecretManagerConnector {
	return &GCPSecretManagerConnector{name: name, projectID: projectID, allowedRefs: allowedRefs}
}

// gcpRefProjectID extracts the project ID embedded in a GCP Secret Manager version
// resource name (`projects/PROJECT/secrets/NAME/versions/VERSION`). It returns ok =
// false if ref does not start with the expected "projects/" segment.
func gcpRefProjectID(ref string) (project string, ok bool) {
	const prefix = "projects/"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	rest := ref[len(prefix):]
	project, _, found := strings.Cut(rest, "/")
	if !found || project == "" {
		return "", false
	}
	return project, true
}

func (c *GCPSecretManagerConnector) Name() string { return c.name }
func (c *GCPSecretManagerConnector) Type() string { return "gcp-secret-manager" }

func (c *GCPSecretManagerConnector) client(ctx context.Context) (gcpSMAccessAPI, error) {
	if c.newClient != nil {
		return c.newClient(ctx)
	}
	cl, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp-secret-manager: new client: %w", err)
	}
	return cl, nil
}

func (c *GCPSecretManagerConnector) GetSecret(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("gcp-secret-manager: secret reference is required (a version resource name, e.g. projects/P/secrets/NAME/versions/latest)")
	}
	if !prefixAllowed(c.allowedRefs, ref) {
		return "", fmt.Errorf("gcp-secret-manager: ref %q is not permitted by this connector's allowed_refs", ref)
	}
	if c.projectID != "" {
		refProject, ok := gcpRefProjectID(ref)
		if !ok {
			return "", fmt.Errorf("gcp-secret-manager: ref %q does not start with projects/PROJECT/... so it cannot be checked against the connector's pinned project %q", ref, c.projectID)
		}
		if refProject != c.projectID {
			return "", fmt.Errorf("gcp-secret-manager: ref %q targets project %q, but this connector is pinned to project %q", ref, refProject, c.projectID)
		}
	}
	cl, err := c.client(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = cl.Close() }()

	out, err := cl.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: ref})
	if err != nil {
		return "", fmt.Errorf("gcp-secret-manager: access %q: %w", ref, err)
	}
	if out.GetPayload() == nil || len(out.GetPayload().GetData()) == 0 {
		return "", fmt.Errorf("gcp-secret-manager: secret %q has no value", ref)
	}
	return string(out.GetPayload().GetData()), nil
}
