// gcpsm.go — the GCP Secret Manager read-through connector. GetSecret resolves a
// reference (the secret VERSION resource name, e.g.
// projects/PROJECT/secrets/NAME/versions/latest) to its current value via
// AccessSecretVersion. Credentials come from Application Default Credentials (ADC) /
// the workload identity — never from Keyorix config — mirroring the GCP KMS and STS
// integrations.
package connect

import (
	"context"
	"fmt"

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
	allowedRefs []string
	// newClient builds an SM client; nil uses the real client (ADC). Tests inject a fake.
	newClient func(ctx context.Context) (gcpSMAccessAPI, error)
}

// NewGCPSecretManagerConnector builds a GCP Secret Manager connector. allowedRefs,
// when non-empty, restricts readable references to those with one of the given
// prefixes (a guardrail on top of the workload identity's IAM scope).
func NewGCPSecretManagerConnector(name string, allowedRefs []string) *GCPSecretManagerConnector {
	return &GCPSecretManagerConnector{name: name, allowedRefs: allowedRefs}
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
