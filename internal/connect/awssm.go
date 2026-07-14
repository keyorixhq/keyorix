// awssm.go — the AWS Secrets Manager read-through connector. GetSecret resolves a
// reference (the secret name or ARN) to its current value via GetSecretValue. AWS
// credentials/region come from the standard chain (env / instance-profile / IRSA),
// exactly like the STS dynamic backend and the KMS/S3 integrations — never from
// Keyorix config.
package connect

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// smSecretGetter is the slice of the Secrets Manager client the connector uses — an
// interface seam so it is unit-tested with a fake and the SDK stays contained here.
type smSecretGetter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSecretsManagerConnector reads secrets from AWS Secrets Manager.
type AWSSecretsManagerConnector struct {
	name        string
	region      string
	allowedRefs []string
	// newClient builds an SM client for the region; nil uses the real AWS client
	// (the standard credential chain). Tests inject a fake.
	newClient func(ctx context.Context, region string) (smSecretGetter, error)
}

// NewAWSSecretsManagerConnector builds an AWS Secrets Manager connector. allowedRefs,
// when non-empty, restricts readable references to those with one of the given
// prefixes (a guardrail on top of the AWS IAM scope of the ambient identity).
func NewAWSSecretsManagerConnector(name, region string, allowedRefs []string) *AWSSecretsManagerConnector {
	return &AWSSecretsManagerConnector{name: name, region: region, allowedRefs: allowedRefs}
}

func (c *AWSSecretsManagerConnector) Name() string { return c.name }
func (c *AWSSecretsManagerConnector) Type() string { return "aws-secrets-manager" }

func (c *AWSSecretsManagerConnector) client(ctx context.Context) (smSecretGetter, error) {
	if c.newClient != nil {
		return c.newClient(ctx, c.region)
	}
	var opts []func(*awsconfig.LoadOptions) error
	if c.region != "" {
		opts = append(opts, awsconfig.WithRegion(c.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws-secrets-manager: load AWS config: %w", err)
	}
	return secretsmanager.NewFromConfig(cfg), nil
}

func (c *AWSSecretsManagerConnector) GetSecret(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("aws-secrets-manager: secret reference is required")
	}
	if !prefixAllowed(c.allowedRefs, ref) {
		return "", fmt.Errorf("aws-secrets-manager: ref %q is not permitted by this connector's allowed_refs", ref)
	}
	cl, err := c.client(ctx)
	if err != nil {
		return "", err
	}
	out, err := cl.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref)})
	if err != nil {
		return "", fmt.Errorf("aws-secrets-manager: get %q: %w", ref, err)
	}
	if out.SecretString != nil {
		return *out.SecretString, nil
	}
	if len(out.SecretBinary) > 0 {
		// A binary secret is returned base64-encoded (the AWS console convention).
		return base64.StdEncoding.EncodeToString(out.SecretBinary), nil
	}
	return "", fmt.Errorf("aws-secrets-manager: secret %q has no value", ref)
}
