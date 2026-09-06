// awssm.go — the AWS Secrets Manager read-through connector. GetSecret resolves a
// reference (the secret name or ARN) to its current value via GetSecretValue. AWS
// credentials/region come from the standard chain (env / instance-profile / IRSA),
// exactly like the STS dynamic backend and the KMS/S3 integrations — never from
// Keyorix config.
//
// Confused-deputy scope (mirrors the gcp-secret-manager connector's project_id pin,
// #431/ADR-082, but with a materially different risk shape): the AWS Secrets Manager
// SecretId parameter accepts either a bare secret name or a full ARN
// (arn:PARTITION:secretsmanager:REGION:ACCOUNT:secret:NAME). A bare name is ALWAYS
// resolved within the account of the ambient credential itself — the AWS API gives
// no way to cross accounts with a bare name, so that shape has no confused-deputy gap
// at all. A full ARN naming a DIFFERENT account can still succeed if that target
// account's own resource-based (Secrets Manager resource) policy has separately
// granted this connector's ambient identity cross-account access — unlike GCP, where
// ANY ref reaches ANY project the ADC identity can access with no additional
// opt-in on the target's side, AWS's gap requires the target account to have
// independently granted access too (a double opt-in, not a single one). Because of
// that narrower shape, accountID is an OPTIONAL pin, not a mandatory one like GCP's
// projectID: an operator whose connector only ever reads
// bare-name refs gets zero benefit from being forced to set it. When set, GetSecret
// independently refuses any ARN-shaped ref naming a different account (defense in
// depth on top of internal/config.validateConnectAWSAccountID's boot-time format
// check) — but this enforcement only bites ARN-shaped refs; a bare-name ref carries
// no account segment to check, by construction, regardless of whether accountID is
// configured.
package connect

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

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
	accountID   string
	allowedRefs []string
	// newClient builds an SM client for the region; nil uses the real AWS client
	// (the standard credential chain). Tests inject a fake.
	newClient func(ctx context.Context, region string) (smSecretGetter, error)
}

// NewAWSSecretsManagerConnector builds an AWS Secrets Manager connector. accountID,
// when set, pins the connector to a single AWS account: any ARN-shaped ref naming a
// DIFFERENT account is rejected before the backend call (see this file's own doc
// comment for the full confused-deputy rationale and why, unlike GCP's projectID,
// this pin is optional rather than mandatory, and only bites ARN-shaped refs — a
// bare secret name never carries a competing account to check against). allowedRefs,
// when non-empty, restricts readable references to those with one of the given
// prefixes (a guardrail on top of the AWS IAM scope of the ambient identity).
func NewAWSSecretsManagerConnector(name, region, accountID string, allowedRefs []string) *AWSSecretsManagerConnector {
	return &AWSSecretsManagerConnector{name: name, region: region, accountID: accountID, allowedRefs: allowedRefs}
}

// awsRefAccountID extracts the account ID segment from a Secrets Manager ARN
// (arn:PARTITION:secretsmanager:REGION:ACCOUNT:secret:NAME-SUFFIX — PARTITION is
// "aws", "aws-cn", or "aws-us-gov"). It returns ok = false for anything that isn't
// shaped like a Secrets Manager ARN, including a bare secret name — which is the
// common ref shape and, per this connector's own doc comment, never carries an
// account segment to check in the first place.
func awsRefAccountID(ref string) (account string, ok bool) {
	parts := strings.SplitN(ref, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "secretsmanager" {
		return "", false
	}
	if parts[4] == "" {
		return "", false
	}
	return parts[4], true
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
	// account_id is an optional pin (unlike gcp-secret-manager's mandatory
	// project_id — see this file's doc comment for why the risk shape differs).
	// It only has anything to check when ref is a full ARN; a bare secret name
	// carries no account segment and is unaffected either way.
	if c.accountID != "" {
		if refAccount, ok := awsRefAccountID(ref); ok && refAccount != c.accountID {
			return "", fmt.Errorf("aws-secrets-manager: ref %q targets account %q, but this connector is pinned to account %q", ref, refAccount, c.accountID)
		}
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
