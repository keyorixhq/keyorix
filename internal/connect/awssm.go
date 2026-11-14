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
//
// A noaws build (see awssm_noaws.go, ADR-109 step 6) compiles this file out
// entirely, dropping aws-sdk-go-v2 (the packages this file alone pulls into
// this package) from the binary.
//
//go:build !noaws

package connect

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
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
	// HTTPClient: the shared hardened *http.Client (hardened_client.go),
	// replacing the SDK's own default transport/BuildableClient outright. The
	// SDK's default already happens not to follow redirects (confirmed live,
	// docs/findings/2026-09-19-FINDING-connect-response-trust-gaps.md §2), but
	// the exact internal mechanism was never fully traced -- this makes the
	// property explicit and provable (refuseRedirect) instead of relying on an
	// untraced SDK internal, and adds what the default genuinely lacks: the
	// link-local-refusing dialer and the post-decompression size cap (§3).
	// awsBaseTransport() is a REAL clone of the SDK's own default transport
	// (hardened_client.go), via its own exported constructor -- not a
	// hand-copied approximation, so it tracks the SDK's actual tuning
	// (including its FIPS-mode TLS curve-preference restriction) automatically.
	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.HTTPClient = &http.Client{
			Transport:     newConnectHardenedTransport(awsBaseTransport()),
			CheckRedirect: refuseRedirect,
		}
	}), nil
}

// unexpectedSuccessStatusError is returned for a 2xx other than 200. It carries
// only the status code, never anything the backend sent.
type unexpectedSuccessStatusError struct{ status int }

func (e unexpectedSuccessStatusError) Error() string {
	return fmt.Sprintf("unexpected success status %d (only 200 is accepted)", e.status)
}

// RetryableError tells the SDK retryer not to re-send: a peer that answered
// 2xx-but-not-200 once is not going to become the service on a retry.
func (unexpectedSuccessStatusError) RetryableError() bool { return false }

// status200Client wraps the SDK's HTTP client and refuses any 2xx response other
// than 200. The smithy awsJson1_1 client treats every 2xx as success, but Secrets
// Manager answers GetSecretValue with 200 only, so a 201/202/204/206 means the
// peer is not the service (or a proxy rewrote the exchange) and its body must
// not be trusted as a secret.
type status200Client struct{ inner secretsmanager.HTTPClient }

func (c status200Client) Do(req *http.Request) (*http.Response, error) {
	resp, err := c.inner.Do(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.StatusCode != http.StatusOK {
		status := resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, unexpectedSuccessStatusError{status: status}
	}
	return resp, nil
}

// requireHTTP200 is a per-call option that installs status200Client around
// whatever HTTP client the SDK client was built with.
func requireHTTP200(o *secretsmanager.Options) {
	inner := o.HTTPClient
	if inner == nil {
		inner = http.DefaultClient
	}
	o.HTTPClient = status200Client{inner: inner}
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
	out, err := cl.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref)}, requireHTTP200)
	if err != nil {
		return "", fmt.Errorf("aws-secrets-manager: get %q: %w", ref, err)
	}
	// SecretString != nil alone is not "has a value": the field decodes to a
	// non-nil pointer to "" for a response body like {"SecretString":""},
	// which a hostile or broken endpoint (or a struct literal built by a test)
	// can produce trivially — that must not be treated as a real secret and
	// returned as success (found by FuzzAWSSMConnectorResponse,
	// crasher 09de4b520b95a429; see
	// docs/findings/2026-09-20-FINDING-awssm-empty-secret-response.md).
	if out.SecretString != nil && *out.SecretString != "" {
		return *out.SecretString, nil
	}
	if len(out.SecretBinary) > 0 {
		// A binary secret is returned base64-encoded (the AWS console convention).
		return base64.StdEncoding.EncodeToString(out.SecretBinary), nil
	}
	return "", fmt.Errorf("aws-secrets-manager: secret %q has no value", ref)
}

func init() {
	registerCloudConnector("aws-secrets-manager", func(p ConnectorParams) Connector {
		return NewAWSSecretsManagerConnector(p.Name, p.Region, p.AccountID, p.AllowedRefs)
	})
}
