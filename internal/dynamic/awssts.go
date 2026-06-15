// awssts.go — the AWS STS dynamic-secret backend (ADR-035, cloud-IAM): instead of
// minting a role on a database, it calls sts:AssumeRole to hand back short-lived AWS
// credentials (AccessKeyId / SecretAccessKey / SessionToken). These are ephemeral —
// AWS enforces their expiry and they cannot be revoked or renewed, so Revoke is a
// no-op and Renew is refused (issue a fresh lease instead).
//
// The encrypted "admin DSN" carries this backend's JSON config instead of a database
// connection string:
//
//	{"role_arn":"arn:aws:iam::123456789012:role/keyorix-dynamic",
//	 "region":"eu-west-1","external_id":"...","duration_seconds":3600}
//
// role_arn is required; the rest are optional. The optional creation template is used
// as an inline STS *session policy* (JSON) to further scope-down the assumed role.
// AWS credentials/region for the AssumeRole call itself come from the standard chain
// (env / instance-profile / IRSA), exactly like the KMS and S3 integrations.
package dynamic

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// stsMinDurationSeconds is the AWS AssumeRole minimum (15 minutes).
const stsMinDurationSeconds int32 = 900

// stsAssumeAPI is the slice of the STS client the engine uses — an interface seam so
// the engine is unit-tested with a fake and the SDK stays contained here.
type stsAssumeAPI interface {
	AssumeRole(ctx context.Context, in *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// AWSSTSEngine mints temporary AWS credentials via sts:AssumeRole.
type AWSSTSEngine struct {
	// newClient builds an STS client for a region; nil uses the real AWS client
	// (the standard credential chain). Tests inject a fake.
	newClient func(ctx context.Context, region string) (stsAssumeAPI, error)
}

func (e *AWSSTSEngine) BackendType() string        { return "aws-sts" }
func (e *AWSSTSEngine) SupportsNativeExpiry() bool { return true } // AWS enforces the credential TTL
func (e *AWSSTSEngine) IsEphemeralBackend() bool   { return true }

type awsSTSConfig struct {
	RoleARN         string `json:"role_arn"`
	Region          string `json:"region,omitempty"`
	ExternalID      string `json:"external_id,omitempty"`
	DurationSeconds int32  `json:"duration_seconds,omitempty"`
}

func (e *AWSSTSEngine) client(ctx context.Context, region string) (stsAssumeAPI, error) {
	if e.newClient != nil {
		return e.newClient(ctx, region)
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws-sts: load AWS config: %w", err)
	}
	return sts.NewFromConfig(cfg), nil
}

// Issue assumes the configured role and returns the temporary credential. roleName
// is the generated session name (used only as a lease label — there is nothing to
// drop on revoke). creationTemplate, when set, is an inline session policy.
func (e *AWSSTSEngine) Issue(ctx context.Context, adminDSN, creationTemplate string, ttl time.Duration) (Credential, string, error) {
	var cfg awsSTSConfig
	if err := json.Unmarshal([]byte(adminDSN), &cfg); err != nil {
		return Credential{}, "", fmt.Errorf("aws-sts: config must be JSON ({\"role_arn\":...}): %w", err)
	}
	if strings.TrimSpace(cfg.RoleARN) == "" {
		return Credential{}, "", fmt.Errorf("aws-sts: role_arn is required")
	}

	duration := cfg.DurationSeconds
	if duration <= 0 {
		duration = int32(ttl.Seconds())
	}
	if duration < stsMinDurationSeconds {
		duration = stsMinDurationSeconds // AWS rejects anything below 15 minutes
	}

	suffix, err := randString(12)
	if err != nil {
		return Credential{}, "", err
	}
	sessionName := "keyorix-dyn-" + suffix

	in := &sts.AssumeRoleInput{
		RoleArn:         aws.String(cfg.RoleARN),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(duration),
	}
	if cfg.ExternalID != "" {
		in.ExternalId = aws.String(cfg.ExternalID)
	}
	if tmpl := strings.TrimSpace(creationTemplate); tmpl != "" {
		in.Policy = aws.String(tmpl) // session policy scopes the assumed role down
	}

	client, err := e.client(ctx, cfg.Region)
	if err != nil {
		return Credential{}, "", err
	}
	out, err := client.AssumeRole(ctx, in)
	if err != nil {
		return Credential{}, "", fmt.Errorf("aws-sts: assume role: %w", err)
	}
	if out.Credentials == nil {
		return Credential{}, "", fmt.Errorf("aws-sts: assume role returned no credentials")
	}

	fields := map[string]string{
		"access_key_id":     aws.ToString(out.Credentials.AccessKeyId),
		"secret_access_key": aws.ToString(out.Credentials.SecretAccessKey),
		"session_token":     aws.ToString(out.Credentials.SessionToken),
	}
	if cfg.Region != "" {
		fields["region"] = cfg.Region
	}
	if out.Credentials.Expiration != nil {
		fields["expiration"] = out.Credentials.Expiration.UTC().Format(time.RFC3339)
	}
	return Credential{Fields: fields}, sessionName, nil
}

// Revoke is a no-op: STS credentials self-expire and cannot be invalidated early.
func (e *AWSSTSEngine) Revoke(_ context.Context, _, _ string) error { return nil }

// Renew is refused: an STS credential's lifetime is fixed at issue. core.RenewLease
// guards on IsEphemeralBackend before reaching here; this is a defensive backstop.
func (e *AWSSTSEngine) Renew(_ context.Context, _, _ string, _ time.Time) error {
	return fmt.Errorf("aws-sts: credentials are not renewable; issue a new lease instead")
}
