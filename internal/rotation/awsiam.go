// awsiam.go — the AWS IAM rotation executor (ADR-047), a GENERATE-upstream backend: it
// rotates an IAM user's access key by minting a fresh key pair (the cloud generates the
// value — Keyorix does not supply it) and removing the user's prior keys, then returns
// the new credential as JSON for Keyorix to store. Credentials come from the ambient
// AWS identity chain, never from Keyorix config.
package rotation

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// iamAPI is the slice of the IAM client the executor uses — an interface seam so the
// SDK stays contained here and tests inject a fake.
type iamAPI interface {
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(ctx context.Context, in *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(ctx context.Context, in *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

// AWSIAMExecutor rotates an IAM user's access key. The stored value is JSON:
// {"access_key_id":"…","secret_access_key":"…"}.
type AWSIAMExecutor struct {
	name        string
	region      string
	allowedRefs []string
	// newClient builds an IAM client; nil uses the real client (ambient chain). Tests inject.
	newClient func(ctx context.Context) (iamAPI, error)
}

// NewAWSIAMExecutor builds an AWS IAM rotation executor. region configures the client
// (IAM is global; any region works). allowedRefs restricts which IAM usernames it may
// rotate (prefix allowlist) — required (fail-closed).
func NewAWSIAMExecutor(name, region string, allowedRefs []string) *AWSIAMExecutor {
	return &AWSIAMExecutor{name: name, region: region, allowedRefs: allowedRefs}
}

func (e *AWSIAMExecutor) Name() string { return e.name }
func (e *AWSIAMExecutor) Type() string { return "aws-iam" }

// Rotate is not the path for a generate-upstream backend: the new value is minted by
// AWS, not supplied. The rotation flow calls GenerateUpstream instead.
func (e *AWSIAMExecutor) Rotate(_ context.Context, _, _ string) error {
	return fmt.Errorf("aws-iam: backend mints the new value upstream; use GenerateUpstream")
}

func (e *AWSIAMExecutor) client(ctx context.Context) (iamAPI, error) {
	if e.newClient != nil {
		return e.newClient(ctx)
	}
	var opts []func(*awsconfig.LoadOptions) error
	if e.region != "" {
		opts = append(opts, awsconfig.WithRegion(e.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws-iam: load config: %w", err)
	}
	return iam.NewFromConfig(cfg), nil
}

// GenerateUpstream rotates IAM user `ref`'s access key: ensure room (delete a prior key
// if the user is already at the two-key limit), create a fresh key, then delete every
// prior key — so only the new key remains — and return it as JSON.
func (e *AWSIAMExecutor) GenerateUpstream(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("aws-iam: IAM username (ref) is required")
	}
	// Fail closed: a rotation backend wields a powerful ambient identity, so it must
	// carry an explicit allow-list of the usernames it may rotate.
	if len(e.allowedRefs) == 0 {
		return "", fmt.Errorf("aws-iam: backend %q has no allowed_refs configured — refusing to rotate (fail-closed)", e.name)
	}
	if !prefixAllowed(e.allowedRefs, ref) {
		return "", fmt.Errorf("aws-iam: user %q is not permitted by this backend's allowed_refs", ref)
	}
	cl, err := e.client(ctx)
	if err != nil {
		return "", err
	}

	list, err := cl.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(ref)})
	if err != nil {
		return "", fmt.Errorf("aws-iam: list access keys for %q: %w", ref, err)
	}
	prior := make([]string, 0, len(list.AccessKeyMetadata))
	for _, k := range list.AccessKeyMetadata {
		if k.AccessKeyId != nil {
			prior = append(prior, *k.AccessKeyId)
		}
	}
	// IAM caps a user at two access keys; free a slot before creating the new one.
	if len(prior) >= 2 {
		if err := e.deleteKey(ctx, cl, ref, prior[0]); err != nil {
			return "", err
		}
		prior = prior[1:]
	}

	created, err := cl.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(ref)})
	if err != nil {
		return "", fmt.Errorf("aws-iam: create access key for %q: %w", ref, err)
	}
	if created.AccessKey == nil || created.AccessKey.AccessKeyId == nil || created.AccessKey.SecretAccessKey == nil {
		return "", fmt.Errorf("aws-iam: create access key for %q returned no credential", ref)
	}
	newID := *created.AccessKey.AccessKeyId

	// Remove every prior key so only the freshly-minted one remains. Best-effort: a
	// delete failure is not fatal (the new key is already live and will be stored).
	for _, id := range prior {
		_ = e.deleteKey(ctx, cl, ref, id)
	}

	out, err := json.Marshal(map[string]string{
		"access_key_id":     newID,
		"secret_access_key": *created.AccessKey.SecretAccessKey,
	})
	if err != nil {
		return "", fmt.Errorf("aws-iam: marshal credential: %w", err)
	}
	return string(out), nil
}

func (e *AWSIAMExecutor) deleteKey(ctx context.Context, cl iamAPI, user, keyID string) error {
	if _, err := cl.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    aws.String(user),
		AccessKeyId: aws.String(keyID),
	}); err != nil {
		return fmt.Errorf("aws-iam: delete access key %s for %q: %w", keyID, user, err)
	}
	return nil
}
