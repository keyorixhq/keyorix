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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
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
func (e *AWSIAMExecutor) GenerateUpstream(ctx context.Context, ref string) (string, error) { // NOSONAR -- cognitive complexity 26, suppress go:S3776
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
	// IAM caps a user at two access keys. Only when both slots are full must we delete
	// one BEFORE creating the new key (the create would otherwise fail) — that is the one
	// unavoidable "revoke-before-mint" window. Minimise its blast radius by evicting the
	// safest victim: an Inactive key if present, else the oldest by CreateDate, so we
	// don't revoke a freshly-active credential and keep the most-likely-in-use key live
	// until the new one is minted. Below the cap we skip this and create first, then
	// delete priors (no window at all).
	if len(prior) >= 2 {
		victim := evictableAccessKey(list.AccessKeyMetadata)
		if victim == "" {
			victim = prior[0]
		}
		if err := e.deleteKey(ctx, cl, ref, victim); err != nil {
			return "", err
		}
		filtered := prior[:0]
		for _, id := range prior {
			if id != victim {
				filtered = append(filtered, id)
			}
		}
		prior = filtered
	}

	created, err := cl.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{UserName: aws.String(ref)})
	if err != nil {
		return "", fmt.Errorf("aws-iam: create access key for %q: %w", ref, err)
	}
	if created.AccessKey == nil || created.AccessKey.AccessKeyId == nil || created.AccessKey.SecretAccessKey == nil {
		return "", fmt.Errorf("aws-iam: create access key for %q returned no credential", ref)
	}
	newID := *created.AccessKey.AccessKeyId

	out, err := json.Marshal(map[string]string{
		"access_key_id":     newID,
		"secret_access_key": *created.AccessKey.SecretAccessKey,
	})
	if err != nil {
		return "", fmt.Errorf("aws-iam: marshal credential: %w", err)
	}

	// Remove every prior key so only the freshly-minted one remains. This is the
	// security-critical step — rotation exists to INVALIDATE the old (possibly
	// compromised) credential — so a delete failure must NOT be swallowed and the
	// run reported as success. Attempt every deletion, then, if any survived, return
	// a PartialRotationError carrying the new value: the caller stores the new
	// credential (so it isn't lost) but records the rotation as incomplete and alerts
	// an operator to remove the leftover key.
	var undeleted []string
	var lastErr error
	for _, id := range prior {
		if derr := e.deleteKey(ctx, cl, ref, id); derr != nil {
			undeleted = append(undeleted, id)
			lastErr = derr
		}
	}
	if len(undeleted) > 0 {
		return "", &PartialRotationError{
			Value: string(out),
			Err: fmt.Errorf("aws-iam: rotated %q but failed to delete prior access key(s) %v (the old credential is still live and must be removed manually): %w",
				ref, undeleted, lastErr),
		}
	}
	return string(out), nil
}

// evictableAccessKey picks the safest key to remove when freeing a slot at the IAM
// two-key cap: an Inactive key if any (returned as soon as one is seen, regardless of
// order), otherwise the oldest by CreateDate. Returns "" when no candidate has an ID.
func evictableAccessKey(keys []iamtypes.AccessKeyMetadata) string {
	victim := ""
	var oldest *time.Time
	for _, k := range keys {
		if k.AccessKeyId == nil {
			continue
		}
		if k.Status == iamtypes.StatusTypeInactive {
			return *k.AccessKeyId
		}
		if oldest == nil || (k.CreateDate != nil && k.CreateDate.Before(*oldest)) {
			victim = *k.AccessKeyId
			oldest = k.CreateDate
		}
	}
	return victim
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
