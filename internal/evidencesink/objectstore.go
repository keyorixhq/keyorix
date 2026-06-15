// objectstore.go — an S3-compatible object-storage evidence target. Each scheduled
// run uploads the pack (and, when signed, its detached HMAC signature) to a bucket,
// so evidence survives the node without a mounted volume and lands in immutable /
// object-locked storage an auditor can pull from. Works with AWS S3 and S3-compatible
// stores (MinIO, Cloudflare R2, Backblaze B2, GCS interop) via a custom endpoint.
// This is the ONLY file that imports the S3 SDK, keeping the dependency contained.
//
// When object-lock is configured, each uploaded object is stamped with an S3 Object
// Lock retention (GOVERNANCE or COMPLIANCE mode + a retain-until date) so the evidence
// is WORM-protected — it cannot be overwritten or deleted before it expires. The
// bucket itself must have Object Lock enabled (a create-time bucket property an
// operator sets); this sets the per-object retention on write.
package evidencesink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// ObjectStoreConfig configures the S3-compatible object-storage target. Credentials
// are NOT taken here — they resolve via the standard AWS chain (AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY env vars, shared config, or instance/workload identity).
type ObjectStoreConfig struct {
	Bucket       string // required — destination bucket
	Prefix       string // optional key prefix, e.g. "keyorix/evidence/"
	Region       string // bucket region (any value for some S3-compatible stores)
	Endpoint     string // optional custom endpoint for S3-compatible stores (MinIO/R2/…)
	UsePathStyle bool   // path-style addressing — required by MinIO and some gateways

	// LockMode opts into S3 Object Lock retention on each uploaded object: ""
	// (off), "governance", or "compliance". The bucket must have Object Lock enabled.
	LockMode string
	// LockRetainDays is the retention period in days applied from upload time.
	// Required (> 0) when LockMode is set.
	LockRetainDays int
}

// s3PutAPI is the slice of the S3 client the sink uses — an interface seam so the
// delivery logic is unit-tested with a fake and the SDK stays inside this adapter.
type s3PutAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// ObjectStore delivers the evidence pack to an S3-compatible bucket.
type ObjectStore struct {
	api      s3PutAPI
	bucket   string
	prefix   string
	lockMode s3types.ObjectLockMode // "" when object lock is off
	retain   time.Duration
	now      func() time.Time
}

// objectLockMode maps the config string to the S3 enum, validating it.
func objectLockMode(mode string) (s3types.ObjectLockMode, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return "", nil
	case "governance":
		return s3types.ObjectLockModeGovernance, nil
	case "compliance":
		return s3types.ObjectLockModeCompliance, nil
	default:
		return "", fmt.Errorf("evidencesink: object_lock_mode must be governance, compliance, or empty (got %q)", mode)
	}
}

// NewObjectStore builds the S3-compatible sink. The bucket is required; credentials
// resolve via the default AWS credential chain.
func NewObjectStore(ctx context.Context, cfg ObjectStoreConfig) (*ObjectStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("evidencesink: object-store bucket is required")
	}
	lockMode, err := objectLockMode(cfg.LockMode)
	if err != nil {
		return nil, err
	}
	if lockMode != "" && cfg.LockRetainDays <= 0 {
		return nil, fmt.Errorf("evidencesink: object_lock_retain_days must be > 0 when object_lock_mode is set")
	}
	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("evidencesink: load AWS config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.UsePathStyle
	})
	return &ObjectStore{
		api:      client,
		bucket:   cfg.Bucket,
		prefix:   normalizePrefix(cfg.Prefix),
		lockMode: lockMode,
		retain:   time.Duration(cfg.LockRetainDays) * 24 * time.Hour,
		now:      time.Now,
	}, nil
}

// ForwardEvidence uploads the pack to <prefix><name> and, when signed, the detached
// signature to <prefix><name>.sig. A failure on either upload fails the delivery.
func (o *ObjectStore) ForwardEvidence(ctx context.Context, name string, data []byte, signature string) error {
	key := o.prefix + name
	if _, err := o.api.PutObject(ctx, o.putInput(key, bytes.NewReader(data), "application/json")); err != nil {
		return fmt.Errorf("evidencesink: put %s: %w", key, err)
	}
	if signature != "" {
		sigKey := key + ".sig"
		if _, err := o.api.PutObject(ctx, o.putInput(sigKey, strings.NewReader(signature), "text/plain")); err != nil {
			return fmt.Errorf("evidencesink: put %s: %w", sigKey, err)
		}
	}
	return nil
}

// putInput builds a PutObjectInput, adding Object Lock retention when configured so
// the written object is WORM-protected for the retention window.
func (o *ObjectStore) putInput(key string, body io.Reader, contentType string) *s3.PutObjectInput {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(o.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	}
	if o.lockMode != "" {
		in.ObjectLockMode = o.lockMode
		in.ObjectLockRetainUntilDate = aws.Time(o.now().Add(o.retain))
	}
	return in
}

// Target labels this forwarder in the export result.
func (o *ObjectStore) Target() string {
	if o.lockMode != "" {
		return fmt.Sprintf("objectstore:%s/%s (lock:%s)", o.bucket, o.prefix, strings.ToLower(string(o.lockMode)))
	}
	return fmt.Sprintf("objectstore:%s/%s", o.bucket, o.prefix)
}

// normalizePrefix ensures a non-empty prefix ends in a single "/" so keys join cleanly.
func normalizePrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(p, "/") + "/"
}
