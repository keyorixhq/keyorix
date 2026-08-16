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
	"net"
	"net/http"
	"net/url"
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
	// LegalHold places an S3 Object Lock legal hold on each uploaded object — an
	// indefinite hold (no expiry) that blocks deletion/overwrite until a principal
	// with s3:PutObjectLegalHold explicitly clears it. Independent of LockMode; the
	// bucket must have Object Lock enabled.
	LegalHold bool
}

// s3PutAPI is the slice of the S3 client the sink uses — an interface seam so the
// delivery logic is unit-tested with a fake and the SDK stays inside this adapter.
type s3PutAPI interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// ObjectStore delivers the evidence pack to an S3-compatible bucket.
type ObjectStore struct {
	api       s3PutAPI
	bucket    string
	prefix    string
	lockMode  s3types.ObjectLockMode // "" when object lock is off
	retain    time.Duration
	legalHold bool
	now       func() time.Time
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

// validateObjectStoreEndpoint checks that a custom S3-compatible endpoint URL is
// well-formed and uses an http(s) scheme, before it is handed to the AWS SDK as
// BaseEndpoint. Unlike webhook.go's validateEndpoint, this deliberately does NOT
// block private/link-local destinations: a self-hosted S3-compatible store (MinIO,
// a local gateway, an in-cluster service, ...) legitimately lives on an internal
// address — that's the whole point of self-hosting — so the blanket SSRF IP-range
// guard webhook.go applies to its own (public-collector-shaped) endpoint would
// break the primary use case here. What IS worth rejecting regardless of target:
// a malformed URL, or a scheme other than http/https (e.g. file://) that has no
// business being handed to an S3 client's BaseEndpoint. An empty raw (use the
// default AWS S3 endpoint) is always fine and returns a nil URL with no error.
func validateObjectStoreEndpoint(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("evidencesink: invalid object-store endpoint %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("evidencesink: object-store endpoint %q must use http or https", raw)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("evidencesink: object-store endpoint %q has no host", raw)
	}
	return u, nil
}

// rawDialContext performs the actual network dial once a target address has been
// chosen. A package-level var (like lookupIPAddr below it) so tests can observe
// the address a pinned dial actually connects to without opening a real socket.
var rawDialContext = (&net.Dialer{}).DialContext

// pinnedDialContext resolves host ONCE — here, at NewObjectStore construction
// time — and returns a DialContext that connects to that literal resolved IP for
// EVERY future connection, never re-resolving. This closes the residual DNS-
// rebinding gap the finding describes: ObjectStoreConfig.Endpoint is a long-lived,
// operator-set config value reused for many uploads over the ObjectStore's whole
// lifetime (unlike webhook.go's per-delivery dialer, which re-validates on every
// dial because it also has a private/link-local block to keep enforcing). Here
// there is no such block to repeat — the endpoint may legitimately be private —
// so the only protection worth applying is pinning: if the hostname is LATER
// repointed via DNS (the domain lapses and is re-registered, an internal DNS
// record is repointed, ...), this long-lived client keeps talking to the address
// that was actually resolved at setup time, instead of silently starting to PUT
// the evidence pack — and its SigV4 Authorization header — to a new, unvetted
// host. A literal IP endpoint has nothing to resolve or pin.
func pinnedDialContext(host string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if ip := net.ParseIP(host); ip != nil {
		return rawDialContext, nil
	}
	addrs, err := lookupIPAddr(host)
	if err != nil {
		return nil, fmt.Errorf("evidencesink: resolve object-store endpoint host %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("evidencesink: object-store endpoint host %q did not resolve to any address", host)
	}
	pinned := addrs[0].IP
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("evidencesink: invalid dial address %q: %w", addr, err)
		}
		return rawDialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
	}, nil
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
	epURL, err := validateObjectStoreEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	var endpointHTTPClient *http.Client
	if epURL != nil {
		dialCtx, derr := pinnedDialContext(epURL.Hostname())
		if derr != nil {
			return nil, derr
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = dialCtx
		endpointHTTPClient = &http.Client{Transport: tr}
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
		if endpointHTTPClient != nil {
			o.HTTPClient = endpointHTTPClient
		}
		o.UsePathStyle = cfg.UsePathStyle
	})
	return &ObjectStore{
		api:       client,
		bucket:    cfg.Bucket,
		prefix:    normalizePrefix(cfg.Prefix),
		lockMode:  lockMode,
		retain:    time.Duration(cfg.LockRetainDays) * 24 * time.Hour,
		legalHold: cfg.LegalHold,
		now:       time.Now,
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
	if o.legalHold {
		in.ObjectLockLegalHoldStatus = s3types.ObjectLockLegalHoldStatusOn
	}
	return in
}

// Target labels this forwarder in the export result.
func (o *ObjectStore) Target() string {
	var marks []string
	if o.lockMode != "" {
		marks = append(marks, "lock:"+strings.ToLower(string(o.lockMode)))
	}
	if o.legalHold {
		marks = append(marks, "legal-hold")
	}
	if len(marks) > 0 {
		return fmt.Sprintf("objectstore:%s/%s (%s)", o.bucket, o.prefix, strings.Join(marks, ","))
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
