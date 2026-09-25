// Package awssource reads secrets from AWS Secrets Manager. GetSecret-equivalent read logic
// (empty-value rejection, binary-secret handling, response hardening) is ported from
// internal/connect/awssm.go — migrate cannot import internal/connect (module boundary,
// docs/design-keyorix-migrate.md) — but this package additionally LISTS every secret in the
// account (paginated), which awssm.go's single-ref GetSecret never needed to do.
package awssource

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/keyorixhq/keyorix/migrate/internal/cloudentry"
	"github.com/keyorixhq/keyorix/migrate/internal/httpsafe"
	"github.com/keyorixhq/keyorix/migrate/internal/splitjson"
)

// Config holds every AWS Secrets Manager setting a Client needs. Credentials always come from
// the standard AWS chain (env / shared profile / IMDS / IRSA) — never a Keyorix config field or
// CLI flag, matching internal/connect/awssm.go's precedent.
type Config struct {
	Region     string // optional; the SDK's own default-config resolution is used when empty.
	NamePrefix string // optional; only secret names with this prefix are imported.
	// SplitJSON imports each top-level key of a JSON-object secret value as its own Keyorix
	// secret (Name field <secret>-<key>) instead of the whole string as one secret.
	SplitJSON bool
}

// smAPI is the slice of the Secrets Manager client this package uses — an interface seam so it
// is unit-tested with a fake, matching internal/connect/awssm.go's smSecretGetter precedent
// (extended here with ListSecrets, which that single-ref connector never needed).
type smAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Client lists and reads secrets from AWS Secrets Manager.
type Client struct {
	cfg Config
	// newClient builds an smAPI; nil uses the real AWS client (the standard credential chain).
	// Tests inject a fake.
	newClient func(ctx context.Context) (smAPI, error)
}

// New builds a Client. It performs no network call — the same "fail fast at the first real
// call, not at construction" shape vaultsource.New's Vault-address/auth validation intentionally
// does NOT need here, since AWS credential resolution itself already fails clearly at first use.
func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func (c *Client) client(ctx context.Context) (smAPI, error) {
	if c.newClient != nil {
		return c.newClient(ctx)
	}
	var opts []func(*awsconfig.LoadOptions) error
	if c.cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.cfg.Region))
	}
	awscfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws-secrets-manager: load AWS config: %w", err)
	}
	return secretsmanager.NewFromConfig(awscfg, func(o *secretsmanager.Options) {
		o.HTTPClient = httpsafe.Client()
	}), nil
}

// List lists every secret in the account (optionally restricted to names with cfg.NamePrefix),
// reads each one's current value, and returns it as a cloudentry.Entry — or, when the secret's
// value can't or shouldn't be imported (no value, a binary value, or a read error), as a
// cloudentry.Skipped with a reason. It never returns a partial success silently: a read error
// on one secret is reported as Skipped for that secret, not an abort of the whole listing —
// matching vaultsource.Client.Walk's "report, don't drop" convention for KV leaves it can't
// import.
func (c *Client) List(ctx context.Context) ([]cloudentry.Entry, []cloudentry.Skipped, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, nil, err
	}

	var entries []cloudentry.Entry
	var skipped []cloudentry.Skipped
	var nextToken *string
	for {
		out, err := cl.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: nextToken})
		if err != nil {
			return nil, nil, fmt.Errorf("aws-secrets-manager: list secrets: %w", err)
		}
		for _, s := range out.SecretList {
			name := aws.ToString(s.Name)
			if name == "" {
				continue
			}
			if c.cfg.NamePrefix != "" && !strings.HasPrefix(name, c.cfg.NamePrefix) {
				continue
			}
			locator := c.locator(name)
			// ListSecrets excludes secrets scheduled for deletion by default (we never set
			// IncludePlannedDeletion) — this check is defense in depth for a test double, or a
			// future SDK/API change, that returns one anyway; a deleted secret's value read
			// would fail regardless, so skip it up front with a clear reason instead of an
			// opaque GetSecretValue error.
			if s.DeletedDate != nil {
				skipped = append(skipped, cloudentry.Skipped{Locator: locator, Reason: fmt.Sprintf("secret is scheduled for deletion (deleted at %s)", s.DeletedDate.UTC().Format(time.RFC3339))})
				continue
			}
			es, skip, err := c.readSecret(ctx, cl, name, locator)
			if err != nil {
				return nil, nil, err
			}
			if skip != nil {
				skipped = append(skipped, *skip)
				continue
			}
			entries = append(entries, es...)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return entries, skipped, nil
}

func (c *Client) locator(name string) string {
	region := c.cfg.Region
	if region == "" {
		region = "default"
	}
	return fmt.Sprintf("aws-secrets-manager:%s/%s", region, name)
}

// readSecret fetches one secret's current value and turns it into one or more cloudentry.Entry
// (more than one only when SplitJSON explodes a JSON object), or a Skipped with a reason.
func (c *Client) readSecret(ctx context.Context, cl smAPI, name, locator string) ([]cloudentry.Entry, *cloudentry.Skipped, error) {
	out, err := cl.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)})
	if err != nil {
		return nil, nil, fmt.Errorf("aws-secrets-manager: get %q: %w", name, err)
	}

	// SecretString != nil alone is not "has a value" -- a response body like
	// {"SecretString":""} decodes to a non-nil pointer to "", which must not be treated as a
	// real secret (the same class of bug internal/connect/awssm.go's GetSecret was fixed for,
	// see docs/findings/2026-09-20-FINDING-awssm-empty-secret-response.md).
	if out.SecretString == nil || *out.SecretString == "" {
		if len(out.SecretBinary) > 0 {
			return nil, &cloudentry.Skipped{Locator: locator, Reason: "binary secret values are not supported by keyorix-migrate"}, nil
		}
		return nil, &cloudentry.Skipped{Locator: locator, Reason: "secret has no value"}, nil
	}

	value := *out.SecretString
	createdAt := ""
	if out.CreatedDate != nil {
		createdAt = out.CreatedDate.UTC().Format(time.RFC3339)
	}
	version := aws.ToString(out.VersionId)

	if c.cfg.SplitJSON {
		if fields, ok := splitjson.Object(value); ok {
			entries := make([]cloudentry.Entry, 0, len(fields))
			for _, f := range fields {
				entries = append(entries, cloudentry.Entry{
					RawName:   name,
					Field:     f.Key,
					Value:     f.Value,
					Version:   version,
					CreatedAt: createdAt,
					Locator:   locator + "#" + f.Key,
				})
			}
			if len(entries) > 0 {
				return entries, nil, nil
			}
		}
	}
	return []cloudentry.Entry{{RawName: name, Value: value, Version: version, CreatedAt: createdAt, Locator: locator}}, nil, nil
}
