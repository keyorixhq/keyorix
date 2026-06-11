// source_aws.go — live import from AWS Secrets Manager.
//
// Authenticates with the standard AWS credential chain (env vars, shared config,
// SSO, instance/role) via the SDK; lists every secret (optionally filtered by
// name prefix) and reads its value. A JSON-object value explodes into one
// Keyorix secret per field; a plain string becomes a single secret.
package secret

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// awsSecretsAPI is the slice of the Secrets Manager client this importer uses,
// expressed as an interface so tests can inject a fake. *secretsmanager.Client
// satisfies it.
type awsSecretsAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// fetchFromAWS builds a real Secrets Manager client from the credential chain
// and collects every secret into entries.
func fetchFromAWS(ctx context.Context) ([]secretEntry, error) {
	var opts []func(*config.LoadOptions) error
	if awsRegion != "" {
		opts = append(opts, config.WithRegion(awsRegion))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("no AWS region configured (use --aws-region or set AWS_REGION)")
	}
	return collectAWS(ctx, secretsmanager.NewFromConfig(cfg))
}

// collectAWS lists and reads secrets from any awsSecretsAPI. Pagination is
// handled manually (NextToken) so the fake in tests stays trivial.
func collectAWS(ctx context.Context, api awsSecretsAPI) ([]secretEntry, error) {
	var entries []secretEntry
	var next *string
	for {
		out, err := api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("list AWS secrets: %w", err)
		}
		for _, s := range out.SecretList {
			if s.Name == nil {
				continue
			}
			name := aws.ToString(s.Name)
			if awsPrefix != "" && !hasPrefix(name, awsPrefix) {
				continue
			}
			val, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: s.Name})
			if err != nil {
				return nil, fmt.Errorf("read AWS secret %q: %w", name, err)
			}
			if val.SecretString == nil {
				// Binary secrets are not imported (values-only MVP).
				fmt.Printf("  ~ Skipped  %-30s (binary secret, not supported)\n", name)
				continue
			}
			entries = append(entries, explodeValue(name, aws.ToString(val.SecretString))...)
		}
		if out.NextToken == nil {
			break
		}
		next = out.NextToken
	}
	return entries, nil
}

// hasPrefix is a tiny local helper to avoid importing strings just for this.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
