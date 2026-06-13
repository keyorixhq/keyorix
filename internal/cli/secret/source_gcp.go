// source_gcp.go — live import from Google Cloud Secret Manager.
//
// Authenticates with Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
// gcloud auth, or workload identity / metadata) via the SDK; lists every secret in
// the project (optionally filtered by name prefix), reads its latest enabled
// version, and feeds it into the shared import path. A JSON-object value explodes
// into one Keyorix secret per field; a plain string becomes a single secret.
package secret

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// gcpSecretsAPI is the slice of Secret Manager this importer uses, behind an
// interface so tests inject a fake (the real client's iterator + version access
// live in gcpClientAdapter). listSecrets returns full resource names
// ("projects/<p>/secrets/<name>"); accessLatest returns the latest enabled
// version's value, or ok=false when the secret has no accessible version.
type gcpSecretsAPI interface {
	listSecrets(ctx context.Context, parent string) ([]string, error)
	accessLatest(ctx context.Context, name string) (value string, ok bool, err error)
}

// fetchFromGCP builds a real Secret Manager client from ADC and collects the
// project's secrets.
func fetchFromGCP(ctx context.Context) ([]secretEntry, error) {
	if strings.TrimSpace(gcpProject) == "" {
		return nil, fmt.Errorf("no GCP project configured (use --gcp-project)")
	}
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to GCP Secret Manager (check Application Default Credentials): %w", err)
	}
	defer func() { _ = client.Close() }()
	return collectGCP(ctx, gcpClientAdapter{c: client}, gcpProject)
}

// collectGCP lists and reads secrets from any gcpSecretsAPI.
func collectGCP(ctx context.Context, api gcpSecretsAPI, project string) ([]secretEntry, error) {
	names, err := api.listSecrets(ctx, "projects/"+project)
	if err != nil {
		return nil, fmt.Errorf("list GCP secrets: %w", err)
	}
	var entries []secretEntry
	for _, full := range names {
		short := full[strings.LastIndex(full, "/")+1:] // …/secrets/<name> → <name>
		if gcpPrefix != "" && !hasPrefix(short, gcpPrefix) {
			continue
		}
		val, ok, err := api.accessLatest(ctx, full)
		if err != nil {
			return nil, fmt.Errorf("read GCP secret %q: %w", short, err)
		}
		if !ok {
			// No enabled/accessible version (e.g. all versions destroyed/disabled).
			fmt.Printf("  ~ Skipped  %-30s (no accessible version)\n", short)
			continue
		}
		entries = append(entries, explodeValue(short, val)...)
	}
	return entries, nil
}

// gcpClientAdapter wraps the real *secretmanager.Client behind gcpSecretsAPI,
// keeping the iterator + version-access glue out of the testable collectGCP.
type gcpClientAdapter struct{ c *secretmanager.Client }

func (a gcpClientAdapter) listSecrets(ctx context.Context, parent string) ([]string, error) {
	it := a.c.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: parent})
	var names []string
	for {
		s, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		names = append(names, s.GetName())
	}
	return names, nil
}

func (a gcpClientAdapter) accessLatest(ctx context.Context, name string) (string, bool, error) {
	resp, err := a.c.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: name + "/versions/latest",
	})
	if err != nil {
		// A secret with no enabled latest version is skipped, not fatal.
		if s, ok := status.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.FailedPrecondition) {
			return "", false, nil
		}
		return "", false, err
	}
	if resp.GetPayload() == nil {
		return "", false, nil
	}
	return string(resp.GetPayload().GetData()), true, nil
}
