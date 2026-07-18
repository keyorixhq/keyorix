// source_gcp_s23_test.go — coverage sprint s23 for source_gcp.go.
//
// Targets error paths in collectGCP that are not covered by the happy-path
// tests in source_gcp_test.go:
//
//   - listSecrets returning an error → "list GCP secrets: ..." wrapping
//   - accessLatest returning an error → "read GCP secret: ..." wrapping
package secret

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errGCPList is a fake gcpSecretsAPI that always returns an error from listSecrets.
type errGCPList struct{ err error }

func (f *errGCPList) listSecrets(_ context.Context, _ string) ([]string, error) {
	return nil, f.err
}
func (f *errGCPList) accessLatest(_ context.Context, _ string) (string, bool, error) {
	return "", false, nil
}

// errGCPAccess is a fake gcpSecretsAPI that lists successfully but fails accessLatest.
type errGCPAccess struct {
	names []string
	err   error
}

func (f *errGCPAccess) listSecrets(_ context.Context, _ string) ([]string, error) {
	return f.names, nil
}
func (f *errGCPAccess) accessLatest(_ context.Context, _ string) (string, bool, error) {
	return "", false, f.err
}

// TestCollectGCP_S23_ListSecretsError verifies that a listSecrets error is
// wrapped as "list GCP secrets: <cause>" and returned from collectGCP.
func TestCollectGCP_S23_ListSecretsError(t *testing.T) {
	gcpPrefix = ""
	cause := errors.New("connection refused")
	_, err := collectGCP(context.Background(), &errGCPList{err: cause}, "my-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list GCP secrets")
	assert.Contains(t, err.Error(), "connection refused")
}

// TestCollectGCP_S23_AccessLatestError verifies that an accessLatest error
// (non-NotFound, non-FailedPrecondition) surfaces as "read GCP secret <name>: ..."
// from collectGCP.
func TestCollectGCP_S23_AccessLatestError(t *testing.T) {
	gcpPrefix = ""
	cause := errors.New("internal error")
	api := &errGCPAccess{
		names: []string{"projects/p/secrets/my-secret"},
		err:   cause,
	}
	_, err := collectGCP(context.Background(), api, "p")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read GCP secret")
	assert.Contains(t, err.Error(), "internal error")
}
