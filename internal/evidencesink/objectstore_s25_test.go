//go:build !lean

// objectstore_s25_test.go — NewObjectStore success-path coverage, split out of
// evidencesink_s25_test.go so this file (which asserts a real S3-backed
// NewObjectStore succeeds — untrue of the lean stub in objectstore_lean.go) can
// be excluded from a lean build without also dropping that file's unrelated
// webhook test coverage.
package evidencesink

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewObjectStore_ValidMinimalConfig tests a minimal valid config (bucket only).
// AWS credential loading still succeeds even without real credentials because the
// SDK only resolves them lazily on the first actual API call, not at LoadDefaultConfig.
func TestNewObjectStore_ValidMinimalConfig(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{Bucket: "my-bucket"})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Equal(t, "objectstore:my-bucket/", o.Target())
}

// TestNewObjectStore_WithRegionAndEndpoint exercises the loadOpts path and the
// custom-endpoint / path-style option branches.
func TestNewObjectStore_WithRegionAndEndpoint(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:       "minio-bucket",
		Prefix:       "evidence",
		Region:       "us-east-1",
		Endpoint:     "http://localhost:9000",
		UsePathStyle: true,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Equal(t, "objectstore:minio-bucket/evidence/", o.Target())
}

// TestNewObjectStore_WithLockGovernanceAndLegalHold exercises object-lock and
// legal-hold construction including the Region branch.
func TestNewObjectStore_WithLockGovernanceAndLegalHold(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:         "bkt",
		LockMode:       "governance",
		LockRetainDays: 30,
		LegalHold:      true,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	target := o.Target()
	assert.Contains(t, target, "lock:governance")
	assert.Contains(t, target, "legal-hold")
}

// TestNewObjectStore_WithComplianceLock exercises the compliance lock mode path.
func TestNewObjectStore_WithComplianceLock(t *testing.T) {
	ctx := context.Background()
	o, err := NewObjectStore(ctx, ObjectStoreConfig{
		Bucket:         "bkt",
		LockMode:       "compliance",
		LockRetainDays: 90,
	})
	require.NoError(t, err)
	require.NotNil(t, o)
	assert.Contains(t, o.Target(), "lock:compliance")
}
