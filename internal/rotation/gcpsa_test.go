package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeGCP struct {
	existing  []string                   // current user-managed key names (all enabled, no ValidAfterTime)
	existingK []gcpServiceAccountKeyInfo // takes precedence over existing when non-nil, for tests needing Disabled/ValidAfterTime
	newName   string
	newJSON   string
	createErr error
	createdAt string // saName passed to CreateKey
	deleted   []string
}

func (f *fakeGCP) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	if f.existingK != nil {
		return append([]gcpServiceAccountKeyInfo(nil), f.existingK...), nil
	}
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *fakeGCP) CreateKey(_ context.Context, saName string) (string, string, error) {
	if f.createErr != nil {
		return "", "", f.createErr
	}
	f.createdAt = saName
	return f.newName, f.newJSON, nil
}
func (f *fakeGCP) DeleteKey(_ context.Context, keyName string) error {
	f.deleted = append(f.deleted, keyName)
	return nil
}

func gcpWith(fake *fakeGCP, allowed ...string) *GCPServiceAccountKeyExecutor {
	e := NewGCPServiceAccountKeyExecutor("gcp", allowed)
	e.newClient = func(context.Context) (gcpKeyAPI, error) { return fake, nil }
	return e
}

func TestGCPSA_TypeAndName(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("prod-gcp", nil)
	assert.Equal(t, "prod-gcp", e.Name())
	assert.Equal(t, "gcp-service-account", e.Type())
}

func TestGCPSA_RotateNotSupported(t *testing.T) {
	err := gcpWith(&fakeGCP{}, "svc-").Rotate(context.Background(), "svc-app@p.iam", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

func TestGCPSA_GenerateUpstream_NoPriorKeys(t *testing.T) {
	fake := &fakeGCP{newName: "projects/-/serviceAccounts/svc-app@p.iam/keys/NEW", newJSON: `{"type":"service_account"}`}
	v, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.NoError(t, err)
	assert.Equal(t, `{"type":"service_account"}`, v)
	assert.Equal(t, "projects/-/serviceAccounts/svc-app@p.iam", fake.createdAt)
	assert.Empty(t, fake.deleted)
}

func TestGCPSA_GenerateUpstream_DeletesPriorKeys(t *testing.T) {
	fake := &fakeGCP{existing: []string{"k/OLD1", "k/OLD2"}, newName: "k/NEW", newJSON: `{"k":"v"}`}
	_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"k/OLD1", "k/OLD2"}, fake.deleted, "all prior user-managed keys removed")
}

func TestGCPSA_GenerateUpstream_FreesSlotAtLimit(t *testing.T) {
	existing := make([]string, gcpServiceAccountMaxKeys) // at the limit
	for i := range existing {
		existing[i] = "k/OLD" + string(rune('A'+i))
	}
	fake := &fakeGCP{existing: existing, newName: "k/NEW", newJSON: `{"k":"v"}`}
	_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.NoError(t, err)
	// All prior keys deleted (one to free the slot, the rest after create).
	assert.Len(t, fake.deleted, gcpServiceAccountMaxKeys)
}

func TestEvictableServiceAccountKey_PrefersDisabledOverEnabled(t *testing.T) {
	keys := []gcpServiceAccountKeyInfo{
		{Name: "k/enabled-oldest", Disabled: false, ValidAfterTime: "2020-01-01T00:00:00Z"},
		{Name: "k/disabled", Disabled: true, ValidAfterTime: "2025-01-01T00:00:00Z"},
		{Name: "k/enabled-newest", Disabled: false, ValidAfterTime: "2026-01-01T00:00:00Z"},
	}
	// The naive prior[0] behavior this replaces would have evicted "k/enabled-oldest"
	// (whatever GCP's unspecified list ordering happened to return first) — a
	// different, WRONG answer from the disabled key, proving this test actually
	// distinguishes correct from incorrect eviction selection.
	assert.Equal(t, "k/disabled", evictableServiceAccountKey(keys))
}

func TestEvictableServiceAccountKey_PrefersOldestWhenAllEnabled(t *testing.T) {
	keys := []gcpServiceAccountKeyInfo{
		{Name: "k/newest", Disabled: false, ValidAfterTime: "2026-01-01T00:00:00Z"},
		{Name: "k/oldest", Disabled: false, ValidAfterTime: "2020-01-01T00:00:00Z"},
		{Name: "k/middle", Disabled: false, ValidAfterTime: "2023-01-01T00:00:00Z"},
	}
	assert.Equal(t, "k/oldest", evictableServiceAccountKey(keys))
}

func TestGCPSA_GenerateUpstream_FreesSlotAtLimit_PrefersDisabledKey(t *testing.T) {
	existingK := make([]gcpServiceAccountKeyInfo, gcpServiceAccountMaxKeys)
	for i := range existingK {
		existingK[i] = gcpServiceAccountKeyInfo{
			Name:           "k/OLD" + string(rune('A'+i)),
			ValidAfterTime: "2020-01-01T00:00:00Z",
		}
	}
	// The one disabled key sorts last by name/order, so a prior[0]-style eviction
	// would never pick it — only the disabled-first preference does.
	existingK[len(existingK)-1].Disabled = true
	wantEvicted := existingK[len(existingK)-1].Name

	fake := &fakeGCP{existingK: existingK, newName: "k/NEW", newJSON: `{"k":"v"}`}
	_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.NoError(t, err)
	require.NotEmpty(t, fake.deleted)
	assert.Equal(t, wantEvicted, fake.deleted[0], "the disabled key must be freed first, not prior[0]")
}

func TestGCPSA_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := gcpWith(&fakeGCP{}, "svc-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("ref with path metacharacters rejected", func(t *testing.T) {
		for _, ref := range []string{
			"svc-app@p.iam/keys/x",     // path segment
			"svc-app@p.iam?query=x",    // query
			"svc-app@p.iam#fragment",   // fragment
			"svc-app@p.iam%2Fkeys%2Fx", // percent-encoded path
		} {
			fake := &fakeGCP{newJSON: "{}"}
			_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), ref)
			require.Error(t, err, "ref %q must be rejected", ref)
			assert.Contains(t, err.Error(), "resource path")
			assert.Empty(t, fake.createdAt, "a path-shaped ref %q never reaches GCP", ref)
		}
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		_, err := gcpWith(&fakeGCP{}).GenerateUpstream(context.Background(), "svc-app@p.iam")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
	})
	t.Run("guardrail", func(t *testing.T) {
		fake := &fakeGCP{newJSON: "{}"}
		_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "root@p.iam")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.createdAt, "a disallowed ref never reaches GCP")
	})
	t.Run("create error propagates", func(t *testing.T) {
		fake := &fakeGCP{createErr: errors.New("PermissionDenied")}
		_, err := gcpWith(fake, "svc-").GenerateUpstream(context.Background(), "svc-app@p.iam")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PermissionDenied")
	})
}
