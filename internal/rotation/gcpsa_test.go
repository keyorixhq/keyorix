package rotation

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeGCP struct {
	existing  []string // current user-managed key names
	newName   string
	newJSON   string
	createErr error
	createdAt string // saName passed to CreateKey
	deleted   []string
}

func (f *fakeGCP) ListKeyNames(_ context.Context, _ string) ([]string, error) {
	return append([]string(nil), f.existing...), nil
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

func TestGCPSA_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := gcpWith(&fakeGCP{}, "svc-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
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
