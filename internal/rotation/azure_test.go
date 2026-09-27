package rotation

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fake azureTokenSource for testing azureGraphClient. azureTokenSource (see
// azure.go) is this package's own seam over the real Azure SDK credential —
// deliberately not azure-sdk-for-go's azcore.TokenCredential itself, so that
// azure.go (and this file) can stay compiled unconditionally (ADR-109 step
// 6: a noazure build still needs AzureAppSecretExecutor to exist so
// azure_fuzz_test.go keeps compiling) without importing azure-sdk-for-go.
// The real, SDK-backed implementation lives in azure_sdk.go (!noazure only).
// Deliberately kept in this untagged file (not rotation_s2_test.go, which is
// //go:build !nogcp) so a standalone -tags nogcp build — which excludes that
// file but not this one — still has these helpers available to the other
// azure test files that use them.
// ---------------------------------------------------------------------------

type fakeTokenCredential struct {
	token string
	err   error
}

func (f *fakeTokenCredential) Token(_ context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

// newGraphClient builds an azureGraphClient pointing at the given test server URL.
func newGraphClient(srv *httptest.Server, tok string) *azureGraphClient {
	return &azureGraphClient{
		tokenSource: &fakeTokenCredential{token: tok},
		http:        srv.Client(),
	}
}

type fakeAzure struct {
	existing  []string // current password keyIds
	newSecret string
	addErr    error
	listErr   error
	removed   []string
	addedFor  string
}

func (f *fakeAzure) ListPasswordKeyIDs(_ context.Context, _ string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]string(nil), f.existing...), nil
}
func (f *fakeAzure) AddPassword(_ context.Context, appID string) (string, error) {
	if f.addErr != nil {
		return "", f.addErr
	}
	f.addedFor = appID
	return f.newSecret, nil
}
func (f *fakeAzure) RemovePassword(_ context.Context, _, keyID string) error {
	f.removed = append(f.removed, keyID)
	return nil
}

func azureWith(fake *fakeAzure, allowed ...string) *AzureAppSecretExecutor {
	e := NewAzureAppSecretExecutor("azure", allowed)
	e.newClient = func(context.Context) (azureGraphAPI, error) { return fake, nil }
	return e
}

func TestAzure_TypeAndName(t *testing.T) {
	e := NewAzureAppSecretExecutor("prod-azure", nil)
	assert.Equal(t, "prod-azure", e.Name())
	assert.Equal(t, "azure-app", e.Type())
}

func TestAzure_RotateNotSupported(t *testing.T) {
	err := azureWith(&fakeAzure{}, "app-").Rotate(context.Background(), "app-123", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

func TestAzure_GenerateUpstream_NoPriorSecrets(t *testing.T) {
	fake := &fakeAzure{newSecret: "n3w-secret"}
	v, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "app-123")
	require.NoError(t, err)
	assert.Equal(t, "n3w-secret", v)
	assert.Equal(t, "app-123", fake.addedFor)
	assert.Empty(t, fake.removed)
}

func TestAzure_GenerateUpstream_RemovesPriorSecrets(t *testing.T) {
	fake := &fakeAzure{existing: []string{"kid1", "kid2"}, newSecret: "n3w"}
	_, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "app-123")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"kid1", "kid2"}, fake.removed, "all prior secrets removed")
}

func TestAzure_GenerateUpstream_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := azureWith(&fakeAzure{}, "app-").GenerateUpstream(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("ref with path metacharacters rejected", func(t *testing.T) {
		fake := &fakeAzure{newSecret: "x"}
		// would otherwise path-traverse to a different app despite the allowed prefix
		_, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "app-1/../victim-2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid application object id")
		assert.Empty(t, fake.addedFor, "a path-shaped ref never reaches Azure")
	})
	t.Run("fail-closed without allowed_refs", func(t *testing.T) {
		_, err := azureWith(&fakeAzure{}).GenerateUpstream(context.Background(), "app-123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no allowed_refs")
	})
	t.Run("guardrail", func(t *testing.T) {
		fake := &fakeAzure{newSecret: "x"}
		_, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "other-999")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.addedFor, "a disallowed ref never reaches Azure")
	})
	t.Run("add error propagates", func(t *testing.T) {
		fake := &fakeAzure{addErr: errors.New("Forbidden")}
		_, err := azureWith(fake, "app-").GenerateUpstream(context.Background(), "app-123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Forbidden")
	})
}
