package connect

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGCPSM is an injected stand-in for the GCP Secret Manager client.
type fakeGCPSM struct {
	out    *secretmanagerpb.AccessSecretVersionResponse
	err    error
	got    string
	closed bool
}

func (f *fakeGCPSM) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.got = req.GetName()
	return f.out, f.err
}
func (f *fakeGCPSM) Close() error { f.closed = true; return nil }

func gcpConnectorWith(name string, fake *fakeGCPSM, allowed ...string) *GCPSecretManagerConnector {
	c := NewGCPSecretManagerConnector(name, allowed)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return fake, nil }
	return c
}

func TestGCPSM_TypeAndName(t *testing.T) {
	c := NewGCPSecretManagerConnector("prod-gcp", nil)
	assert.Equal(t, "prod-gcp", c.Name())
	assert.Equal(t, "gcp-secret-manager", c.Type())
}

func TestGCPSM_GetSecret(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte("g0ph3r")},
	}}
	ref := "projects/p/secrets/db/versions/latest"
	val, err := gcpConnectorWith("gcp", fake).GetSecret(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "g0ph3r", val)
	assert.Equal(t, ref, fake.got, "the ref is passed as the version resource name")
	assert.True(t, fake.closed, "the client is closed after use")
}

func TestGCPSM_GetSecret_Errors(t *testing.T) {
	t.Run("empty ref", func(t *testing.T) {
		_, err := gcpConnectorWith("gcp", &fakeGCPSM{}).GetSecret(context.Background(), "")
		require.Error(t, err)
	})
	t.Run("backend error", func(t *testing.T) {
		_, err := gcpConnectorWith("gcp", &fakeGCPSM{err: errors.New("PermissionDenied")}).GetSecret(context.Background(), "projects/p/secrets/x/versions/1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PermissionDenied")
	})
	t.Run("no value", func(t *testing.T) {
		_, err := gcpConnectorWith("gcp", &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{}}).GetSecret(context.Background(), "projects/p/secrets/x/versions/1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no value")
	})
	t.Run("allowed_refs guardrail", func(t *testing.T) {
		fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")}}}
		c := gcpConnectorWith("gcp", fake, "projects/p/secrets/keyorix-")
		_, err := c.GetSecret(context.Background(), "projects/p/secrets/other/versions/latest")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
		assert.Empty(t, fake.got, "a disallowed ref must not reach the backend")
	})
}
