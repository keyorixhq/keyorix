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
	c := NewGCPSecretManagerConnector(name, "", allowed)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return fake, nil }
	return c
}

func gcpPinnedConnectorWith(name, projectID string, fake *fakeGCPSM, allowed ...string) *GCPSecretManagerConnector {
	c := NewGCPSecretManagerConnector(name, projectID, allowed)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return fake, nil }
	return c
}

func TestGCPSM_TypeAndName(t *testing.T) {
	c := NewGCPSecretManagerConnector("prod-gcp", "", nil)
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

// TestGCPSM_ProjectPin covers #431: an unpinned connector (projectID == "", the
// pre-existing default) may address any project the ADC identity can reach — no
// regression — while a pinned connector rejects a ref naming a different project and
// still works normally for its own project's refs.
func TestGCPSM_ProjectPin(t *testing.T) {
	t.Run("pinned connector rejects a ref targeting a different project", func(t *testing.T) {
		fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")}}}
		c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
		_, err := c.GetSecret(context.Background(), "projects/other-proj/secrets/db/versions/latest")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pinned to project")
		assert.Contains(t, err.Error(), "my-proj")
		assert.Contains(t, err.Error(), "other-proj")
		assert.Empty(t, fake.got, "a cross-project ref must not reach the backend")
	})

	t.Run("pinned connector still works for its own project's refs", func(t *testing.T) {
		fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("g0ph3r")}}}
		c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
		ref := "projects/my-proj/secrets/db/versions/latest"
		val, err := c.GetSecret(context.Background(), ref)
		require.NoError(t, err)
		assert.Equal(t, "g0ph3r", val)
		assert.Equal(t, ref, fake.got)
	})

	t.Run("pinned connector rejects a ref with no parseable project segment", func(t *testing.T) {
		fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")}}}
		c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
		_, err := c.GetSecret(context.Background(), "not-a-project-resource-name")
		require.Error(t, err)
		assert.Empty(t, fake.got)
	})

	t.Run("unpinned connector (legacy/default config) still reads across projects", func(t *testing.T) {
		fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("g0ph3r")}}}
		c := gcpConnectorWith("gcp", fake) // projectID == "" — the pre-existing default
		ref := "projects/some-other-proj/secrets/db/versions/latest"
		val, err := c.GetSecret(context.Background(), ref)
		require.NoError(t, err, "no regression: an unpinned connector keeps today's cross-project behavior")
		assert.Equal(t, "g0ph3r", val)
	})
}

func TestGCPRefProjectID(t *testing.T) {
	tests := []struct {
		ref     string
		project string
		ok      bool
	}{
		{"projects/p/secrets/db/versions/latest", "p", true},
		{"projects/my-proj-123/secrets/x/versions/1", "my-proj-123", true},
		{"projects/", "", false},
		{"projects", "", false},
		{"secrets/db/versions/latest", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		project, ok := gcpRefProjectID(tt.ref)
		assert.Equal(t, tt.ok, ok, "ref %q", tt.ref)
		assert.Equal(t, tt.project, project, "ref %q", tt.ref)
	}
}
