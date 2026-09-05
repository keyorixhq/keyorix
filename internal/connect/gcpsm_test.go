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

// gcpConnectorWith builds a pinned connector for tests that exercise GetSecret
// behavior unrelated to project pinning (backend errors, empty payloads, allowed_refs,
// client lifecycle, etc.) — every ref used with connectors built by this helper
// embeds project "p", so the (now mandatory, see TestGCPSM_RequiresProjectID)
// project pin check passes transparently and does not interfere with what each test
// actually means to exercise.
func gcpConnectorWith(name string, fake *fakeGCPSM, allowed ...string) *GCPSecretManagerConnector {
	c := NewGCPSecretManagerConnector(name, "p", allowed)
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

// TestGCPSM_ProjectPin covers #431: a pinned connector rejects a ref naming a
// different project and still works normally for its own project's refs. project_id
// is now a required binding (validateConnectGCPProjectID enforces this at boot,
// server/main.go's gcp-secret-manager case constructs every connector with a
// non-empty ProjectID) — an unpinned (projectID == "") connector is no longer a
// legacy-compatible "allow all projects" configuration, it is refused outright at
// use-time; see TestGCPSM_RequiresProjectID.
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

}

// TestGCPSM_RequiresProjectID is the use-time guard test for the confused-deputy gap
// this connector used to have: a connector with no project_id configured must
// refuse EVERY read (fail closed), not fall back to the old "reach any project the
// ADC identity can access" behavior. This is defense in depth on top of
// internal/config.validateConnectGCPProjectID's boot-time requirement — it must
// hold even if a connector somehow got constructed with an empty projectID despite
// that boot check (a bug in wiring, a bypass, a future caller of
// NewGCPSecretManagerConnector that skips cfg.Validate()). Before this change, this
// exact scenario (empty projectID, a ref naming an arbitrary project) returned the
// secret value with no error — this test is RED against that old behavior and GREEN
// against the fail-closed fix.
func TestGCPSM_RequiresProjectID(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("g0ph3r")}}}
	c := NewGCPSecretManagerConnector("gcp", "", nil) // projectID == "" — must never reach the backend
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return fake, nil }

	ref := "projects/some-other-proj/secrets/db/versions/latest"
	_, err := c.GetSecret(context.Background(), ref)
	require.Error(t, err, "a connector with no project_id must refuse every read, not fall back to unrestricted cross-project access")
	assert.Contains(t, err.Error(), "project_id")
	assert.Empty(t, fake.got, "the backend must never be reached when project_id is unset")
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
