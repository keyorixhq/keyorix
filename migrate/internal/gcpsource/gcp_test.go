package gcpsource

import (
	"context"
	"errors"
	"strings"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeLister is an in-process secretLister fake — no network, no real GCP project.
type fakeLister struct {
	secrets []*secretmanagerpb.Secret
	idx     int
}

func (f *fakeLister) Next() (*secretmanagerpb.Secret, error) {
	if f.idx >= len(f.secrets) {
		return nil, iterator.Done
	}
	s := f.secrets[f.idx]
	f.idx++
	return s, nil
}

// fakeGCP is an in-process gcpAPI fake.
type fakeGCP struct {
	list      []*secretmanagerpb.Secret
	versions  map[string]*secretmanagerpb.SecretVersion // keyed by the "projects/P/secrets/NAME" secret resource name
	payloads  map[string]*secretmanagerpb.SecretPayload // keyed by the same secret resource name
	accessErr map[string]error
	closed    bool
}

func (f *fakeGCP) ListSecrets(context.Context, *secretmanagerpb.ListSecretsRequest, ...gax.CallOption) secretLister {
	return &fakeLister{secrets: f.list}
}

func (f *fakeGCP) GetSecretVersion(_ context.Context, req *secretmanagerpb.GetSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	secretName := strings.TrimSuffix(req.GetName(), "/versions/latest")
	v, ok := f.versions[secretName]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such version")
	}
	return v, nil
}

func (f *fakeGCP) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	secretName := strings.TrimSuffix(req.GetName(), "/versions/latest")
	if err, ok := f.accessErr[secretName]; ok {
		return nil, err
	}
	p, ok := f.payloads[secretName]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such secret")
	}
	return &secretmanagerpb.AccessSecretVersionResponse{Payload: p}, nil
}

func (f *fakeGCP) Close() error { f.closed = true; return nil }

func secretRes(name string) string { return "projects/proj-1/secrets/" + name }

func enabledVersion(secretName string) *secretmanagerpb.SecretVersion {
	return &secretmanagerpb.SecretVersion{Name: secretRes(secretName) + "/versions/1", State: secretmanagerpb.SecretVersion_ENABLED, CreateTime: timestamppb.Now()}
}

func newClientWithFake(f *fakeGCP) *Client {
	c := New(Config{ProjectID: "proj-1"})
	c.newClient = func(context.Context) (gcpAPI, error) { return f, nil }
	return c
}

func TestList_ReturnsEveryEnabledSecret(t *testing.T) {
	f := &fakeGCP{
		list: []*secretmanagerpb.Secret{{Name: secretRes("s1")}, {Name: secretRes("s2")}},
		versions: map[string]*secretmanagerpb.SecretVersion{
			secretRes("s1"): enabledVersion("s1"),
			secretRes("s2"): enabledVersion("s2"),
		},
		payloads: map[string]*secretmanagerpb.SecretPayload{
			secretRes("s1"): {Data: []byte("v1")},
			secretRes("s2"): {Data: []byte("v2")},
		},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", skipped)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2", entries)
	}
	if !f.closed {
		t.Error("List did not close the client")
	}
}

func TestList_NamePrefixFilters(t *testing.T) {
	f := &fakeGCP{
		list: []*secretmanagerpb.Secret{{Name: secretRes("team-a-db")}, {Name: secretRes("team-b-db")}},
		versions: map[string]*secretmanagerpb.SecretVersion{
			secretRes("team-a-db"): enabledVersion("team-a-db"),
			secretRes("team-b-db"): enabledVersion("team-b-db"),
		},
		payloads: map[string]*secretmanagerpb.SecretPayload{
			secretRes("team-a-db"): {Data: []byte("v1")},
			secretRes("team-b-db"): {Data: []byte("v2")},
		},
	}
	c := New(Config{ProjectID: "proj-1", NamePrefix: "team-a"})
	c.newClient = func(context.Context) (gcpAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].RawName != "team-a-db" {
		t.Fatalf("entries = %+v, want only team-a-db", entries)
	}
}

// TestList_DisabledAndDestroyedVersionsAreSkipped is the "disabled secret" case (GCP's
// equivalent covers both DISABLED and DESTROYED version states): neither is imported nor
// silently dropped, and AccessSecretVersion must never be called for either.
func TestList_DisabledAndDestroyedVersionsAreSkipped(t *testing.T) {
	f := &fakeGCP{
		list: []*secretmanagerpb.Secret{{Name: secretRes("off")}, {Name: secretRes("gone")}},
		versions: map[string]*secretmanagerpb.SecretVersion{
			secretRes("off"):  {Name: secretRes("off") + "/versions/1", State: secretmanagerpb.SecretVersion_DISABLED},
			secretRes("gone"): {Name: secretRes("gone") + "/versions/1", State: secretmanagerpb.SecretVersion_DESTROYED},
		},
		payloads: map[string]*secretmanagerpb.SecretPayload{}, // AccessSecretVersion must never be reached
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %+v, want 2", skipped)
	}
	reasons := skipped[0].Reason + "|" + skipped[1].Reason
	if !strings.Contains(reasons, "disabled") || !strings.Contains(reasons, "destroyed") {
		t.Errorf("skipped = %+v, want reasons mentioning disabled and destroyed", skipped)
	}
}

func TestList_SecretWithNoVersionsIsSkipped(t *testing.T) {
	f := &fakeGCP{
		list:     []*secretmanagerpb.Secret{{Name: secretRes("empty-secret")}},
		versions: map[string]*secretmanagerpb.SecretVersion{}, // GetSecretVersion returns NotFound
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "no versions") {
		t.Fatalf("skipped = %+v, want one skip mentioning no versions", skipped)
	}
}

// TestReadSecret_EmptyPayloadIsSkipped locks in the same bug class
// internal/connect/gcpsm.go's GetSecret already guards: a nil or empty payload must not be
// imported as a real secret.
func TestReadSecret_EmptyPayloadIsSkipped(t *testing.T) {
	f := &fakeGCP{
		list:     []*secretmanagerpb.Secret{{Name: secretRes("empty")}},
		versions: map[string]*secretmanagerpb.SecretVersion{secretRes("empty"): enabledVersion("empty")},
		payloads: map[string]*secretmanagerpb.SecretPayload{secretRes("empty"): {Data: []byte{}}},
	}
	c := newClientWithFake(f)
	entries, skipped, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "no value") {
		t.Fatalf("skipped = %+v, want one skip reasoning about no value", skipped)
	}
}

func TestReadSecret_SplitJSONExplodesTopLevelKeys(t *testing.T) {
	f := &fakeGCP{
		list:     []*secretmanagerpb.Secret{{Name: secretRes("creds")}},
		versions: map[string]*secretmanagerpb.SecretVersion{secretRes("creds"): enabledVersion("creds")},
		payloads: map[string]*secretmanagerpb.SecretPayload{secretRes("creds"): {Data: []byte(`{"username":"alice","password":"hunter2"}`)}},
	}
	c := New(Config{ProjectID: "proj-1", SplitJSON: true})
	c.newClient = func(context.Context) (gcpAPI, error) { return f, nil }
	entries, _, err := c.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want 2 (one per JSON key)", entries)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Field] = e.Value
	}
	if got["username"] != "alice" || got["password"] != "hunter2" {
		t.Errorf("entries = %+v, want username=alice password=hunter2", got)
	}
}

// TestList_ReadErrorAbortsWithoutLeakingCanaryValue asserts that when AccessSecretVersion fails
// for one secret, the top-level error returned by List never contains another secret's real
// value — mirroring awssource/azuresource's canary tests (docs/design-keyorix-migrate.md's
// "Never log, print, or report a secret value").
func TestList_ReadErrorAbortsWithoutLeakingCanaryValue(t *testing.T) {
	const canary = "CANARY-do-not-leak-8f3a1c"
	f := &fakeGCP{
		list: []*secretmanagerpb.Secret{{Name: secretRes("good")}, {Name: secretRes("bad")}},
		versions: map[string]*secretmanagerpb.SecretVersion{
			secretRes("good"): enabledVersion("good"),
			secretRes("bad"):  enabledVersion("bad"),
		},
		payloads:  map[string]*secretmanagerpb.SecretPayload{secretRes("good"): {Data: []byte(canary)}},
		accessErr: map[string]error{secretRes("bad"): errors.New("simulated backend failure")},
	}
	c := newClientWithFake(f)
	_, _, err := c.List(context.Background())
	if err == nil {
		t.Fatal("List with a failing AccessSecretVersion call returned no error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("List's returned error leaked the canary value: %q", err.Error())
	}
}

func TestGcpShortNameAndVersionID(t *testing.T) {
	if got := gcpShortName("projects/p/secrets/my-secret"); got != "my-secret" {
		t.Errorf("gcpShortName = %q, want my-secret", got)
	}
	if got := gcpShortName("garbage"); got != "" {
		t.Errorf("gcpShortName(garbage) = %q, want empty", got)
	}
	if got := gcpVersionID("projects/p/secrets/my-secret/versions/7"); got != "7" {
		t.Errorf("gcpVersionID = %q, want 7", got)
	}
}
