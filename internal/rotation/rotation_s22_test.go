package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// quoteMySQLString — direct unit tests
// ---------------------------------------------------------------------------

// TestQuoteMySQLString_S22_Clean verifies that a clean string is simply
// single-quoted with no modifications.
func TestQuoteMySQLString_S22_Clean(t *testing.T) {
	assert.Equal(t, `'hello'`, quoteMySQLString("hello"))
}

// TestQuoteMySQLString_S22_SingleQuoteDoubled verifies that internal single
// quotes are doubled to prevent SQL injection.
func TestQuoteMySQLString_S22_SingleQuoteDoubled(t *testing.T) {
	assert.Equal(t, `'it''s'`, quoteMySQLString("it's"))
}

// TestQuoteMySQLString_S22_BackslashDoubled verifies that backslashes are
// doubled before quoting (injection-safe under default sql_mode).
func TestQuoteMySQLString_S22_BackslashDoubled(t *testing.T) {
	assert.Equal(t, `'a\\b'`, quoteMySQLString(`a\b`))
}

// TestQuoteMySQLString_S22_MixedEscapes verifies both backslash and single
// quote doubling in a single string.
func TestQuoteMySQLString_S22_MixedEscapes(t *testing.T) {
	// Input: a\'b  → backslash doubled first → a\\'b → quote doubled → a\\''b
	// Final quoted: 'a\\''b'
	assert.Equal(t, `'a\\''b'`, quoteMySQLString(`a\'b`))
}

// TestQuoteMySQLString_S22_EmptyString verifies that an empty string becomes
// a pair of single quotes.
func TestQuoteMySQLString_S22_EmptyString(t *testing.T) {
	assert.Equal(t, `''`, quoteMySQLString(""))
}

// ---------------------------------------------------------------------------
// quoteIdentifier — direct unit tests (postgres.go)
// ---------------------------------------------------------------------------

// TestQuoteIdentifier_S22_Clean verifies a clean identifier is double-quoted.
func TestQuoteIdentifier_S22_Clean(t *testing.T) {
	assert.Equal(t, `"myRole"`, quoteIdentifier("myRole"))
}

// TestQuoteIdentifier_S22_DoubleQuoteDoubled verifies that an embedded
// double-quote is doubled so the identifier cannot escape the DDL.
func TestQuoteIdentifier_S22_DoubleQuoteDoubled(t *testing.T) {
	assert.Equal(t, `"ro""le"`, quoteIdentifier(`ro"le`))
}

// TestQuoteIdentifier_S22_Empty verifies an empty identifier is safe.
func TestQuoteIdentifier_S22_Empty(t *testing.T) {
	assert.Equal(t, `""`, quoteIdentifier(""))
}

// ---------------------------------------------------------------------------
// quoteLiteral — direct unit tests (postgres.go)
// ---------------------------------------------------------------------------

// TestQuoteLiteral_S22_Clean verifies a clean value is single-quoted.
func TestQuoteLiteral_S22_Clean(t *testing.T) {
	assert.Equal(t, `'newpass'`, quoteLiteral("newpass"))
}

// TestQuoteLiteral_S22_SingleQuoteDoubled verifies that an embedded
// single-quote is doubled.
func TestQuoteLiteral_S22_SingleQuoteDoubled(t *testing.T) {
	assert.Equal(t, `'it''s'`, quoteLiteral("it's"))
}

// TestQuoteLiteral_S22_Empty verifies an empty literal is safe.
func TestQuoteLiteral_S22_Empty(t *testing.T) {
	assert.Equal(t, `''`, quoteLiteral(""))
}

// ---------------------------------------------------------------------------
// MySQL empty-DSN guard
// ---------------------------------------------------------------------------

// TestMySQLExecutor_S22_EmptyDSN verifies that Rotate returns an error when
// the DSN is empty, even after all earlier guards pass.
func TestMySQLExecutor_S22_EmptyDSN(t *testing.T) {
	e := NewMySQLExecutor("mysql-noDSN", "", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no admin DSN")
}

// ---------------------------------------------------------------------------
// Redis empty-DSN guard
// ---------------------------------------------------------------------------

// TestRedisExecutor_S22_EmptyDSN verifies that Rotate returns an error when
// the DSN is empty, after all earlier guards pass.
func TestRedisExecutor_S22_EmptyDSN(t *testing.T) {
	e := NewRedisExecutor("redis-noDSN", "", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no admin DSN")
}

// ---------------------------------------------------------------------------
// MongoDB empty-DSN guard
// ---------------------------------------------------------------------------

// TestMongoExecutor_S22_EmptyDSN verifies that Rotate returns an error when
// the DSN is empty, after all earlier guards pass.
func TestMongoExecutor_S22_EmptyDSN(t *testing.T) {
	e := NewMongoExecutor("mongo-noDSN", "", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no admin DSN")
}

// ---------------------------------------------------------------------------
// MongoDB conn-error path (newConn returns error)
// ---------------------------------------------------------------------------

// TestMongoExecutor_S22_ConnError covers the conn() error branch in Rotate
// when newConn returns an error after all guards pass.
func TestMongoExecutor_S22_ConnError(t *testing.T) {
	e := NewMongoExecutor("mongo-connerr", "mongodb://localhost:27017", []string{"svc-"})
	e.newConn = func(context.Context, string) (mongoConn, error) {
		return nil, errors.New("connection refused")
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

// ---------------------------------------------------------------------------
// MySQL conn-error path (newConn returns error)
// ---------------------------------------------------------------------------

// TestMySQLExecutor_S22_ConnError covers the conn() error branch in Rotate
// when newConn returns an error after all guards pass.
func TestMySQLExecutor_S22_ConnError(t *testing.T) {
	e := NewMySQLExecutor("mysql-connerr", "user:pw@tcp(db:3306)/", []string{"svc-"})
	e.newConn = func(context.Context, string) (mysqlConn, error) {
		return nil, errors.New("dial tcp: connection refused")
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

// ---------------------------------------------------------------------------
// Postgres conn-error path (newConn returns error)
// ---------------------------------------------------------------------------

// TestPostgresExecutor_S22_ConnError covers the conn() error branch in Rotate
// when newConn returns an error after all guards pass.
func TestPostgresExecutor_S22_ConnError(t *testing.T) {
	e := NewPostgresExecutor("pg-connerr", "postgres://admin@db/postgres", []string{"svc-"})
	e.newConn = func(context.Context, string) (pgConn, error) {
		return nil, errors.New("dial tcp: connection refused")
	}
	err := e.Rotate(context.Background(), "svc-app", "newpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

// ---------------------------------------------------------------------------
// azureGraphClient.RemovePassword — success path via httptest
// ---------------------------------------------------------------------------

// TestAzureGraphClient_S22_RemovePassword_Success exercises RemovePassword
// by routing through an httptest server that returns 204 No Content, covering
// the do() branch where out is nil.
func TestAzureGraphClient_S22_RemovePassword_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := &azureGraphClient{
		cred: &fakeTokenCredential{token: "tok"},
		http: &http.Client{Transport: &rewriteTransport{target: srv.URL, inner: srv.Client().Transport}},
	}
	err := c.RemovePassword(context.Background(), "test-app-id", "key-123")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// azureGraphClient.do() — HTTP 5xx response
// ---------------------------------------------------------------------------

// TestAzureGraphClient_S22_Do_ServerError verifies that a 5xx response is
// surfaced as an error with the status code in the message.
func TestAzureGraphClient_S22_Do_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer srv.Close()

	c := &azureGraphClient{
		cred: &fakeTokenCredential{token: "tok"},
		http: srv.Client(),
	}
	err := c.do(context.Background(), http.MethodGet, srv.URL+"/test", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// ---------------------------------------------------------------------------
// azureGraphClient.do() — token error propagates into do()
// ---------------------------------------------------------------------------

// TestAzureGraphClient_S22_Do_TokenError verifies that a GetToken failure
// inside do() is propagated as the return error.
func TestAzureGraphClient_S22_Do_TokenError(t *testing.T) {
	c := &azureGraphClient{
		cred: &fakeTokenCredential{err: errors.New("no credentials available")},
		http: http.DefaultClient,
	}
	err := c.do(context.Background(), http.MethodGet, "https://graph.microsoft.com/v1.0/test", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials available")
}

// ---------------------------------------------------------------------------
// Azure GenerateUpstream — mixed prior deletion: some succeed, some fail
// ---------------------------------------------------------------------------

// fakeAzureMixedRemove is a fake that fails only specific key IDs.
type fakeAzureMixedRemove struct {
	fakeAzure
	failKeys map[string]bool
}

func (f *fakeAzureMixedRemove) RemovePassword(_ context.Context, _, keyID string) error {
	if f.failKeys[keyID] {
		return errors.New("permission denied for key " + keyID)
	}
	f.removed = append(f.removed, keyID)
	return nil
}

// TestAzure_S22_GenerateUpstream_PartialDeletion tests the scenario where
// there are multiple prior secrets and only some can be deleted. The rotation
// must be flagged as partial (PartialRotationError) carrying the new secret,
// even though one of the old secrets was successfully deleted.
func TestAzure_S22_GenerateUpstream_PartialDeletion(t *testing.T) {
	fake := &fakeAzureMixedRemove{
		fakeAzure: fakeAzure{
			existing:  []string{"kid-ok", "kid-fail"},
			newSecret: "fresh-secret",
		},
		failKeys: map[string]bool{"kid-fail": true},
	}
	e := NewAzureAppSecretExecutor("azure-s22-partial", []string{"app-"})
	e.newClient = func(context.Context) (azureGraphAPI, error) { return fake, nil }

	v, err := e.GenerateUpstream(context.Background(), "app-guid")
	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial, "mixed deletion must produce PartialRotationError")
	assert.Equal(t, "fresh-secret", partial.Value, "new secret must be carried on the error")
	assert.Contains(t, err.Error(), "kid-fail", "the un-deleted key id must appear in the error")
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v, "return value must be empty on partial rotation")
	// The key that could be deleted was removed.
	assert.Contains(t, fake.removed, "kid-ok")
}

// ---------------------------------------------------------------------------
// GCP GenerateUpstream — mixed prior deletion: some succeed, some fail
// ---------------------------------------------------------------------------

// fakeGCPMixedDelete is a fake gcpKeyAPI that fails DeleteKey only for
// specific key names, allowing partial-deletion scenarios.
type fakeGCPMixedDelete struct {
	existing []string
	newName  string
	newJSON  string
	failKeys map[string]bool
	deleted  []string
}

func (f *fakeGCPMixedDelete) ListKeys(_ context.Context, _ string) ([]gcpServiceAccountKeyInfo, error) {
	keys := make([]gcpServiceAccountKeyInfo, len(f.existing))
	for i, name := range f.existing {
		keys[i] = gcpServiceAccountKeyInfo{Name: name}
	}
	return keys, nil
}
func (f *fakeGCPMixedDelete) CreateKey(_ context.Context, _ string) (string, string, error) {
	return f.newName, f.newJSON, nil
}
func (f *fakeGCPMixedDelete) DeleteKey(_ context.Context, keyName string) error {
	if f.failKeys[keyName] {
		return errors.New("permission denied for " + keyName)
	}
	f.deleted = append(f.deleted, keyName)
	return nil
}

// TestGCP_S22_GenerateUpstream_PartialDeletion tests that when some prior
// keys are deleted and others fail, a PartialRotationError is returned with
// the new key JSON preserved.
func TestGCP_S22_GenerateUpstream_PartialDeletion(t *testing.T) {
	fake := &fakeGCPMixedDelete{
		existing: []string{"k/OLD-OK", "k/OLD-FAIL"},
		newName:  "k/NEW",
		newJSON:  `{"type":"service_account","key":"new"}`,
		failKeys: map[string]bool{"k/OLD-FAIL": true},
	}
	e := NewGCPServiceAccountKeyExecutor("gcp-s22-partial", []string{"svc-"})
	e.newClient = func(context.Context) (gcpKeyAPI, error) { return fake, nil }

	v, err := e.GenerateUpstream(context.Background(), "svc-app@p.iam")
	require.Error(t, err)
	var partial *PartialRotationError
	require.ErrorAs(t, err, &partial, "mixed deletion must produce PartialRotationError")
	assert.Equal(t, `{"type":"service_account","key":"new"}`, partial.Value)
	assert.Contains(t, err.Error(), "k/OLD-FAIL")
	assert.Contains(t, err.Error(), "still live")
	assert.Empty(t, v)
	assert.Contains(t, fake.deleted, "k/OLD-OK")
}

// ---------------------------------------------------------------------------
// AWSIAMExecutor slot-free delete failure (two-key cap, eviction delete fails)
// ---------------------------------------------------------------------------

// fakeIAMSlotFreeErrS22 is a fake whose DeleteAccessKey always fails, so the
// slot-free eviction at the two-key cap surfaces as an error.
type fakeIAMSlotFreeErrS22 struct {
	keys      []iamtypes.AccessKeyMetadata
	deleteErr error
}

func (f *fakeIAMSlotFreeErrS22) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys}, nil
}
func (f *fakeIAMSlotFreeErrS22) CreateAccessKey(_ context.Context, _ *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{AccessKey: &iamtypes.AccessKey{
		AccessKeyId: aws.String("AKIANEW"), SecretAccessKey: aws.String("secret"),
	}}, nil
}
func (f *fakeIAMSlotFreeErrS22) DeleteAccessKey(_ context.Context, _ *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return nil, f.deleteErr
}

// TestAWSIAM_S22_SlotFreeDeleteFails verifies that when a user is at the
// two-key cap and the slot-free eviction delete fails, the error is returned
// immediately without attempting to create a new key.
func TestAWSIAM_S22_SlotFreeDeleteFails(t *testing.T) {
	fake := &fakeIAMSlotFreeErrS22{
		keys: []iamtypes.AccessKeyMetadata{
			{AccessKeyId: aws.String("AKIA1"), Status: iamtypes.StatusTypeActive},
			{AccessKeyId: aws.String("AKIA2"), Status: iamtypes.StatusTypeActive},
		},
		deleteErr: errors.New("AccessDenied: cannot delete key"),
	}
	e := NewAWSIAMExecutor("aws-s22-slotfree", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }

	_, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDenied")
	assert.Contains(t, err.Error(), "delete access key")
}

// ---------------------------------------------------------------------------
// AWSIAMExecutor — credential JSON marshal verify
// ---------------------------------------------------------------------------

// TestAWSIAM_S22_GenerateUpstream_CredentialJSON verifies that the returned
// JSON from GenerateUpstream contains both access_key_id and
// secret_access_key fields.
func TestAWSIAM_S22_GenerateUpstream_CredentialJSON(t *testing.T) {
	fake := &fakeIAM{newID: "AKIAEXAMPLE", newSecret: "wJalrXUtnFEMI"}
	e := NewAWSIAMExecutor("aws-s22-json", "us-east-1", []string{"svc-"})
	e.newClient = func(context.Context) (iamAPI, error) { return fake, nil }

	v, err := e.GenerateUpstream(context.Background(), "svc-app")
	require.NoError(t, err)

	var cred map[string]string
	require.NoError(t, json.Unmarshal([]byte(v), &cred))
	assert.Equal(t, "AKIAEXAMPLE", cred["access_key_id"])
	assert.Equal(t, "wJalrXUtnFEMI", cred["secret_access_key"])
}

// ---------------------------------------------------------------------------
// AzureAppSecretExecutor.Rotate() — always returns an error
// ---------------------------------------------------------------------------

// TestAzure_S22_RotateAlwaysErrors verifies the Rotate method on the
// generate-upstream Azure executor returns an instructive error directing
// the caller to use GenerateUpstream.
func TestAzure_S22_RotateAlwaysErrors(t *testing.T) {
	e := NewAzureAppSecretExecutor("azure-s22-rotate", []string{"app-"})
	err := e.Rotate(context.Background(), "app-guid", "some-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

// ---------------------------------------------------------------------------
// GCPServiceAccountKeyExecutor.Rotate() — always returns an error
// ---------------------------------------------------------------------------

// TestGCP_S22_RotateAlwaysErrors verifies the Rotate method on the
// generate-upstream GCP executor returns an instructive error.
func TestGCP_S22_RotateAlwaysErrors(t *testing.T) {
	e := NewGCPServiceAccountKeyExecutor("gcp-s22-rotate", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app@p.iam", "some-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

// ---------------------------------------------------------------------------
// AWSIAMExecutor.Rotate() — always returns an error
// ---------------------------------------------------------------------------

// TestAWSIAM_S22_RotateAlwaysErrors verifies the Rotate method on the
// generate-upstream AWS executor returns an instructive error.
func TestAWSIAM_S22_RotateAlwaysErrors(t *testing.T) {
	e := NewAWSIAMExecutor("aws-s22-rotate", "us-east-1", []string{"svc-"})
	err := e.Rotate(context.Background(), "svc-app", "some-value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateUpstream")
}

// ---------------------------------------------------------------------------
// Manager.Names() — ordering-agnostic check with several executors
// ---------------------------------------------------------------------------

// TestManager_S22_NamesMultiple verifies that Names() returns all executor
// names, regardless of insertion order.
func TestManager_S22_NamesMultiple(t *testing.T) {
	execs := []Executor{
		stubExec{name: "alpha"},
		stubExec{name: "beta"},
		stubExec{name: "gamma"},
	}
	m := NewManager(execs)
	assert.ElementsMatch(t, []string{"alpha", "beta", "gamma"}, m.Names())
}

// TestManager_S22_MixedNilAndValid verifies that nil entries are skipped and
// valid executors are registered correctly.
func TestManager_S22_MixedNilAndValid(t *testing.T) {
	execs := []Executor{nil, stubExec{name: "x"}, nil, stubExec{name: "y"}}
	m := NewManager(execs)
	assert.ElementsMatch(t, []string{"x", "y"}, m.Names())
	_, ok := m.Get("x")
	assert.True(t, ok)
	_, ok = m.Get("y")
	assert.True(t, ok)
}

// ---------------------------------------------------------------------------
// redactSQLError — additional edge cases
// ---------------------------------------------------------------------------

// TestRedactSQLError_S22_AdjacentLiterals verifies that two adjacent
// single-quoted literals are each individually redacted.
func TestRedactSQLError_S22_AdjacentLiterals(t *testing.T) {
	raw := errors.New("near 'foo''bar' in statement")
	wrapped := redactSQLError("mysql", "user", raw)
	require.Error(t, wrapped)
	// 'foo''bar' is a single SQL literal ('' escape inside); it must be
	// treated as one literal and redacted to '***'.
	assert.NotContains(t, wrapped.Error(), "foo")
	assert.NotContains(t, wrapped.Error(), "bar")
	assert.Contains(t, wrapped.Error(), "'***'")
}

// TestRedactSQLError_S22_EmptyLiteral verifies that an empty SQL literal
// (”) is also redacted.
func TestRedactSQLError_S22_EmptyLiteral(t *testing.T) {
	raw := errors.New("near '' in statement")
	wrapped := redactSQLError("postgresql", "role", raw)
	require.Error(t, wrapped)
	assert.Contains(t, wrapped.Error(), "'***'")
}

// ---------------------------------------------------------------------------
// PartialRotationError — errors.As unwrap from a wrapping error
// ---------------------------------------------------------------------------

// TestPartialRotationError_S22_WrappedUnwrap verifies that errors.As finds
// a PartialRotationError even when it is wrapped by another error layer.
func TestPartialRotationError_S22_WrappedUnwrap(t *testing.T) {
	inner := &PartialRotationError{
		Value: "key-material",
		Err:   errors.New("cleanup failed"),
	}
	outer := errors.Join(errors.New("outer context"), inner)

	var partial *PartialRotationError
	require.True(t, errors.As(outer, &partial), "errors.As must find the PartialRotationError through wrapping")
	assert.Equal(t, "key-material", partial.Value)
}
