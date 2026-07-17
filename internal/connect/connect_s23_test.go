package connect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── connect.go: RefHasDotSegment edge cases ──────────────────────────────────

// TestRefHasDotSegment_S23_TripleDotIsNotTraversal verifies that a segment of
// three dots ("...") is NOT treated as a traversal segment — only "." and ".."
// are reserved by POSIX. A legitimate ref whose segment happens to be "..." must
// pass through.
func TestRefHasDotSegment_S23_TripleDotIsNotTraversal(t *testing.T) {
	assert.False(t, RefHasDotSegment("secret/data/.../config"),
		"\"...\" is not a POSIX traversal segment and must not be rejected")
}

// TestRefHasDotSegment_S23_SingleDotAlone verifies that a ref equal to "." alone
// (one segment, no slashes) is reported as containing a dot segment.
func TestRefHasDotSegment_S23_SingleDotAlone(t *testing.T) {
	assert.True(t, RefHasDotSegment("."))
}

// TestRefHasDotSegment_S23_DotDotAlone verifies a ref equal to ".." alone.
func TestRefHasDotSegment_S23_DotDotAlone(t *testing.T) {
	assert.True(t, RefHasDotSegment(".."))
}

// TestRefHasDotSegment_S23_DotInLeafSegment exercises a dot embedded inside a
// regular segment name such as "v1.0" — only whole-segment "." counts.
func TestRefHasDotSegment_S23_DotInLeafSegment(t *testing.T) {
	assert.False(t, RefHasDotSegment("secret/data/v1.0/config"),
		"a dot inside a segment name is not a traversal segment")
}

// ── connect.go: prefixAllowed edge cases ────────────────────────────────────

// TestPrefixAllowed_S23_NilAllowlistWithTraversal confirms that a nil allowlist
// still blocks a traversal-shaped ref (the early RefHasDotSegment guard fires
// before the "empty => permit all" shortcut).
func TestPrefixAllowed_S23_NilAllowlistWithTraversal(t *testing.T) {
	assert.False(t, prefixAllowed(nil, "secret/./etc"),
		"traversal must be denied even with a nil allowlist")
}

// TestPrefixAllowed_S23_AllowlistContainingOnlyEmptyStrings verifies that an
// allowlist whose entries are all empty strings is effectively non-empty (so the
// "len == 0 permits everything" shortcut does not fire), but every empty prefix
// is skipped inside the loop — net result: the ref is denied.
func TestPrefixAllowed_S23_AllowlistContainingOnlyEmptyStrings(t *testing.T) {
	assert.False(t, prefixAllowed([]string{"", "", ""}, "any/ref"),
		"a list of only empty-string entries must not grant access")
}

// TestPrefixAllowed_S23_ExactPrefixMatch verifies that a ref equal to the prefix
// exactly (no trailing slash, no sub-path) is permitted.
func TestPrefixAllowed_S23_ExactPrefixMatch(t *testing.T) {
	assert.True(t, prefixAllowed([]string{"prod/db"}, "prod/db"))
}

// TestPrefixAllowed_S23_RefShorterThanAllPrefix checks that a ref that is a
// proper prefix of an allowed prefix is not accidentally permitted.
func TestPrefixAllowed_S23_RefShorterThanAllPrefix(t *testing.T) {
	assert.False(t, prefixAllowed([]string{"prod/db/credentials"}, "prod/db"),
		"a ref shorter than every configured prefix must be denied")
}

// ── connect.go: refWithinPrefix edge cases ──────────────────────────────────

// TestRefWithinPrefix_S23_EmptyPrefixNeverMatches verifies that an empty prefix
// string ("") never satisfies refWithinPrefix for a non-empty ref. This is the
// internal helper; the allowlist loop already skips p=="" entries, but the
// function itself must also be sound.
func TestRefWithinPrefix_S23_EmptyPrefixNeverMatches(t *testing.T) {
	// ref == p when both are "": returns true (trivial exact match).
	assert.True(t, refWithinPrefix("", ""))
	// non-empty ref never equals empty prefix, and HasPrefix("anything", "") is
	// always true — so the segment-boundary check applies: ref[len("")] == ref[0]
	// which is not '/', so the function must return false.
	assert.False(t, refWithinPrefix("", "db/prod"),
		"a non-empty ref must not be considered within an empty prefix")
}

// TestRefWithinPrefix_S23_TrailingSlashPrefixExactMatch verifies that a ref that
// equals the prefix with the trailing slash included is still accepted.
func TestRefWithinPrefix_S23_TrailingSlashPrefixExactMatch(t *testing.T) {
	assert.True(t, refWithinPrefix("db/prod/", "db/prod/"))
}

// ── connect.go: Manager ──────────────────────────────────────────────────────

// TestManager_S23_NilConnectorInList verifies that a nil entry in the connector
// slice is silently skipped and does not cause a panic.
func TestManager_S23_NilConnectorInList(t *testing.T) {
	named := connectorWith("real", &fakeSM{})
	m := NewManager([]Connector{nil, named, nil})
	assert.ElementsMatch(t, []string{"real"}, m.Names())
	_, ok := m.Get("real")
	assert.True(t, ok)
}

// TestManager_S23_NilManagerGetIsNilSafe verifies that (*Manager)(nil).Get does
// not panic and returns (nil, false).
func TestManager_S23_NilManagerGetIsNilSafe(t *testing.T) {
	var m *Manager
	c, ok := m.Get("x")
	assert.False(t, ok)
	assert.Nil(t, c)
}

// TestManager_S23_NilManagerNamesIsNilSafe verifies that (*Manager)(nil).Names
// does not panic and returns nil.
func TestManager_S23_NilManagerNamesIsNilSafe(t *testing.T) {
	var m *Manager
	assert.Nil(t, m.Names())
}

// ── vault.go: sanitizeVaultRef additional branches ──────────────────────────

// TestSanitizeVaultRef_S23_HashIsEncoded verifies that a hash character "#" is
// percent-escaped and cannot inject a URL fragment.
func TestSanitizeVaultRef_S23_HashIsEncoded(t *testing.T) {
	got, err := sanitizeVaultRef("secret/data/app#fragment")
	require.NoError(t, err)
	assert.NotContains(t, got, "#", "# must be percent-escaped")
	assert.Contains(t, got, "%23", "# must become %23 in the path")
}

// TestSanitizeVaultRef_S23_MultipleLeadingSlashes verifies that multiple leading
// slashes are stripped the same way a single leading slash is, without leaving an
// empty leading segment.
func TestSanitizeVaultRef_S23_MultipleLeadingSlashes(t *testing.T) {
	got, err := sanitizeVaultRef("//secret/data/app")
	require.NoError(t, err)
	assert.Equal(t, "secret/data/app", got,
		"multiple leading slashes must be collapsed away")
}

// TestSanitizeVaultRef_S23_OnlySlashes verifies that a ref consisting entirely
// of slash characters (which all collapse to empty segments) returns an error.
func TestSanitizeVaultRef_S23_OnlySlashes(t *testing.T) {
	_, err := sanitizeVaultRef("///")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no usable path")
}

// TestSanitizeVaultRef_S23_PercentLiteralIsEncoded verifies that a literal "%"
// character is passed through url.PathEscape and becomes "%25" — it is not
// misinterpreted as an existing percent-encoding.
func TestSanitizeVaultRef_S23_PercentLiteralIsEncoded(t *testing.T) {
	got, err := sanitizeVaultRef("secret/data/100%secure")
	require.NoError(t, err)
	assert.Contains(t, got, "%25", "literal % must be encoded as %25")
}

// TestSanitizeVaultRef_S23_NullByteRejected verifies that the NUL byte (0x00)
// is rejected as a control character.
func TestSanitizeVaultRef_S23_NullByteRejected(t *testing.T) {
	_, err := sanitizeVaultRef("secret/data/bad\x00key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "control character")
}

// TestSanitizeVaultRef_S23_SegmentsJoinedWithSlash verifies the multi-segment
// output has exactly one "/" between each sanitized segment (no doubling).
func TestSanitizeVaultRef_S23_SegmentsJoinedWithSlash(t *testing.T) {
	got, err := sanitizeVaultRef("a/b/c")
	require.NoError(t, err)
	assert.Equal(t, "a/b/c", got)
}

// ── vault.go: GetSecret branches not yet covered ────────────────────────────

// TestVault_S23_GetSecret_AllowedRefsTraversalBlocked verifies that a
// traversal-shaped ref that would literally satisfy a HasPrefix check on the
// configured allowed_refs is blocked by prefixAllowed before sanitizeVaultRef
// even runs.
func TestVault_S23_GetSecret_AllowedRefsTraversalBlocked(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"x":"y"}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewVaultConnector("v", srv.URL, "tok", []string{"secret/data/app/"})
	_, err := c.GetSecret(context.Background(), "secret/data/app/../other/secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
	assert.Zero(t, hits, "no request must reach the server for a traversal ref")
}

// TestVault_S23_GetSecret_EmptyRefRejected verifies the empty-ref early return.
func TestVault_S23_GetSecret_EmptyRefRejected(t *testing.T) {
	c := NewVaultConnector("v", "https://vault.example.com", "tok", nil)
	_, err := c.GetSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestVault_S23_GetSecret_MissingToken verifies the missing-token early return.
func TestVault_S23_GetSecret_MissingToken(t *testing.T) {
	c := NewVaultConnector("v", "https://vault.example.com", "", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token")
}

// TestVault_S23_GetSecret_NetworkError verifies that a connector whose address
// points to a server that has been shut down returns a wrapped network error.
func TestVault_S23_GetSecret_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"x":"y"}}`))
	}))
	addr := srv.URL
	srv.Close() // shut down immediately so the GET fails

	c := NewVaultConnector("v", addr, "tok", nil)
	_, err := c.GetSecret(context.Background(), "secret/data/app")
	require.Error(t, err)
}

// TestVault_S23_GetSecret_KVv2BothDataAndMetadata is a positive KV-v2 path
// exercised end-to-end through fakeVault to confirm the KV v2 unwrap returns
// just the inner data object, not the outer envelope.
func TestVault_S23_GetSecret_KVv2BothDataAndMetadata(t *testing.T) {
	srv := fakeVault(t, "tok", map[string]string{
		"/v1/secret/data/svc": `{"data":{"data":{"key":"val"},"metadata":{"version":7,"created_time":"2024-01-01T00:00:00Z"}}}`,
	})
	c := NewVaultConnector("v", srv.URL, "tok", nil)
	val, err := c.GetSecret(context.Background(), "secret/data/svc")
	require.NoError(t, err)
	assert.JSONEq(t, `{"key":"val"}`, val)
}

// ── awssm.go: additional branches ───────────────────────────────────────────

// TestAWSSM_S23_GetSecret_TraversalRefBlockedByAllowedRefs verifies that a
// traversal-shaped ref that would satisfy a literal HasPrefix check on
// allowed_refs is rejected before the backend client is built.
func TestAWSSM_S23_GetSecret_TraversalRefBlockedByAllowedRefs(t *testing.T) {
	var buildCount int
	c := NewAWSSecretsManagerConnector("aws", "eu-west-1", []string{"keyorix/"})
	c.newClient = func(_ context.Context, _ string) (smSecretGetter, error) {
		buildCount++
		return &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("x")}}, nil
	}
	_, err := c.GetSecret(context.Background(), "keyorix/../root/secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
	assert.Zero(t, buildCount, "client must not be built for a traversal ref")
}

// TestAWSSM_S23_GetSecret_EmptyRefRejected verifies the empty-ref early return.
func TestAWSSM_S23_GetSecret_EmptyRefRejected(t *testing.T) {
	c := connectorWith("aws", &fakeSM{})
	_, err := c.GetSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestAWSSM_S23_GetSecret_BothStringAndBinaryNil exercises the branch where the
// SM output is non-nil but SecretString is nil and SecretBinary is empty — the
// "no value" error path.
func TestAWSSM_S23_GetSecret_BothStringAndBinaryNil(t *testing.T) {
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{
		SecretString: nil,
		SecretBinary: nil,
	}}
	_, err := connectorWith("aws", fake).GetSecret(context.Background(), "prod/db")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

// TestAWSSM_S23_GetSecret_NoRegion verifies that a connector configured with an
// empty region string still builds a client (region is optional in the AWS
// credential chain) and returns the secret value.
func TestAWSSM_S23_GetSecret_NoRegion(t *testing.T) {
	c := NewAWSSecretsManagerConnector("aws", "", nil) // region == ""
	c.newClient = func(_ context.Context, region string) (smSecretGetter, error) {
		assert.Equal(t, "", region, "empty region must be forwarded as-is")
		return &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("val")}}, nil
	}
	val, err := c.GetSecret(context.Background(), "prod/db")
	require.NoError(t, err)
	assert.Equal(t, "val", val)
}

// TestAWSSM_S23_TypeAndName is a sanity guard that Name() and Type() are
// forwarded from the struct fields unchanged.
func TestAWSSM_S23_TypeAndName(t *testing.T) {
	c := NewAWSSecretsManagerConnector("my-connector", "us-east-1", nil)
	assert.Equal(t, "my-connector", c.Name())
	assert.Equal(t, "aws-secrets-manager", c.Type())
}

// ── azurekv.go: additional branches ─────────────────────────────────────────

// TestAzureKV_S23_GetSecret_TraversalRefBlockedByAllowedRefs verifies that
// traversal-shaped refs are rejected before the Key Vault client is built.
func TestAzureKV_S23_GetSecret_TraversalRefBlockedByAllowedRefs(t *testing.T) {
	var buildCount int
	c := NewAzureKeyVaultConnector("az", "https://v.vault.azure.net/", []string{"keyorix/"})
	c.newClient = func(_ context.Context) (azSecretGetter, error) {
		buildCount++
		return nil, errors.New("should not be called")
	}
	_, err := c.GetSecret(context.Background(), "keyorix/../other")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
	assert.Zero(t, buildCount, "client must not be built for a traversal ref")
}

// TestAzureKV_S23_GetSecret_VersionWithExtraSlash verifies the name/version
// split behaviour when the ref contains multiple slashes: strings.Cut splits
// only on the first "/" so only the first segment is the name and the remainder
// becomes the version string.
func TestAzureKV_S23_GetSecret_VersionWithExtraSlash(t *testing.T) {
	fake := &fakeAzKV{value: strptr("versioned")}
	// ref = "db-password/abc123/extra" — Cut("db-password/abc123/extra", "/")
	// returns name="db-password", version="abc123/extra".
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake)
	val, err := c.GetSecret(context.Background(), "db-password/abc123/extra")
	require.NoError(t, err)
	assert.Equal(t, "versioned", val)
	assert.Equal(t, "db-password", fake.gotName)
	assert.Equal(t, "abc123/extra", fake.gotVersion)
}

// TestAzureKV_S23_GetSecret_EmptyRefRejected verifies the empty-ref guard.
func TestAzureKV_S23_GetSecret_EmptyRefRejected(t *testing.T) {
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", &fakeAzKV{})
	_, err := c.GetSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestAzureKV_S23_GetSecret_EmptyVaultURL verifies the missing vault-URL guard
// fires before the allowed_refs check.
func TestAzureKV_S23_GetSecret_EmptyVaultURL(t *testing.T) {
	c := azKVConnectorWith("az", "", &fakeAzKV{})
	_, err := c.GetSecret(context.Background(), "some-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no vault address")
}

// TestAzureKV_S23_GetSecret_LeadingSlashEmptyName verifies that a ref beginning
// with "/" (which makes the segment before the first "/" empty) is rejected with
// an "empty secret name" error.
func TestAzureKV_S23_GetSecret_LeadingSlashEmptyName(t *testing.T) {
	fake := &fakeAzKV{value: strptr("x")}
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake)
	_, err := c.GetSecret(context.Background(), "/version-only")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty secret name")
	assert.False(t, fake.called, "backend must not be reached when the name is empty")
}

// TestAzureKV_S23_GetSecret_AllowedRefsPrefixMatches verifies the positive
// allowed_refs path: a ref that is within the allowed prefix reaches the backend
// and returns the value. The prefix must use a segment boundary (trailing slash
// or an exact match followed by '/') per refWithinPrefix semantics.
func TestAzureKV_S23_GetSecret_AllowedRefsPrefixMatches(t *testing.T) {
	fake := &fakeAzKV{value: strptr("secret-value")}
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake, "keyorix/")
	val, err := c.GetSecret(context.Background(), "keyorix/db")
	require.NoError(t, err)
	assert.Equal(t, "secret-value", val)
	assert.True(t, fake.called)
}

// ── gcpsm.go: additional branches ───────────────────────────────────────────

// TestGCPSM_S23_gcpRefProjectID_EmptyProjectSegment verifies that a ref of the
// form "projects//secrets/x/versions/1" (empty project segment between the two
// slashes) is rejected by gcpRefProjectID because strings.Cut finds "/" but the
// captured project string is "".
func TestGCPSM_S23_gcpRefProjectID_EmptyProjectSegment(t *testing.T) {
	project, ok := gcpRefProjectID("projects//secrets/x/versions/1")
	assert.False(t, ok, "an empty project segment must return ok=false")
	assert.Empty(t, project)
}

// TestGCPSM_S23_gcpRefProjectID_NoPrefixReturnsNotOK verifies that a ref that
// does not start with "projects/" returns ok=false.
func TestGCPSM_S23_gcpRefProjectID_NoPrefixReturnsNotOK(t *testing.T) {
	project, ok := gcpRefProjectID("secrets/x/versions/1")
	assert.False(t, ok)
	assert.Empty(t, project)
}

// TestGCPSM_S23_GetSecret_TraversalRefBlockedByAllowedRefs verifies that a
// traversal-shaped GCP ref is rejected before the Secret Manager client is
// built.
func TestGCPSM_S23_GetSecret_TraversalRefBlockedByAllowedRefs(t *testing.T) {
	var buildCount int
	c := NewGCPSecretManagerConnector("gcp", "", []string{"projects/p/"})
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) {
		buildCount++
		return nil, errors.New("should not be called")
	}
	_, err := c.GetSecret(context.Background(), "projects/p/../other/secrets/x/versions/1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
	assert.Zero(t, buildCount)
}

// TestGCPSM_S23_GetSecret_NilPayloadIsNoValue verifies the branch where the
// AccessSecretVersion response has a nil Payload (distinct from a non-nil
// Payload with empty Data, which is covered by s22).
func TestGCPSM_S23_GetSecret_NilPayloadIsNoValue(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: nil,
	}}
	c := gcpConnectorWith("gcp", fake)
	_, err := c.GetSecret(context.Background(), "projects/p/secrets/db/versions/latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

// TestGCPSM_S23_GetSecret_PinnedProjectMatchesExactly confirms that the pinned
// project check does a string equality on the project segment: a ref whose
// project is a prefix of the pinned project ("my-proj-suffix" vs "my-proj") is
// NOT considered a match.
func TestGCPSM_S23_GetSecret_PinnedProjectMatchesExactly(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")},
	}}
	c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
	_, err := c.GetSecret(context.Background(), "projects/my-proj-suffix/secrets/db/versions/latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pinned to project")
	assert.Empty(t, fake.got)
}

// TestGCPSM_S23_GetSecret_BackendErrorSurfaced verifies that an error returned
// by AccessSecretVersion is wrapped and propagated.
func TestGCPSM_S23_GetSecret_BackendErrorSurfaced(t *testing.T) {
	fake := &fakeGCPSM{err: errors.New("ResourceExhausted")}
	c := gcpConnectorWith("gcp", fake)
	_, err := c.GetSecret(context.Background(), "projects/p/secrets/db/versions/latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ResourceExhausted")
}

// TestGCPSM_S23_GetSecret_ClientClosedAfterUse verifies that the GCP client's
// Close() is called even when the backend returns an error (defer in GetSecret).
func TestGCPSM_S23_GetSecret_ClientClosedAfterUse(t *testing.T) {
	fake := &fakeGCPSM{err: errors.New("InternalError")}
	c := gcpConnectorWith("gcp", fake)
	_, _ = c.GetSecret(context.Background(), "projects/p/secrets/db/versions/latest")
	assert.True(t, fake.closed, "client must be closed even when the backend call fails")
}

// TestAzureKV_S23_GetSecret_BackendErrorMessage verifies the error message is
// correctly wrapped with the ref included.
func TestAzureKV_S23_GetSecret_BackendErrorMessage(t *testing.T) {
	fake := &fakeAzKV{err: errors.New("SecretNotFound")}
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake)
	_, err := c.GetSecret(context.Background(), "missing-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-secret")
	assert.Contains(t, err.Error(), "SecretNotFound")
}

// TestAzureKV_S23_TypeAndName is a sanity guard for Name() and Type().
func TestAzureKV_S23_TypeAndName(t *testing.T) {
	c := NewAzureKeyVaultConnector("my-vault", "https://v.vault.azure.net/", nil)
	assert.Equal(t, "my-vault", c.Name())
	assert.Equal(t, "azure-key-vault", c.Type())
}

// TestGCPSM_S23_TypeAndName is a sanity guard for Name() and Type().
func TestGCPSM_S23_TypeAndName(t *testing.T) {
	c := NewGCPSecretManagerConnector("my-gcp", "proj", nil)
	assert.Equal(t, "my-gcp", c.Name())
	assert.Equal(t, "gcp-secret-manager", c.Type())
}

// TestAzureKV_S23_GetSecret_NilValueSurfacesError verifies the nil-Value guard:
// a successful HTTP call whose response Secret.Value is nil returns "no value".
func TestAzureKV_S23_GetSecret_NilValueSurfacesError(t *testing.T) {
	fake := &fakeAzKV{value: nil}
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake)
	_, err := c.GetSecret(context.Background(), "db-creds")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no value")
}

// TestAzureKV_S23_GetSecret_RefWithVersionPassedCorrectly verifies that the
// name and version segments are split on the first "/" only and forwarded to the
// backend as distinct arguments.
func TestAzureKV_S23_GetSecret_RefWithVersionPassedCorrectly(t *testing.T) {
	fake := &fakeAzKV{value: strptr("versioned-val")}
	c := azKVConnectorWith("az", "https://v.vault.azure.net/", fake)
	val, err := c.GetSecret(context.Background(), "my-secret/v2")
	require.NoError(t, err)
	assert.Equal(t, "versioned-val", val)
	assert.Equal(t, "my-secret", fake.gotName)
	assert.Equal(t, "v2", fake.gotVersion)
}

// TestAWSSM_S23_GetSecret_BinarySecretBase64Roundtrip confirms that a binary
// secret is returned as a correct base64-encoded string that round-trips back to
// the original bytes.
func TestAWSSM_S23_GetSecret_BinarySecretBase64Roundtrip(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretBinary: payload}}
	val, err := connectorWith("aws", fake).GetSecret(context.Background(), "bin/secret")
	require.NoError(t, err)
	// The value should be standard base64 for {0xDE, 0xAD, 0xBE, 0xEF} = "3q2+7w=="
	assert.Equal(t, "3q2+7w==", val)
}

// TestGCPSM_S23_GetSecret_EmptyRefRejected verifies the empty-ref early return
// on the GCP connector.
func TestGCPSM_S23_GetSecret_EmptyRefRejected(t *testing.T) {
	c := gcpConnectorWith("gcp", &fakeGCPSM{})
	_, err := c.GetSecret(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestGCPSM_S23_GetSecret_PinnedProjectUnparseable verifies the branch where the
// connector is pinned to a project but the ref does not start with "projects/".
func TestGCPSM_S23_GetSecret_PinnedProjectUnparseable(t *testing.T) {
	fake := &fakeGCPSM{out: &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte("x")},
	}}
	c := gcpPinnedConnectorWith("gcp", "my-proj", fake)
	_, err := c.GetSecret(context.Background(), "secrets/db/versions/latest") // no "projects/" prefix
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not start with projects/PROJECT")
	assert.Empty(t, fake.got)
}
