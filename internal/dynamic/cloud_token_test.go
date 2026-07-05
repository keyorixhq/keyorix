package dynamic

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- GCP ---

type fakeGCPMinter struct {
	token       string
	expiry      time.Time
	err         error
	gotSA       string
	gotScopes   []string
	gotLifetime time.Duration
}

func (f *fakeGCPMinter) mintAccessToken(_ context.Context, sa string, scopes []string, lifetime time.Duration) (string, time.Time, error) {
	f.gotSA, f.gotScopes, f.gotLifetime = sa, scopes, lifetime
	return f.token, f.expiry, f.err
}

func TestGCPEngine_Issue(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeGCPMinter{token: "ya29.token", expiry: exp}
	eng := &GCPEngine{minter: fake}

	cfg := `{"service_account":"sa@proj.iam.gserviceaccount.com","scopes":["https://example/scope"],"lifetime_seconds":600}`
	cred, role, err := eng.Issue(context.Background(), cfg, "", time.Hour)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(role, "keyorix-dyn-"))
	assert.Equal(t, "ya29.token", cred.Fields["access_token"])
	assert.Equal(t, "sa@proj.iam.gserviceaccount.com", cred.Fields["service_account"])
	assert.NotEmpty(t, cred.Fields["expiration"])
	assert.Empty(t, cred.Username)

	// Config drove the minter: explicit scopes + lifetime override the ttl.
	assert.Equal(t, "sa@proj.iam.gserviceaccount.com", fake.gotSA)
	assert.Equal(t, []string{"https://example/scope"}, fake.gotScopes)
	assert.Equal(t, 600*time.Second, fake.gotLifetime)

	// Semantics.
	assert.True(t, eng.IsEphemeralBackend())
	assert.True(t, eng.SupportsNativeExpiry())
	assert.Equal(t, "gcp", eng.BackendType())
	require.NoError(t, eng.Revoke(context.Background(), "", role))
	require.Error(t, eng.Renew(context.Background(), "", role, time.Now()))
	assert.False(t, eng.RevokeInvalidatesCredential(""), "GCP generateAccessToken tokens can't be revoked before natural expiry")
}

func TestGCPEngine_Defaults(t *testing.T) {
	fake := &fakeGCPMinter{token: "t"}
	eng := &GCPEngine{minter: fake}
	_, _, err := eng.Issue(context.Background(), `{"service_account":"sa@p.iam.gserviceaccount.com"}`, "", 45*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, []string{gcpDefaultScope}, fake.gotScopes, "defaults to cloud-platform scope")
	assert.Equal(t, 45*time.Minute, fake.gotLifetime, "lifetime defaults to the lease TTL")
}

func TestGCPEngine_ConfigValidation(t *testing.T) {
	eng := &GCPEngine{minter: &fakeGCPMinter{}}
	_, _, err := eng.Issue(context.Background(), "not-json", "", time.Hour)
	require.Error(t, err)
	_, _, err = eng.Issue(context.Background(), `{"scopes":["s"]}`, "", time.Hour) // no service_account
	require.Error(t, err)
}

// --- Azure ---

type fakeAzureMinter struct {
	token     string
	expiry    time.Time
	err       error
	gotScopes []string
}

func (f *fakeAzureMinter) mintToken(_ context.Context, scopes []string) (string, time.Time, error) {
	f.gotScopes = scopes
	return f.token, f.expiry, f.err
}

func TestAzureEngine_Issue(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	fake := &fakeAzureMinter{token: "eyJ.token", expiry: exp}
	eng := &AzureEngine{minter: fake}

	cfg := `{"scopes":["https://management.azure.com/.default"]}`
	cred, role, err := eng.Issue(context.Background(), cfg, "", time.Hour)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(role, "keyorix-dyn-"))
	assert.Equal(t, "eyJ.token", cred.Fields["access_token"])
	assert.NotEmpty(t, cred.Fields["expiration"])
	assert.Equal(t, []string{"https://management.azure.com/.default"}, fake.gotScopes)
	assert.Empty(t, cred.Username)

	assert.True(t, eng.IsEphemeralBackend())
	assert.True(t, eng.SupportsNativeExpiry())
	assert.Equal(t, "azure", eng.BackendType())
	require.NoError(t, eng.Revoke(context.Background(), "", role))
	require.Error(t, eng.Renew(context.Background(), "", role, time.Now()))
	assert.False(t, eng.RevokeInvalidatesCredential(""), "Azure client-credential access tokens can't be revoked before natural expiry")
}

func TestAzureEngine_ConfigValidation(t *testing.T) {
	eng := &AzureEngine{minter: &fakeAzureMinter{}}
	_, _, err := eng.Issue(context.Background(), "not-json", "", time.Hour)
	require.Error(t, err)
	_, _, err = eng.Issue(context.Background(), `{}`, "", time.Hour) // no scopes
	require.Error(t, err)
}
