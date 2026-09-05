// auth_login_remote_test.go covers Login's RemoteLoginVerifier branch
// (auth.go), entirely untested before this file: every existing Login test
// exercises the direct LocalStorage (bcrypt) path, never a storage backend
// that implements RemoteLoginVerifier (storage.type: remote, #508). The four
// branches below mirror the four the LocalStorage path already has coverage
// for (verify error, MFA-required, defensive nil-session fail-closed, and
// success) so both dispatch paths carry the same invariant coverage.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// remoteLoginVerifierStorage wraps MockStorage to additionally implement
// RemoteLoginVerifier, so Login's `c.storage.(RemoteLoginVerifier)` type
// assertion succeeds -- MockStorage alone does not implement this interface.
type remoteLoginVerifierStorage struct {
	*MockStorage
	verify func(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error)
}

func (m *remoteLoginVerifierStorage) VerifyLoginCredentials(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
	return m.verify(ctx, username, password, userAgent, ipAddress)
}

func TestLogin_Remote_VerifyError(t *testing.T) {
	storage := &remoteLoginVerifierStorage{
		MockStorage: new(MockStorage),
		verify: func(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
			return nil, nil, errors.New("invalid credentials")
		},
	}
	c := NewKeyorixCore(storage)
	session, user, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: "pw"})
	require.Error(t, err)
	assert.Nil(t, session)
	assert.Nil(t, user)
}

func TestLogin_Remote_MFARequired(t *testing.T) {
	storage := &remoteLoginVerifierStorage{
		MockStorage: new(MockStorage),
		verify: func(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
			return &models.User{ID: 1, Username: "alice", MFAEnabled: true}, nil, nil
		},
	}
	c := NewKeyorixCore(storage)
	session, user, err := c.Login(context.Background(), &LoginRequest{Username: "alice", Password: "pw"})
	require.ErrorIs(t, err, ErrMFARequired)
	assert.Nil(t, session)
	require.NotNil(t, user)
	assert.Equal(t, uint(1), user.ID)
}

// TestLogin_Remote_NilSessionWithoutMFA_FailsClosed pins the defensive branch:
// an upstream that reports no MFA/WebAuthn gate but still withholds a session
// (a contract violation on the upstream's part) must not let Login proceed
// with a nil session -- it fails closed with an explicit error instead.
func TestLogin_Remote_NilSessionWithoutMFA_FailsClosed(t *testing.T) {
	storage := &remoteLoginVerifierStorage{
		MockStorage: new(MockStorage),
		verify: func(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
			return &models.User{ID: 2, Username: "bob"}, nil, nil
		},
	}
	c := NewKeyorixCore(storage)
	session, user, err := c.Login(context.Background(), &LoginRequest{Username: "bob", Password: "pw"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not return one")
	assert.Nil(t, session)
	assert.Nil(t, user)
}

func TestLogin_Remote_Success(t *testing.T) {
	wantUser := &models.User{ID: 3, Username: "carol"}
	wantSession := &models.Session{ID: 99, UserID: 3, SessionToken: "tok-abc"}
	storage := &remoteLoginVerifierStorage{
		MockStorage: new(MockStorage),
		verify: func(ctx context.Context, username, password, userAgent, ipAddress string) (*models.User, *models.Session, error) {
			assert.Equal(t, "carol", username)
			assert.Equal(t, "correct-horse", password)
			assert.Equal(t, "test-agent", userAgent)
			assert.Equal(t, "10.0.0.1", ipAddress)
			return wantUser, wantSession, nil
		},
	}
	c := NewKeyorixCore(storage)
	session, user, err := c.Login(context.Background(), &LoginRequest{
		Username: "carol", Password: "correct-horse", UserAgent: "test-agent", IPAddress: "10.0.0.1",
	})
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, wantSession.SessionToken, session.SessionToken)
	require.NotNil(t, user)
	assert.Equal(t, uint(3), user.ID)
}
