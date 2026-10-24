// account_current_password_budget_router_test.go — AUTH-ACCOUNT-1 item 3.
//
// #3365 (AUTH-PW-BUDGET) made POST /auth/change-password and PUT /auth/profile
// (email change) spend the /auth/login per-IP budget and audit a wrong current
// password as auth.login_failed with success=false. Its handler tests call the
// handler method with a hand-built context; these drive the same promises
// through the REAL router (NewRouter: routing, authentication middleware, client
// IP derivation, handler) with a real session bearer token:
//
//   - LoginMaxAttempts wrong current passwords answer 401, the next request from
//     that IP answers 429 even with the right password and changes nothing;
//   - each wrong password left one auth.login_failed row with Success=false,
//     the account and the client IP;
//   - the budget is per IP (another address still gets the ordinary 401), and a
//     profile edit that checks no password (display name) is never throttled.
//
// What it does not cover: the per-account lockout half (internal/core
// account_current_password_lockout_test.go) and a second-factor account.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/keyorixhq/keyorix/server/http/handlers"
)

const (
	acctBudgetPassword = "Qr7#Kp2$Lm5@Vn9!"
	acctBudgetNew      = "Brandnew#Passw0rd!y"
	acctBudgetIP       = "192.0.2.77:4242" // the caller; httptest's default is 192.0.2.1
	acctBudgetOtherIP  = "198.51.100.9:4242"
)

type acctBudgetEnv struct {
	router http.Handler
	c      *core.KeyorixCore
	st     corestorage.Storage
	token  string
	userID uint
}

func newAcctBudgetEnv(t *testing.T) *acctBudgetEnv {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	scfg := &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: sqlitetest.DSN("kxacctbudget_")},
	}}
	st, err := appstorage.NewStorageFactory().CreateStorage(scfg)
	require.NoError(t, err)
	c := core.NewKeyorixCore(st)

	ctx := context.Background()
	_, err = c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "acct_budget", Email: "acct_budget@example.com", Password: acctBudgetPassword,
	})
	require.NoError(t, err)
	u, err := c.GetUserByEmail(ctx, "acct_budget@example.com")
	require.NoError(t, err)
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "acct_budget", Password: acctBudgetPassword})
	require.NoError(t, err)

	cfg := &config.Config{}
	cfg.Server.HTTP = config.ServerInstanceConfig{Enabled: true, Port: "8080"}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	return &acctBudgetEnv{router: router, c: c, st: st, token: sess.SessionToken, userID: u.ID}
}

func (e *acctBudgetEnv) call(t *testing.T, remoteAddr, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

// passwordUnchanged fails if the stored hash no longer matches the original password.
func (e *acctBudgetEnv) passwordUnchanged(t *testing.T) {
	t.Helper()
	u, err := e.c.GetUserByEmail(context.Background(), "acct_budget@example.com")
	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(acctBudgetPassword)),
		"a refused request must not change the password")
}

// failedCredentialAudits counts the auth.login_failed rows written for the user,
// checking each carries success=false and the caller's IP.
func (e *acctBudgetEnv) failedCredentialAudits(t *testing.T) int {
	t.Helper()
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	action := "auth.login_failed"
	rows, _, err := e.st.GetAuditLogs(context.Background(), &corestorage.AuditFilter{Action: &action, UserID: &e.userID})
	require.NoError(t, err)
	for _, r := range rows {
		require.NotNil(t, r.Success, "auth.login_failed row %d has no success flag", r.ID)
		assert.False(t, *r.Success, "a failure audit must carry success=false")
		assert.Equal(t, "192.0.2.77", r.IPAddress)
	}
	return len(rows)
}

func TestChangePassword_CurrentPasswordBudgetThroughRouter(t *testing.T) {
	e := newAcctBudgetEnv(t)
	const path = "/api/v1/auth/change-password"
	guess := map[string]string{"current_password": "wrong-guess", "new_password": acctBudgetNew}

	for i := range core.LoginMaxAttempts {
		w := e.call(t, acctBudgetIP, http.MethodPost, path, guess)
		require.Equal(t, http.StatusUnauthorized, w.Code, "guess %d: %s", i+1, w.Body.String())
	}

	// Budget spent: even the right password is refused before it is checked.
	w := e.call(t, acctBudgetIP, http.MethodPost, path,
		map[string]string{"current_password": acctBudgetPassword, "new_password": acctBudgetNew})
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	e.passwordUnchanged(t)

	assert.Equal(t, core.LoginMaxAttempts, e.failedCredentialAudits(t),
		"every wrong current password is one auth.login_failed, success=false")

	// The budget is per IP: another address still gets the ordinary wrong-password answer.
	w = e.call(t, acctBudgetOtherIP, http.MethodPost, path, guess)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}

func TestUpdateProfile_CurrentPasswordBudgetThroughRouter(t *testing.T) {
	e := newAcctBudgetEnv(t)
	const path = "/api/v1/auth/profile"
	guess := map[string]string{"email": "mallory@example.com", "current_password": "wrong-guess"}

	for i := range core.LoginMaxAttempts {
		w := e.call(t, acctBudgetIP, http.MethodPut, path, guess)
		require.Equal(t, http.StatusUnauthorized, w.Code, "guess %d: %s", i+1, w.Body.String())
	}

	w := e.call(t, acctBudgetIP, http.MethodPut, path,
		map[string]string{"email": "mallory@example.com", "current_password": acctBudgetPassword})
	require.Equal(t, http.StatusTooManyRequests, w.Code, w.Body.String())
	u, err := e.c.GetUserByEmail(context.Background(), "acct_budget@example.com")
	require.NoError(t, err, "the email must not have changed")
	assert.Equal(t, "acct_budget@example.com", u.Email)

	assert.Equal(t, core.LoginMaxAttempts, e.failedCredentialAudits(t))

	// No current_password means no guess: a display-name edit is never throttled.
	w = e.call(t, acctBudgetIP, http.MethodPut, path, map[string]string{"display_name": "Acct B."})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
