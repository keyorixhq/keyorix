// sso_login_session_failed_test.go — #2839 item 1 tail (SAML-TAILS-1 item 2):
// the SAML ACS JIT-provisions an account, reconciles its groups and roles, and
// THEN fails to create the session. Real SQLite under faultstorage, so the state
// the failed login leaves is read back from the database.
//
// Decision, made with these tests: the left-behind account is an acceptable,
// retriable state, not a reason to put provisioning and the session insert in
// one transaction. That is Andrei's class-C decision on #2839 item 1
// (docs/atomicity-exempt.tsv, JIT:(*KeyorixCore).CompleteSAML), and the second
// test below is the property it rests on: a second ACS for the same identity
// reuses the account (no duplicate user) and converges its grants on exactly
// what a clean first login gives (no extra role, no duplicate membership).
// What was missing is the record: before the fix nothing in the audit trail
// said the login failed after those writes (auth.sso_jit_provisioned alone
// reads like a provision followed by a login that simply never came).
package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// ssoLoginSessionFailedEvent is EventSSOLoginSessionFailed's wire value, spelled
// out so the red run against the pre-fix tree is a behavioural failure, not a
// compile error.
const ssoLoginSessionFailedEvent = "auth.sso_login_session_failed"

const (
	jitMintSubject = "corp|jit-mint"
	jitMintEmail   = "jit-mint@x.io"
	jitMintIP      = "198.51.100.23"
)

type jitMintWorld struct {
	t     *testing.T
	c     *KeyorixCore
	db    *gorm.DB
	fs    *faultstorage.FaultyStorage
	login int
}

// newJITMintWorld is a JIT-provisioning SAML provider with group sync and a
// mapped role: one login creates the account with its default role, adds the
// "engineers" membership and grants the mapped role.
func newJITMintWorld(t *testing.T) *jitMintWorld {
	t.Helper()
	db := sqlitetest.OpenWithConfig(t, "jitmintfail_", &gorm.Config{})
	require.NoError(t, db.AutoMigrate(models.AllTestModels()...))
	for _, r := range []models.Role{
		{ID: 1, Name: "system_viewer", NameFolded: "system_viewer", AssignableScope: models.RoleAssignableAny},
		{ID: 2, Name: "eng", NameFolded: "eng", AssignableScope: models.RoleAssignableAny},
	} {
		require.NoError(t, db.Create(&r).Error)
	}
	require.NoError(t, db.Create(&models.Group{ID: 10, Name: "engineers", NameFolded: "engineers"}).Error)
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(db), nil)
	p := &SSOProvider{
		Name: "corp", Type: "saml",
		SAML:          &stubSAML{info: &ports.SAMLAssertion{Subject: jitMintSubject, Email: jitMintEmail, Name: "Jit", Groups: []string{"engineers"}, GroupsPresent: true}},
		AutoProvision: true, TrustAssertedEmail: true, DefaultRole: "system_viewer",
		GroupSync: true, GroupRoleMap: map[string]string{"engineers": "eng"},
	}
	c := &KeyorixCore{storage: fs, now: time.Now, ssoProviders: map[string]*SSOProvider{"corp": p}}
	return &jitMintWorld{t: t, c: c, db: db, fs: fs}
}

// acs runs one ACS with a fresh RelayState, the way a user retrying from the
// IdP does: the old one was consumed by the failed attempt.
func (w *jitMintWorld) acs() (*models.Session, error) {
	w.t.Helper()
	w.login++
	relay := fmt.Sprintf("relay-%d", w.login)
	require.NoError(w.t, w.db.Create(&models.SSOLoginState{
		State: relay, Nonce: "req-1", Provider: "corp", ReturnTo: "/home",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}).Error)
	req := httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil)
	session, _, _, err := w.c.CompleteSAML(context.Background(), "corp", req, relay, "ua", jitMintIP)
	return session, err
}

func (w *jitMintWorld) users() []models.User {
	var us []models.User
	require.NoError(w.t, w.db.Where("external_id = ?", ssoExternalID("corp", jitMintSubject)).Find(&us).Error)
	return us
}

// grants is the account's state as sorted, comparable rows: every role
// assignment (role id and scope) and every group membership.
func (w *jitMintWorld) grants(userID uint) []string {
	var out []string
	var urs []models.UserRole
	require.NoError(w.t, w.db.Where("user_id = ?", userID).Find(&urs).Error)
	for _, ur := range urs {
		out = append(out, fmt.Sprintf("role %d project=%d env=%d", ur.RoleID, ur.ProjectID, ur.EnvironmentID))
	}
	var ugs []models.UserGroup
	require.NoError(w.t, w.db.Where("user_id = ?", userID).Find(&ugs).Error)
	for _, ug := range ugs {
		out = append(out, fmt.Sprintf("group %d", ug.GroupID))
	}
	sort.Strings(out)
	return out
}

func (w *jitMintWorld) events(eventType string) []models.AuditEvent {
	var evs []models.AuditEvent
	require.NoError(w.t, w.db.Where("event_type = ?", eventType).Find(&evs).Error)
	return evs
}

func (w *jitMintWorld) sessions() int64 {
	var n int64
	require.NoError(w.t, w.db.Model(&models.Session{}).Count(&n).Error)
	return n
}

func (w *jitMintWorld) failSessionInsert() {
	w.fs.Arm(&faultstorage.FaultSpec{
		Method: "CreateSession", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: session insert failed"),
	})
}

// A session insert that fails after JIT provisioning refuses the login with no
// session, keeps the provisioned account (class C, by decision), and records
// the failure as its own failed audit event naming the account and the client.
//
// RED on main: no auth.sso_login_session_failed event (nothing said the login
// failed after the account was created).
func TestCompleteSAML_SessionInsertFailsAfterJIT_RefusedKeptAndAudited(t *testing.T) {
	w := newJITMintWorld(t)
	w.failSessionInsert()

	session, err := w.acs()

	require.True(t, w.fs.Fired(), "the armed CreateSession fault must have fired, or this test proves nothing")
	require.Error(t, err)
	assert.Nil(t, session)
	assert.Zero(t, w.sessions(), "a refused login leaves no session row")
	assert.Empty(t, w.events(EventSSOLogin), "no login event for a refused login")

	us := w.users()
	require.Len(t, us, 1, "class C: the JIT account is kept, not rolled back")
	assert.NotEmpty(t, w.events(EventSSOJITProvision), "condition 3: the JIT provision is audited even though the login failed")

	failed := w.events(ssoLoginSessionFailedEvent)
	require.Len(t, failed, 1, "exactly one record that the login failed after provisioning")
	ev := failed[0]
	require.NotNil(t, ev.Success)
	assert.False(t, *ev.Success, "the event records a failure")
	require.NotNil(t, ev.UserID)
	assert.Equal(t, us[0].ID, *ev.UserID, "the event names the account the failed login left behind")
	assert.Equal(t, jitMintIP, ev.IPAddress, "the event names the client, like auth.sso_login")
	assert.NotContains(t, ev.Description, "injected", "the storage error goes to the log, not the audit trail")
}

// The retry property the class-C decision rests on: after a failed first
// attempt, a second ACS for the same identity logs in, reuses the account and
// leaves exactly the grants a clean first login gives. Compared against a
// fault-free world rather than a hand-written list, so a new grant step on
// either path is covered without editing this test.
func TestCompleteSAML_RetryAfterSessionInsertFailure_ConvergesOnCleanLogin(t *testing.T) {
	clean := newJITMintWorld(t)
	_, err := clean.acs()
	require.NoError(t, err, "calibration: the fault-free login succeeds")
	cleanUsers := clean.users()
	require.Len(t, cleanUsers, 1)
	want := clean.grants(cleanUsers[0].ID)
	require.Contains(t, want, "group 10", "calibration: the clean login applied the membership")
	require.Contains(t, want, "role 2 project=0 env=0", "calibration: the clean login granted the mapped role")

	w := newJITMintWorld(t)
	w.failSessionInsert()
	_, err = w.acs()
	require.Error(t, err)
	require.True(t, w.fs.Fired())
	w.fs.Arm(nil)

	session, err := w.acs()

	require.NoError(t, err, "the retry logs in")
	require.NotNil(t, session)
	us := w.users()
	require.Len(t, us, 1, "the retry reuses the account the failed attempt provisioned, it does not create a second one")
	assert.Equal(t, want, w.grants(us[0].ID), "the retry converges on exactly the clean login's grants: no extra or duplicate role or membership")
	assert.Len(t, w.events(EventSSOJITProvision), 1, "provisioned once, across both attempts")
	assert.Len(t, w.events(ssoLoginSessionFailedEvent), 1, "only the failed attempt is recorded as failed")
	assert.Len(t, w.events(EventSSOLogin), 1, "the retry is the one successful login")
	assert.EqualValues(t, 1, w.sessions())
}

// The OIDC callback shares the post-provisioning mint step (CompleteSSO) and
// records the same event.
func TestCompleteSSO_SessionInsertFailure_Audited(t *testing.T) {
	f := newOIDCReconcileFixture(t, nil, nil)
	fs := faultstorage.NewFaultyStorage(f.c.storage, &faultstorage.FaultSpec{
		Method: "CreateSession", NthCall: 1, Kind: faultstorage.KindError,
		Err: errors.New("injected: session insert failed"),
	})
	f.c.storage = fs

	session, err := f.login()

	require.True(t, fs.Fired())
	require.Error(t, err)
	assert.Nil(t, session)
	failed := f.events(ssoLoginSessionFailedEvent)
	require.Len(t, failed, 1)
	require.NotNil(t, failed[0].UserID)
	assert.Equal(t, samlReconcileUserID, *failed[0].UserID)
	assert.Equal(t, "1.2.3.4", failed[0].IPAddress)
}
