// identity_name_validation_test.go: IDENTITY-FOLD-SPACE-WIDTH (Andrei's
// answer (b) to ask identity-fold-space-width). identity.NewFoldedName does
// not fold space or width variants onto ASCII, so "admin" and "ａｄｍｉｎ",
// "ad min" and "ad\u00a0min", "admin" and "admin " were all accepted as
// DIFFERENT principals. Instead of re-keying every stored *_folded column, core
// now validates usernames and role names where they are chosen (create and
// rename), never where they are looked up (login, session/token validation,
// GetUserByUsername, GetRoleByName). These tests cover each creation path, the
// IdP-sourced paths that must normalize rather than reject, and an account and
// a role stored before the rule that must keep working.
package core

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// spoofedNames are the variants the finding demonstrated, plus the
// whitespace-only and repeated-space shapes validateIdentifier already rejects
// for projects.
var spoofedNames = map[string]string{
	"fullwidth":          "ａｄｍｉｎ",
	"no-break space":     "ad\u00a0min",
	"ideographic space":  "ad\u3000min",
	"trailing space":     "admin ",
	"leading space":      " admin",
	"repeated space":     "ad  min",
	"whitespace only":    "   ",
	"tab":                "ad\tmin",
	"zero-width joiner":  "ad\u200dmin",
	"cyrillic homograph": "аdmin", // U+0430
	"latin-1 letter":     "jürgen",
}

const legacyTestPassword = "Zq8!vT3#mW9$pL2&xR6"

// Names stored before the rule that fail it (fullwidth letters plus edge
// whitespace): TestValidateUsernameCharset and TestValidateIdentifier_LegacyRoleName
// pin that premise.
const (
	legacyStoredUsername = "ｌｅｇａｃｙ user "
	legacyStoredRoleName = " ｏｐｓ team"
)

// assertUsernameRuleError pins that err is the username rule's refusal, not an
// unrelated validation failure (password policy, length) that would make a
// "rejected" assertion pass vacuously.
func assertUsernameRuleError(t *testing.T, err error, msg string) {
	t.Helper()
	s := err.Error()
	assert.True(t, strings.Contains(s, "username must contain only ASCII") || strings.Contains(s, "leading, trailing, or repeated internal whitespace"),
		"%s: want the username rule's error, got %q", msg, s)
}

func adminID(t *testing.T, st *store.LocalStorage) uint {
	t.Helper()
	admin, err := st.GetUserByUsername(context.Background(), "admin")
	require.NoError(t, err)
	return admin.ID
}

// Admin create (REST classic + assignments, gRPC, setup-link and one-time-password
// variants) all reach buildUserForCreate -> validateCreateUserRequest.
func TestCreateUserPaths_RejectSpoofedUsernames(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	actor := adminID(t, st)

	creators := map[string]func(req *CreateUserRequest) error{
		"CreateUser": func(req *CreateUserRequest) error { _, err := c.CreateUser(ctx, req); return err },
		"CreateUserAudited": func(req *CreateUserRequest) error {
			_, err := c.CreateUserAudited(ctx, req, actor)
			return err
		},
		"CreateUserWithAssignments": func(req *CreateUserRequest) error {
			_, err := c.CreateUserWithAssignments(ctx, req, "", nil, actor, false)
			return err
		},
		"CreateUserWithOneTimePassword": func(req *CreateUserRequest) error {
			_, _, err := c.CreateUserWithOneTimePassword(ctx, req, actor)
			return err
		},
	}
	for path, create := range creators {
		for label, name := range spoofedNames {
			if len(name) < usernameMinLen {
				continue // the length rule answers first; covered by its own tests
			}
			err := create(&CreateUserRequest{Username: name, Email: "x@example.com", Password: legacyTestPassword})
			require.Error(t, err, "%s accepted %s username %q", path, label, name)
			assertUsernameRuleError(t, err, path+" "+label)
		}
	}
	_, err := st.GetUserByEmail(ctx, "x@example.com")
	require.Error(t, err, "no spoofed account may have been written")

	// Control: the ASCII punctuation usernames carry today still creates.
	for i, name := range []string{"john.developer", "user@example.com", "Ada Lovelace"} {
		_, err := c.CreateUser(ctx, &CreateUserRequest{Username: name, Email: []string{"j@example.com", "u@example.com", "a@example.com"}[i], Password: legacyTestPassword})
		require.NoError(t, err, name)
	}
}

// BootstrapSystem builds the first admin through buildUserForCreate too.
func TestBootstrapSystem_RejectsSpoofedAdminUsername(t *testing.T) {
	t.Parallel()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, kxstorage.MigrateExisting(db))
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin ", Email: "admin@example.com", Password: "BootstrapPass123!", Token: "test-bootstrap-token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "whitespace")
	_, n, err := st.ListUsers(context.Background(), &storage.UserFilter{Page: 1, PageSize: 1})
	require.NoError(t, err)
	assert.Zero(t, n, "a refused bootstrap writes no admin")
}

// UpdateUser is the only rename path (REST PATCH, gRPC UpdateUser, CLI user update).
func TestUpdateUser_RenameRejectsSpoofedUsernames(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	actor := adminID(t, st)
	u, err := c.CreateUser(ctx, &CreateUserRequest{Username: "bob", Email: "bob@example.com", Password: legacyTestPassword})
	require.NoError(t, err)

	for label, name := range spoofedNames {
		if len(name) < usernameMinLen {
			continue
		}
		_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: actor, Username: name})
		require.Error(t, err, "rename to %s %q accepted", label, name)
		assertUsernameRuleError(t, err, label)
	}
	got, err := st.GetUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "bob", got.Username)

	_, err = c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: actor, Username: "bob.smith"})
	require.NoError(t, err, "control: a valid rename still applies")
}

// An account stored before the rule (or written by any path that predates it)
// with a name the rule rejects: login, session validation, lookup and an update
// that echoes the stored name back all keep working; only renaming it to
// another failing name is refused, and renaming it to a valid name is allowed.
func TestLegacyStoredUsernameFailingRule_KeepsWorking(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	actor := adminID(t, st)

	u, err := c.CreateUser(ctx, &CreateUserRequest{Username: "legacyseed", Email: "legacy@example.com", Password: legacyTestPassword})
	require.NoError(t, err)
	const legacy = legacyStoredUsername
	folded, err := identity.NewFoldedName(legacy)
	require.NoError(t, err)
	u.Username, u.UsernameFolded = legacy, folded.Folded()
	_, err = st.UpdateUser(ctx, u)
	require.NoError(t, err)

	byName, err := c.storage.GetUserByUsername(ctx, legacy)
	require.NoError(t, err, "lookup")
	assert.Equal(t, u.ID, byName.ID)

	sess, user, err := c.Login(ctx, &LoginRequest{Username: legacy, Password: legacyTestPassword, UserAgent: "ua", IPAddress: "127.0.0.1"})
	require.NoError(t, err, "login")
	assert.Equal(t, u.ID, user.ID)
	vu, _, err := c.ValidateSessionToken(ctx, sess.SessionToken)
	require.NoError(t, err, "session validation")
	assert.Equal(t, legacy, vu.Username)

	updated, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: actor, Username: legacy, DisplayName: "Legacy"})
	require.NoError(t, err, "an update echoing the unchanged stored name must not be refused")
	assert.Equal(t, legacy, updated.Username)
	assert.Equal(t, "Legacy", updated.DisplayName)

	_, err = c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: actor, Username: "ｌｅｇａｃｙ user"})
	require.Error(t, err, "renaming to another failing name is a rename and is checked")
	assertUsernameRuleError(t, err, "legacy rename")

	fixed, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: u.ID, ActorID: actor, Username: "legacy.user"})
	require.NoError(t, err, "renaming a legacy name to a valid one is allowed")
	assert.Equal(t, "legacy.user", fixed.Username)
}

// SCIM and SSO/SAML JIT take the username from IdP data. Non-ASCII, fullwidth
// and padded IdP values must NOT break provisioning: deriveSCIMUsername
// normalizes them to [a-z0-9], and the result always passes the rule.
var idpUserNames = []string{
	"jürgen.müller@example.com",
	"日本太郎@example.com",
	"ａｄｍｉｎ@example.com",
	" padded.user @example.com",
	"ad\u00a0min@example.com",
	"Ωmega@example.com",
	"x@example.com",
	"averyveryveryveryveryveryveryverylonglocalpartthatexceedsfifty@example.com",
}

// derivedUsernameShape is what deriveSCIMUsername/deriveUsername produce: a
// strict subset of the username rule's charset with no whitespace at all.
var derivedUsernameShape = regexp.MustCompile(`^[a-z0-9]{3,50}$`)

func TestIdPDerivedUsernames_PassUsernameRule(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	for _, in := range idpUserNames {
		name, err := c.deriveSCIMUsername(ctx, in)
		require.NoError(t, err, in)
		require.NoError(t, validateUsernameFormat(name), "%q -> %q", in, name)
		require.Regexp(t, derivedUsernameShape, name, in)
	}
}

func TestProvisionSCIMUser_NonASCIIUserNameProvisions(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	for i, in := range idpUserNames {
		u, err := c.ProvisionSCIMUser(ctx, 0, in, "", "", "ext-"+string(rune('a'+i)), true)
		require.NoError(t, err, "SCIM provisioning must not break on %q", in)
		require.Regexp(t, derivedUsernameShape, u.Username, in)
	}
}

func TestProvisionSSOUser_NonASCIIEmailProvisions(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	p := &SSOProvider{Name: "corp", AutoProvision: true}
	for i, email := range idpUserNames {
		u, err := c.provisionSSOUser(ctx, p, "sub-"+string(rune('a'+i)), email, true, "Ünïcødé Näme")
		require.NoError(t, err, "SSO/SAML JIT must not break on %q", email)
		require.Regexp(t, derivedUsernameShape, u.Username, email)
	}
}

// Invitation acceptance derives the username from the invited email
// (deriveUsername, [a-z0-9]) and creates it through CreateUser, so the rule
// applies and a non-ASCII invite email still yields a valid username.
func TestInviteDerivedUsernames_PassUsernameRule(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	for _, in := range idpUserNames[:6] {
		name, err := c.deriveUsername(ctx, in)
		require.NoError(t, err, in)
		require.Regexp(t, derivedUsernameShape, name, in)
	}
}

// CreateRole is the only caller-reachable role-name write (REST, gRPC,
// keyorix-migrate via REST). gRPC previously reached it with only a length check.
func TestCreateRole_RejectsSpoofedRoleNames(t *testing.T) {
	t.Parallel()
	c, _ := newRoleCRUDTestCore(t)
	ctx := context.Background()
	names := map[string]string{
		"fullwidth": "ｏｐｓ_team", "no-break space": "ops\u00a0team", "trailing space": "ops team ",
		"leading space": " ops team", "repeated space": "ops  team", "whitespace only": "     ", "dot": "ops.team",
	}
	for label, name := range names {
		_, _, err := c.CreateRole(ctx, 1, name, "d", nil)
		require.Error(t, err, "%s role name %q accepted", label, name)
		assert.True(t, errors.Is(err, ErrRoleValidation), "%s: must classify as a validation error (400/InvalidArgument)", label)
	}
	for _, ok := range []string{"ops team", "vault-migrated-read-write", "alert_operator2"} {
		_, _, err := c.CreateRole(ctx, 1, ok, "d", nil)
		require.NoError(t, err, ok)
	}
}

// A role stored before the rule with a failing name stays resolvable by name and
// updatable (role names are immutable; UpdateRole never re-validates the name).
func TestLegacyStoredRoleNameFailingRule_KeepsWorking(t *testing.T) {
	t.Parallel()
	c, _ := newRoleCRUDTestCore(t)
	ctx := context.Background()
	const legacy = legacyStoredRoleName
	folded, err := identity.NewFoldedName(legacy)
	require.NoError(t, err)
	r, err := c.storage.CreateRole(ctx, folded, "pre-rule")
	require.NoError(t, err)

	got, err := c.storage.GetRoleByName(ctx, legacy)
	require.NoError(t, err)
	assert.Equal(t, r.ID, got.ID)

	got.Description = "updated"
	updated, _, err := c.UpdateRole(ctx, 1, got, nil)
	require.NoError(t, err)
	assert.Equal(t, legacy, updated.Name)
	assert.Equal(t, "updated", updated.Description)
}
