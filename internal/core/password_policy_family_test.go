package core

// PASSWORD-POLICY-FAMILY-1: every core entrypoint that accepts a new password
// refuses a policy violation with the typed refusal (ErrPasswordPolicy), whose
// text is the policy's fixed wording. The transports map that type to 400 /
// InvalidArgument with the rule text; a plain string match on the error text
// (the old mapping) turned a refusal raised in one place into a blanket failure
// in another.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newBootstrappedCoreNoAdmin is newBootstrappedCore without the BootstrapSystem
// call: a migrated, empty install.
func newBootstrappedCoreNoAdmin(t *testing.T) (*KeyorixCore, *store.LocalStorage) {
	t.Helper()
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
	return NewKeyorixCore(st), st
}

func requirePolicyRefusal(t *testing.T, err error, rule string) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrPasswordPolicy)
	msg, ok := PolicyRefusalMessage(err)
	require.True(t, ok)
	assert.Contains(t, msg, rule)
}

func TestCreateUser_PolicyViolationIsTheTypedRefusal(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	_, err := c.CreateUser(context.Background(), &CreateUserRequest{
		Username: "carol", Email: "carol@example.com", DisplayName: "Carol",
		Password: "Carol-Str0ng-Passw0rd!x",
	})
	requirePolicyRefusal(t, err, "not contain your username, email, or display name")
}

func TestBootstrapSystem_PolicyViolationIsTheTypedRefusalAndKeepsTheToken(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCoreNoAdmin(t)
	c.SetBootstrapToken("tok")
	_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "rootadmin", Email: "rootadmin@example.com", Password: "Rootadmin-Str0ng-Pass!x", Token: "tok",
	})
	requirePolicyRefusal(t, err, "not contain your username, email, or display name")

	// Nothing was written and the token is still good: the operator retries with a
	// stronger password.
	_, err = c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "rootadmin", Email: "rootadmin@example.com", Password: strongPw, Token: "tok",
	})
	require.NoError(t, err)
}

// A wrong token never reaches the policy: the refusal is not a way to probe the
// policy without the credential.
func TestBootstrapSystem_WrongTokenIsNotAPolicyAnswer(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCoreNoAdmin(t)
	c.SetBootstrapToken("tok")
	_, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "rootadmin", Email: "rootadmin@example.com", Password: "weak", Token: "wrong",
	})
	require.ErrorIs(t, err, ErrInvalidBootstrapToken)
	assert.False(t, errors.Is(err, ErrPasswordPolicy))
}

// An invitee's own address is part of the policy context. Checked without it, the
// password passed the pre-create check and was refused inside CreateUser, which
// the handler answers as "this setup link could not be completed" (a dead link).
func TestCompleteSetup_InvitationAccept_PolicyViolationIsRefusedBeforeAnythingIsSpent(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const email = "invitee@example.com"
	const rawToken = setupPrefix + "policy-family-invite-1"

	proj, err := st.CreateProject(ctx, &models.Project{Name: "policy-family", Description: "d"})
	require.NoError(t, err)
	inviteAcceptFixture(t, c, st, proj.ID, 1, email, rawToken)

	for name, pw := range map[string]string{
		"embeds the email local part": "Invitee-Str0ng-Passw0rd!x",
		"too short":                   "Sh0rt!aB",
	} {
		_, err = c.CompleteSetup(ctx, rawToken, pw, "ua", "1.2.3.4")
		require.ErrorIs(t, err, ErrInvalidSetupPassword, name)
		requirePolicyRefusal(t, err, "password must")
	}

	// No account was created and the link was not spent: the same link works with a
	// good password.
	_, gerr := c.GetUserByEmail(ctx, email)
	require.Error(t, gerr, "a refused password must not leave an account behind")
	_, err = c.CompleteSetup(ctx, rawToken, strongPw, "ua", "1.2.3.4")
	require.NoError(t, err)
}
