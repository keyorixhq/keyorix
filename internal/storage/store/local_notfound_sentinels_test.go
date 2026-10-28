// local_notfound_sentinels_test.go — every LocalStorage getter that maps
// gorm.ErrRecordNotFound returns its typed not-found sentinel (matched through
// one extra %w wrap, as a handler would see it), and a non-not-found driver
// error (missing table) does NOT match any of them. Classification is by
// errors.Is, never by message text: the text is translated.
package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestLocalStorage_NotFoundSentinels(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		models   []any
		sentinel error
		call     func(ls *LocalStorage) error
	}{
		{"notification channel", []any{&models.NotificationChannel{}}, storage.ErrNotificationChannelNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetNotificationChannel(ctx, 1); return err }},
		{"machine credential", []any{&models.MachineIdentityCredential{}}, storage.ErrMachineCredentialNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetMachineIdentityCredentialByID(ctx, 1); return err }},
		{"oidc binding", []any{&models.MachineIdentityOIDCBinding{}}, storage.ErrOIDCBindingNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetOIDCBindingByID(ctx, 1); return err }},
		{"connector binding", []any{&models.ConnectorProjectBinding{}}, storage.ErrConnectorBindingNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetConnectorProjectBinding(ctx, "c"); return err }},
		{"secret template by id", []any{&models.SecretTemplate{}}, storage.ErrSecretTemplateNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetSecretTemplate(ctx, 1); return err }},
		{"secret template by name", []any{&models.SecretTemplate{}}, storage.ErrSecretTemplateNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetSecretTemplateByName(ctx, "n"); return err }},
		{"share", []any{&models.ShareRecord{}}, storage.ErrShareNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetShareRecord(ctx, 1); return err }},
		{"share (lock)", []any{&models.ShareRecord{}}, storage.ErrShareNotFound,
			func(ls *LocalStorage) error { _, err := ls.LockShareRecordForUpdate(ctx, 1); return err }},
		{"sso login state", []any{&models.SSOLoginState{}}, storage.ErrSSOLoginStateNotFound,
			func(ls *LocalStorage) error { _, err := ls.ConsumeSSOLoginState(ctx, "s"); return err }},
		{"permission", []any{&models.Permission{}}, storage.ErrPermissionNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetPermission(ctx, 1); return err }},
		{"alert escalation", []any{&models.AlertEscalationPolicy{}}, storage.ErrAlertEscalationNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetAlertEscalationPolicy(ctx, 1); return err }},
		{"rotation policy", []any{&models.RotationPolicy{}}, storage.ErrRotationPolicyNotFound,
			func(ls *LocalStorage) error { _, err := ls.GetRotationPolicy(ctx, 1); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			err := c.call(newPartialSecretsDB(t, c.models...))
			require.Error(t, err)
			require.True(t, errors.Is(fmt.Errorf("handler: %w", err), c.sentinel),
				"definitive not-found must match %v through an extra wrap; got %v", c.sentinel, err)

			// A driver error (table missing) is not a not-found.
			derr := c.call(newBrokenDB(t))
			require.Error(t, derr)
			require.False(t, errors.Is(fmt.Errorf("handler: %w", derr), c.sentinel),
				"a non-not-found driver error must NOT match %v; got %v", c.sentinel, derr)
		})
	}
}
