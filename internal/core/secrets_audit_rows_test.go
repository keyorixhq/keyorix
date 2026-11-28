package core

// secrets_audit_rows_test.go — AUDIT-FAILCLOSED-SECRETS-1, the secrets rows of
// #4718: each change and its audit row commit together (withAuditedMutation), or,
// for an environment clone / copy, the operation's started row is on record before
// anything is copied. Red on main: every one of these committed first and wrote its
// row afterwards with the result discarded, so the outage leg found the change.
// SQLite always; PostgreSQL with KEYORIX_TEST_PG_DSN.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSecretsAuditRows_ChangeCommitsWithItsRowOrNothing(t *testing.T) {
	runOutageKinds(t, secretsRowKinds())
}

func secretsRowKinds() []outageKind {
	existing := func(w *outageWorld, tag string) (uint, string) {
		s := w.secret("rows-" + tag)
		return s.ID, s.Name
	}
	node := func(w *outageWorld, id uint) models.SecretNode {
		var s models.SecretNode
		require.NoError(w.t, w.db.Unscoped().First(&s, id).Error)
		return s
	}
	edges := func(w *outageWorld, id uint) int64 {
		var n int64
		require.NoError(w.t, w.db.Model(&models.SecretDependency{}).Where("dependent_secret_id = ?", id).Count(&n).Error)
		return n
	}
	// pair is a secret with a sibling it can depend on.
	pair := func(w *outageWorld, tag string) (uint, string) {
		s := w.secret("rows-" + tag)
		w.secret("rows-" + tag + "-dep")
		return s.ID, s.Name
	}
	depOf := func(w *outageWorld, name string) uint {
		var d models.SecretNode
		require.NoError(w.t, w.db.Where("name = ?", name+"-dep").First(&d).Error)
		return d.ID
	}
	// inOwnEnv is a secret alone in a fresh environment, plus an empty target
	// environment named after it.
	inOwnEnv := func(w *outageWorld, tag string) (uint, string) {
		src := w.env("rows-src-" + tag)
		w.env("rows-dst-" + tag)
		s, err := w.c.CreateSecret(w.ctx, &CreateSecretRequest{
			Name: "rows-" + tag, Value: []byte("v"), ProjectID: w.f.projectID, EnvironmentID: src,
			Type: "generic", CreatedBy: "admin", OwnerID: w.f.adminID,
		})
		require.NoError(w.t, err)
		return s.ID, s.Name
	}
	dstOf := func(w *outageWorld, name string) uint {
		var e models.Environment
		require.NoError(w.t, w.db.Where("name = ?", "rows-dst-"+name[len("rows-"):]).First(&e).Error)
		return e.ID
	}
	copied := func(w *outageWorld, _ uint, name string) bool {
		var n int64
		require.NoError(w.t, w.db.Model(&models.SecretNode{}).Where("name = ? AND environment_id = ?", name, dstOf(w, name)).Count(&n).Error)
		return n == 1
	}
	return []outageKind{
		{
			name: "auto-rotate-config", eventType: EventSecretAutoRotateConfig, prepare: existing, sentinel: ErrMutationAuditUnavailable,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				return id, w.c.SetSecretAutoRotate(context.Background(), id, AutoRotateSpec{Enabled: true}, w.f.adminID)
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return node(w, id).AutoRotate },
		},
		{
			name: "dependency-add", eventType: EventSecretDependencyAdded, prepare: pair, sentinel: ErrMutationAuditUnavailable,
			mutate: func(w *outageWorld, id uint, name string) (uint, error) {
				_, err := w.c.AddSecretDependency(context.Background(), ActorTypeUser, w.f.adminID, id, depOf(w, name), "", 0)
				return id, err
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return edges(w, id) == 1 },
		},
		{
			name: "dependency-remove", eventType: EventSecretDependencyRemoved, sentinel: ErrMutationAuditUnavailable,
			prepare: func(w *outageWorld, tag string) (uint, string) {
				id, name := pair(w, tag)
				_, err := w.c.AddSecretDependency(w.ctx, ActorTypeUser, w.f.adminID, id, depOf(w, name), "", 0)
				require.NoError(w.t, err)
				return id, name
			},
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				var e models.SecretDependency
				require.NoError(w.t, w.db.Where("dependent_secret_id = ?", id).First(&e).Error)
				return id, w.c.RemoveSecretDependency(context.Background(), ActorTypeUser, w.f.adminID, id, e.ID)
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return edges(w, id) == 0 },
		},
		{
			name: "retention-override", eventType: "secret.retention_override_set", prepare: existing, sentinel: ErrMutationAuditUnavailable,
			mutate: func(w *outageWorld, id uint, _ string) (uint, error) {
				return id, w.c.SetSecretRetentionOverride(context.Background(), w.f.adminID, id, 30)
			},
			committed: func(w *outageWorld, id uint, _ string) bool { return node(w, id).RetentionOverrideDays == 30 },
		},
		{
			name: "clone-environment", eventType: EventEnvironmentCloneStarted, prepare: inOwnEnv, sentinel: ErrMutationAuditUnavailable, projectLevel: true,
			mutate: func(w *outageWorld, id uint, name string) (uint, error) {
				_, err := w.c.CloneEnvironment(context.Background(), w.f.projectID, node(w, id).EnvironmentID, dstOf(w, name), "admin", w.f.adminID)
				return 0, err
			},
			committed: copied,
		},
		{
			name: "copy-environment", eventType: EventEnvironmentSecretsCopyStarted, prepare: inOwnEnv, sentinel: ErrMutationAuditUnavailable, projectLevel: true,
			mutate: func(w *outageWorld, id uint, name string) (uint, error) {
				_, _, err := w.c.CopyEnvironmentSecrets(context.Background(), w.f.projectID, node(w, id).EnvironmentID, dstOf(w, name), "admin", w.f.adminID, "198.51.100.9", "rows-test")
				return 0, err
			},
			committed: copied,
		},
	}
}
