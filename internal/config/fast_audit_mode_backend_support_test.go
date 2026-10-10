// fast_audit_mode_backend_support_test.go — ADR-112 Amendment 1's two
// backend decisions (Andrei, 2026-10-05):
//
//  1. PostgreSQL ONLY. A SQLite backend with
//     storage.database.insecure_audit_skip_durable_sync set REFUSES TO START,
//     with a named error. No silent ignore.
//  2. On a `remote` backend the setting is reported as CONFIGURED BUT NOT IN
//     EFFECT, with the reason carried as a structured field rather than only
//     as log text.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeFastAuditConfig writes a minimal, otherwise-valid config for the given
// storage type, with the fast audit mode either present or absent — so the two
// arms of every case below differ by exactly one YAML line.
func writeFastAuditConfig(t *testing.T, storageType string, setFastAudit bool) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("storage:\n  type: " + storageType + "\n  database:\n")
	switch storageType {
	case "local", "sqlite":
		b.WriteString("    path: ./secrets.db\n")
	case "postgres", "postgresql":
		b.WriteString("    host: db\n    name: keyorix\n    user: keyorix\n")
	}
	if setFastAudit {
		b.WriteString("    insecure_audit_skip_durable_sync: true\n")
	}
	b.WriteString("  encryption:\n    enabled: false\n")
	b.WriteString("server:\n  http:\n    enabled: false\n  grpc:\n    enabled: false\n")
	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

// TestConfigValidate_RejectsFastAuditModeOnSQLite is decision 1's gate: the
// combination must fail CONFIG VALIDATION, which is what makes it a start-up
// refusal for every entry point (server boot, every `admin` command) rather
// than something each caller has to remember to check.
//
// Both directions. Without the setting the same SQLite config must validate
// cleanly — otherwise this would be a check that always fails, which teaches
// people to ignore it (CLAUDE.md).
func TestConfigValidate_RejectsFastAuditModeOnSQLite(t *testing.T) {
	for _, storageType := range []string{"local", "sqlite"} {
		t.Run(storageType+": set, must refuse", func(t *testing.T) {
			cfg, err := Load(writeFastAuditConfig(t, storageType, true))
			require.NoError(t, err, "Load itself must still succeed -- the refusal belongs to Validate")

			err = cfg.Validate()
			require.Error(t, err,
				"storage.type %q with insecure_audit_skip_durable_sync set MUST refuse to start. Silently "+
					"ignoring it is what Andrei's decision explicitly rules out: an operator who wrote the "+
					"line believes their reads are fast and their durability relaxed, and on SQLite neither "+
					"is true.", storageType)
			require.Equal(t, auditSkipDurableSyncSQLiteUnsupportedError, err.Error(),
				"the refusal must use the exact reviewed wording, so an operator can search for it and so "+
					"this test and Validate cannot drift apart")
			// The message has to tell them what to DO, not just that it is wrong.
			require.Contains(t, err.Error(), "remove it or switch storage to postgres")
		})

		t.Run(storageType+": absent, must validate", func(t *testing.T) {
			cfg, err := Load(writeFastAuditConfig(t, storageType, false))
			require.NoError(t, err)
			require.NoError(t, cfg.Validate(),
				"a SQLite config WITHOUT the setting must validate cleanly -- if this fails, the new check "+
					"is rejecting every SQLite install rather than the one combination it is aimed at")
		})
	}
}

// TestConfigValidate_AllowsFastAuditModeOnPostgres is the other half: the
// supported backend keeps working. Without it, a mutation that rejected the
// setting unconditionally would leave the SQLite test above green.
func TestConfigValidate_AllowsFastAuditModeOnPostgres(t *testing.T) {
	for _, storageType := range []string{"postgres", "postgresql"} {
		t.Run(storageType, func(t *testing.T) {
			cfg, err := Load(writeFastAuditConfig(t, storageType, true))
			require.NoError(t, err)
			require.NoError(t, cfg.Validate(),
				"storage.type %q is the ONE backend that supports the fast audit mode; rejecting it would "+
					"make the feature unreachable", storageType)
			require.True(t, cfg.Storage.Database.InsecureAuditSkipDurableSync)
		})
	}
}

// TestAuditDurableSyncStatus covers the computed status every surface reads —
// the single source of truth for "is this actually doing anything, and if not,
// why not".
//
// The not-configured case asserts an entirely zero struct, which is what makes
// "NotInEffectReason is non-empty ONLY when configured and not in effect"
// checkable rather than just documented: a consumer can treat a non-empty
// reason as unambiguous.
func TestAuditDurableSyncStatus(t *testing.T) {
	t.Run("not configured: zero status on every backend", func(t *testing.T) {
		for _, storageType := range []string{"postgres", "postgresql", "local", "sqlite", "remote", ""} {
			d := &DatabaseConfig{}
			st := d.AuditDurableSyncStatus(storageType)
			require.False(t, st.Configured, "storageType=%q", storageType)
			require.False(t, st.InEffect, "storageType=%q", storageType)
			require.Empty(t, st.NotInEffectReason,
				"a setting that was never configured must carry NO reason -- a non-empty reason has to mean "+
					"exactly one thing: you wrote this and it is doing nothing (storageType=%q)", storageType)
		}
	})

	t.Run("postgres: in effect, no reason", func(t *testing.T) {
		for _, storageType := range []string{"postgres", "postgresql"} {
			d := &DatabaseConfig{InsecureAuditSkipDurableSync: true}
			st := d.AuditDurableSyncStatus(storageType)
			require.True(t, st.Configured)
			require.True(t, st.InEffect, "storageType=%q must be in effect -- it is the supported backend", storageType)
			require.Empty(t, st.NotInEffectReason,
				"an IN EFFECT setting must carry no not-in-effect reason, or the field stops being a reliable "+
					"signal of the ignored state")
		}
	})

	t.Run("remote: configured, NOT in effect, with the reason", func(t *testing.T) {
		d := &DatabaseConfig{InsecureAuditSkipDurableSync: true}
		st := d.AuditDurableSyncStatus("remote")
		require.True(t, st.Configured, "the operator did write the key; that fact must not be lost")
		require.False(t, st.InEffect,
			"storage.type: remote has no local database whose commit durability could be relaxed, so the "+
				"setting is not in effect (Andrei's decision, 2026-10-05: show it as OFF)")
		require.Equal(t, auditSkipDurableSyncRemoteNotInEffectReason, st.NotInEffectReason)
		require.Contains(t, st.NotInEffectReason, "storage.type is remote",
			"the reason has to name WHY, in operator-facing words, not just assert that it is off")
		require.Contains(t, st.NotInEffectReason, "only applies to a local database")
	})

	t.Run("sqlite: not in effect, with the unsupported reason", func(t *testing.T) {
		// Unreachable with a validated config (Validate refuses it), but the
		// answer still has to be the SAFE one rather than a claim that SQLite
		// durability was relaxed -- which would be false, since the SQLite
		// NORMAL path was removed outright.
		for _, storageType := range []string{"local", "sqlite"} {
			d := &DatabaseConfig{InsecureAuditSkipDurableSync: true}
			st := d.AuditDurableSyncStatus(storageType)
			require.True(t, st.Configured)
			require.False(t, st.InEffect,
				"storageType=%q must never report in-effect: there is no SQLite implementation of the mode "+
					"at all any more", storageType)
			require.Equal(t, auditSkipDurableSyncSQLiteUnsupportedError, st.NotInEffectReason)
		}
	})

	t.Run("unknown backend: not in effect, allowlist not denylist", func(t *testing.T) {
		// A backend nobody taught this function about must come out NOT in
		// effect. The alternative (a default that returns in-effect) would
		// have a future backend silently claim weakened durability it never
		// implemented.
		for _, storageType := range []string{"", "mysql", "postgress"} {
			d := &DatabaseConfig{InsecureAuditSkipDurableSync: true}
			st := d.AuditDurableSyncStatus(storageType)
			require.False(t, st.InEffect,
				"storageType=%q must not report in-effect: only postgres/postgresql implement the mechanism, "+
					"and this switch is an allowlist for exactly that reason", storageType)
			require.NotEmpty(t, st.NotInEffectReason, "storageType=%q", storageType)
		}
	})
}
