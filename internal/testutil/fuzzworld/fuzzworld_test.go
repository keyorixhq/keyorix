package fuzzworld

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// TestWorlds_CarryProductionSchema is the #1947 regression: fixture worlds
// must be bootstrapped through the production migration, so they carry the
// indexes/constraints a bare AutoMigrate never creates. Runs on SQLite
// always and on PostgreSQL too when KEYORIX_TEST_PG_DSN is set.
func TestWorlds_CarryProductionSchema(t *testing.T) {
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("i18n: %v", err)
	}
	defer i18n.ResetForTesting()

	for _, w := range Worlds(t, "fwtest", ":memory:", 1) {
		for tbl, idx := range map[string]string{
			"secret_versions": "uniq_secret_versions_node_version", // #121 backstop
			// Not uniq_users_email_active: production DROPS that legacy index in
			// favor of this NFC/case-folded one. The HTTP API fuzzer's
			// hand-copied index list still created the legacy one -- the very
			// drift #1947 is about.
			"users":               "uniq_users_email_folded_active",
			"project_memberships": "uniq_project_memberships_active",
		} {
			if !w.DB.Migrator().HasIndex(tbl, idx) {
				t.Errorf("[%s] %s.%s missing: world was not built from the production schema", w.Backend, tbl, idx)
			}
		}
		if err := w.Reset([]string{"secret_versions", "secret_nodes"}); err != nil {
			t.Errorf("[%s] reset: %v", w.Backend, err)
		}
	}
}
