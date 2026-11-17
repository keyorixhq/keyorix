package store

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// AUDIT-SEARCH-PARITY-1 item 2: the other exact-match string filters of
// GetAuditLogs (Action, Actions, IPAddress, RequestID, ActorType) compare with
// "=" / IN. SQLite compares text byte-wise (BINARY) and PostgreSQL compares a
// deterministic collation byte-for-byte for equality, so all of them are
// case-sensitive on both backends and need no fix. Pinned so a future switch to
// LIKE, or a NOCASE column on one backend, is caught. The tables and stores are
// shared with local_audit_filter_case_parity_test.go.
func runAuditExactFilterParity(t *testing.T, ls *LocalStorage) {
	t.Helper()
	seedAuditParityRows(t, ls)
	str := func(s string) *string { return &s }

	for _, c := range []struct {
		name string
		f    storage.AuditFilter
		want []string
	}{
		{"action exact", storage.AuditFilter{Action: str("secret.read")}, []string{"secret.read"}},
		{"action other case", storage.AuditFilter{Action: str("SECRET.READ")}, nil},
		{"actions exact", storage.AuditFilter{Actions: []string{"user.login", "secretx.read"}}, []string{"secretx.read", "user.login"}},
		{"actions other case", storage.AuditFilter{Actions: []string{"User.Login"}}, nil},
		{"ip exact", storage.AuditFilter{IPAddress: str("10.0.0.A")}, []string{"secret.read"}},
		{"ip other case", storage.AuditFilter{IPAddress: str("10.0.0.a")}, nil},
		{"request id exact", storage.AuditFilter{RequestID: str("Req-ABC")}, []string{"secret.read"}},
		{"request id other case", storage.AuditFilter{RequestID: str("req-abc")}, nil},
		{"actor type exact", storage.AuditFilter{ActorType: str("admin_cli")}, []string{"secretx.read"}},
		{"actor type other case", storage.AuditFilter{ActorType: str("ADMIN_CLI")}, nil},
	} {
		assert.Equal(t, c.want, auditParityEventTypes(t, ls, c.f), c.name)
	}
}

func TestAuditExactFilterCaseParity_SQLite(t *testing.T) {
	runAuditExactFilterParity(t, newAuditParitySQLiteStore(t))
}

func TestAuditExactFilterCaseParity_Postgres(t *testing.T) {
	runAuditExactFilterParity(t, newAuditParityPGStore(t))
}
