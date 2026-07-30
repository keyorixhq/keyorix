// like_escape_integration_test.go — integration tests verifying that
// escapeLIKE prevents SQL wildcard injection in GetAuditLogs and ListSecrets
// (#r124-M LIKE injection).  These tests run against a real in-memory SQLite
// database so the LIKE predicate is actually evaluated by the SQL engine.
package store

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// likeEscapeDBSeq makes each in-memory DB unique within the process, even
// across repeated invocations of the same test (e.g. `go test -count=N`).
var likeEscapeDBSeq atomic.Int64

// TestGetAuditLogs_LIKEEscape_ActorUsername verifies that the escapeLIKE applied
// to actor_username filter prevents SQL wildcard injection: a search for
// "alice%admin" must NOT match a user whose name is "alice-admin" (#r124-M).
func TestGetAuditLogs_LIKEEscape_ActorUsername(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:kxlikeescape_actor_%d?mode=memory&cache=shared", likeEscapeDBSeq.Add(1))), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))

	// Seed two users with similar names: "alice-admin" and "alice_admin".
	alice := &models.User{Username: "alice-admin", Email: "a@ex.com", PasswordHash: "x"}
	require.NoError(t, db.Create(alice).Error)
	aliceUnderscore := &models.User{Username: "alice_admin", Email: "b@ex.com", PasswordHash: "x"}
	require.NoError(t, db.Create(aliceUnderscore).Error)

	tru := true
	// Seed audit events for each user.
	require.NoError(t, db.Create(&models.AuditEvent{
		UserID: &alice.ID, EventType: "secret.read", ActorType: "user",
		EventTime: time.Now(), Success: &tru,
	}).Error)
	require.NoError(t, db.Create(&models.AuditEvent{
		UserID: &aliceUnderscore.ID, EventType: "secret.read", ActorType: "user",
		EventTime: time.Now(), Success: &tru,
	}).Error)

	ls := NewLocalStorage(db)
	ctx := context.Background()

	// Search with literal "%" — without escapeLIKE, "alice%admin" as a LIKE
	// pattern would match any string starting with "alice" and ending with
	// "admin" (e.g. "alice-admin", "alice_admin").  With escapeLIKE the "%" is
	// escaped to "\%" and treated as a literal percent sign → no user has "%" in
	// their name → 0 results.
	pct := "alice%admin"
	events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{
		ActorUsername: &pct,
		PageSize:      100,
	})
	require.NoError(t, err)
	assert.Empty(t, events, "wildcard injection via ActorUsername must be neutralised by escapeLIKE")

	// A literal match for the exact username must still work.
	exact := "alice-admin"
	events2, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{
		ActorUsername: &exact,
		PageSize:      100,
	})
	require.NoError(t, err)
	assert.Len(t, events2, 1, "exact-match ActorUsername filter must return the right event")
}

// TestGetAuditLogs_LIKEEscape_ResourceType verifies that a resource_type filter
// containing SQL LIKE metacharacters is escaped so it matches only the intended
// resource prefix and not unrelated event types (#r124-M).
func TestGetAuditLogs_LIKEEscape_ResourceType(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:kxlikeescape_restype_%d?mode=memory&cache=shared", likeEscapeDBSeq.Add(1))), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))

	tru := true
	// Seed events for two different resource types.
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret.read", ActorType: "user", EventTime: time.Now(), Success: &tru,
	}).Error)
	require.NoError(t, db.Create(&models.AuditEvent{
		EventType: "secret_backup.read", ActorType: "user", EventTime: time.Now(), Success: &tru,
	}).Error)

	ls := NewLocalStorage(db)
	ctx := context.Background()

	// "secret_backup" with escapeLIKE → "secret\_backup" — the underscore is a
	// literal char and must NOT match "secret.read" (unescaped "_" would match
	// any single char including ".").  The pattern becomes "secret\_backup.%"
	// which only matches "secret_backup.*" event types.
	rt := "secret_backup"
	events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{
		ResourceType: &rt,
		PageSize:     100,
	})
	require.NoError(t, err)
	for _, e := range events {
		assert.Contains(t, e.EventType, "secret_backup",
			"only secret_backup events must match when underscore is escaped")
	}

	// "secret" (no underscore) should still match "secret.read" and NOT
	// "secret_backup.read" (because the LIKE pattern is "secret.%" — the dot is
	// a literal, which SQLite treats as such; only the prefix-bounded match
	// applies to the resource portion before the dot).
	rt2 := "secret"
	events2, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{
		ResourceType: &rt2,
		PageSize:     100,
	})
	require.NoError(t, err)
	for _, e := range events2 {
		assert.Equal(t, "secret.read", e.EventType,
			"resource_type=secret must match only secret.* not secret_backup.*")
	}
}

// TestGetAuditLogs_ClampPage verifies that a page number beyond maxStoragePage
// is silently clamped to maxStoragePage rather than generating an enormous OFFSET
// (#r124-M pagination DoS).
func TestGetAuditLogs_ClampPage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:kxlikeescape_clamppage_%d?mode=memory&cache=shared", likeEscapeDBSeq.Add(1))), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.User{}))

	ls := NewLocalStorage(db)
	ctx := context.Background()

	// Hostile page number: 2^30 — would produce an enormous OFFSET without clamping.
	events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{
		Page:     1 << 30,
		PageSize: 10,
	})
	require.NoError(t, err, "a hostile page number must be clamped, not error")
	assert.Empty(t, events, "no events seeded, empty result expected")
}

// TestListSecrets_LIKEEscape_Search verifies that the search filter LIKE
// parameter is escaped so a caller-supplied "%" or "_" in a search term does
// not expand unexpectedly (#r124-M LIKE injection in ListSecrets).
func TestListSecrets_LIKEEscape_Search(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:kxlikeescape_search_%d?mode=memory&cache=shared", likeEscapeDBSeq.Add(1))), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.Environment{}))

	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "api-key-prod",
		IsSecret: true, Type: "api_key", Status: "active",
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "api-key-staging",
		IsSecret: true, Type: "api_key", Status: "active",
	}).Error)

	ls := NewLocalStorage(db)
	ctx := context.Background()

	// A search for "api%key" without escapeLIKE would expand "%" to match any
	// substring, matching BOTH "api-key-prod" and "api-key-staging".  With
	// escapeLIKE the "%" is treated literally → no secret has "%" in its name
	// → 0 results.
	pct := "api%key"
	results, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{Search: &pct, Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Empty(t, results, "wildcard injection via Search must be neutralised by escapeLIKE")

	// An exact substring match must still work as expected.
	exact := "api-key"
	results2, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{Search: &exact, Page: 1, PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, results2, 2, "exact search prefix must return matching secrets")
}
