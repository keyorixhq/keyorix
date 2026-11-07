package store

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListUsers{Search} (username OR email OR display_name) and the audit-log actor
// filter must be Unicode-case-insensitive and treat % _ \ literally, identically
// on SQLite and PostgreSQL, like the Username / Email filters in
// search_fold_consistency_test.go. The same tables run on SQLite always and on
// PostgreSQL when KEYORIX_TEST_PG_DSN is set.

type searchUser struct{ username, email, display string }

var searchUsers = []searchUser{
	{"alpha", "a1@example.com", "Ünal Kaya"},
	{"ünal", "u2@example.com", "Plain"},
	{"ÄÖ-user", "u3@example.com", "x"},
	{"zoë", "u4@example.com", "y"}, // stored decomposed
	{"under_score", "u5@example.com", "z"},
	{"underXscore", "u6@example.com", "z"},
	{"pct", "50%off@example.com", "z"},
	{"odos", "u8@example.com", "ΟΔΟΣ"},
	{"slash", "u9@example.com", `back\slash`},
}

var searchCases = []struct {
	name, query string
	want        []string // usernames
}{
	{"ascii case", "ALPHA", []string{"alpha"}},
	{"umlaut in username, other case", "ÜNAL", []string{"alpha", "ünal"}}, // alpha via display_name
	{"umlaut in display name", "kaya", []string{"alpha"}},
	{"umlaut upper finds umlaut", "äö", []string{"ÄÖ-user"}},
	{"composed finds stored decomposed", "zoë", []string{"zoë"}},
	{"email match", "U2@EXAMPLE", []string{"ünal"}},
	{"underscore is literal", "r_s", []string{"under_score"}},
	{"percent is literal", "%off", []string{"pct"}},
	{"backslash is literal", `\`, []string{"slash"}},
	{"greek final sigma", "οδος", []string{"odos"}},
	{"no match", "zzz", nil},
}

func runUserSearchFold(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	for _, u := range searchUsers {
		require.NoError(t, ls.db.Create(&models.User{
			Username: u.username, Email: u.email, DisplayName: u.display, PasswordHash: "x",
		}).Error)
	}
	for _, c := range searchCases {
		q := c.query
		got, _, err := ls.ListUsers(ctx, &storage.UserFilter{Search: &q, PageSize: 100})
		require.NoError(t, err, c.name)
		var names []string
		for _, u := range got {
			names = append(names, u.Username)
		}
		sort.Strings(names)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		assert.Equal(t, want, names, "%s (query %q)", c.name, c.query)
	}
	empty := ""
	got, _, err := ls.ListUsers(ctx, &storage.UserFilter{Search: &empty, PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, got, len(searchUsers), "empty search means no filter")
}

func TestListUsers_SearchUnicodeCase_SQLite(t *testing.T) {
	runUserSearchFold(t, newFoldSQLiteStore(t))
}

func TestListUsers_SearchUnicodeCase_Postgres(t *testing.T) {
	runUserSearchFold(t, newFoldPGStore(t))
}

func runAuditActorFold(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	users := map[string]*models.User{}
	for _, n := range []string{"Ünal", "ΟΔΟΣ", "zoë", "a_b", "aXb", "50%off"} {
		u := &models.User{Username: n, Email: n + "@example.com", PasswordHash: "x"}
		require.NoError(t, ls.db.Create(u).Error)
		users[n] = u
	}
	bot := &models.MachineIdentity{Name: "Büro-CI", State: "active", ProjectID: 1}
	require.NoError(t, ls.db.Create(bot).Error)

	ip := map[string]string{}
	i := 0
	add := func(label string, e *models.AuditEvent) {
		i++
		e.EventType, e.EventTime = "secret.read", now.Add(time.Duration(i)*time.Second)
		e.IPAddress = "10.0.0." + string(rune('0'+i))
		ip[e.IPAddress] = label
		require.NoError(t, ls.LogAuditEvent(ctx, e))
	}
	for n, u := range users {
		uid := u.ID
		add(n, &models.AuditEvent{ActorType: "user", UserID: &uid})
	}
	bid := bot.ID
	add("Büro-CI", &models.AuditEvent{ActorType: "machine_identity", MachineIdentityID: &bid})

	cases := []struct {
		name, query string
		want        []string
	}{
		{"umlaut lower finds upper", "ünal", []string{"Ünal"}},
		{"umlaut upper", "ÜNAL", []string{"Ünal"}},
		{"machine identity umlaut other case", "BÜRO", []string{"Büro-CI"}},
		{"greek final sigma", "οδος", []string{"ΟΔΟΣ"}},
		{"composed finds stored decomposed", "zoë", []string{"zoë"}},
		{"underscore is literal", "a_b", []string{"a_b"}},
		{"lone underscore is literal", "_", []string{"a_b"}},
		{"percent is literal", "%", []string{"50%off"}},
		{"no match", "zzz", nil},
	}
	for _, c := range cases {
		q := c.query
		events, _, err := ls.GetAuditLogs(ctx, &storage.AuditFilter{ActorUsername: &q, PageSize: 50})
		require.NoError(t, err, c.name)
		var got []string
		for _, e := range events {
			got = append(got, ip[e.IPAddress])
		}
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		assert.Equal(t, want, got, "%s (query %q)", c.name, c.query)
	}
}

func TestAuditActorFilter_UnicodeCase_SQLite(t *testing.T) {
	runAuditActorFold(t, newActorMachineSQLiteStore(t))
}

func TestAuditActorFilter_UnicodeCase_Postgres(t *testing.T) {
	runAuditActorFold(t, newActorMachinePGStore(t))
}

// runAuditAllFilters sets every AuditFilter predicate applyAuditFilter knows at
// once, with a folded actor term, as the /audit/search all-params request does
// (TestSearchAuditLogs_Handler_AllParams). Each decoy misses exactly one
// predicate, so only the target row may come back, on both backends.
func runAuditAllFilters(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	unal := &models.User{Username: "Ünal", Email: "unal@example.com", PasswordHash: "x"}
	other := &models.User{Username: "other", Email: "other@example.com", PasswordHash: "x"}
	require.NoError(t, ls.db.Create(unal).Error)
	require.NoError(t, ls.db.Create(other).Error)

	project, secret, yes := uint(2), uint(3), true
	// request_id is stamped only from the server-minted id in the context.
	log := func(reqID string, uid uint, ip string) {
		require.NoError(t, ls.LogAuditEvent(serverRequestCtx(reqID), &models.AuditEvent{
			EventType: "secret.read", EventTime: now, ActorType: "user", UserID: &uid,
			ProjectID: &project, SecretNodeID: &secret, IPAddress: ip, Success: &yes,
		}))
	}
	log("req-target", unal.ID, "10.0.0.1")
	log("req-target", other.ID, "10.0.0.1") // other actor
	log("req-target", unal.ID, "10.0.0.2")  // other IP
	log("req-decoy", unal.ID, "10.0.0.1")   // other request id

	actor, action, resource, actorType := "ünal", "secret.read", "secret", "user"
	ip, reqID := "10.0.0.1", "req-target"
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	after, upTo := uint(0), uint(1<<31)
	uid := unal.ID
	f := &storage.AuditFilter{
		ProjectID: &project, UserID: &uid, SecretID: &secret, Action: &action,
		Actions: []string{action}, StartTime: &start, EndTime: &end, Success: &yes,
		ActorType: &actorType, AfterID: &after, UpToID: &upTo, IPAddress: &ip,
		RequestID: &reqID, ActorUsername: &actor, ResourceType: &resource, PageSize: 50,
	}
	events, total, err := ls.GetAuditLogs(ctx, f)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.EqualValues(t, 1, total)
	assert.Equal(t, unal.ID, *events[0].UserID)
	assert.Equal(t, "10.0.0.1", events[0].IPAddress)
	assert.Equal(t, "req-target", *events[0].RequestID)
}

func TestAuditAllFilters_FoldedActor_SQLite(t *testing.T) {
	runAuditAllFilters(t, newActorMachineSQLiteStore(t))
}

func TestAuditAllFilters_FoldedActor_Postgres(t *testing.T) {
	runAuditAllFilters(t, newActorMachinePGStore(t))
}
