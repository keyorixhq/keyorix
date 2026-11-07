package store

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// Regression tests for the SQLite-vs-PostgreSQL search divergences found by the
// backend differential fuzz: ListSecrets{Search}, ListUsers{Username} and
// ListUsers{Email} must be case-insensitive in the Unicode sense, identically on
// both backends. The same table runs on SQLite always and on PostgreSQL when
// KEYORIX_TEST_PG_DSN is set.

type foldCase struct {
	name  string
	query string
	want  []string
}

func newFoldSQLiteStore(t *testing.T) *LocalStorage {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "searchfold_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SecretNode{}))
	return NewLocalStorage(db)
}

func newFoldPGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — PostgreSQL leg of the search-fold consistency test")
	}
	schema := "search_fold_consistency_test"
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SecretNode{}))
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return NewLocalStorage(db)
}

var foldSecretNames = []string{
	"ÄÖ-key",     // ÄÖ-key
	"straße",     // straße
	"ΟΔΟΣ",       // ΟΔΟΣ (capital sigma)
	"οδος-lower", // οδος-lower (final sigma)
	"İstanbul",   // İstanbul
	"prod_KEY",
	"prodXKEY",
	"100%done",
	"100xdone",
	`back\slash`,
	"A\u0308-nfd", // Ä-nfd stored decomposed (A + U+0308), not NFC
}

var foldSecretCases = []foldCase{
	{"umlaut lower finds upper", "äö", []string{"ÄÖ-key"}},
	{"umlaut upper finds upper", "ÄÖ", []string{"ÄÖ-key"}},
	{"decomposed input is NFC-normalized", "a\u0308ö", []string{"ÄÖ-key"}},
	{"composed lower finds stored decomposed", "ä-nfd", []string{"A\u0308-nfd"}},
	{"composed upper finds stored decomposed", "Ä-NFD", []string{"A\u0308-nfd"}},
	{"decomposed input finds stored decomposed", "a\u0308-nfd", []string{"A\u0308-nfd"}},
	{"composed fragment finds composed and decomposed", "ä", []string{"ÄÖ-key", "A\u0308-nfd"}},
	{"sharp s matches itself", "STRAßE", []string{"straße"}},
	{"sharp s is not expanded to ss", "STRASSE", nil},
	{"greek capital sigma", "ΟΔΟΣ", []string{"ΟΔΟΣ", "οδος-lower"}},
	{"greek medial sigma", "οδοσ", []string{"ΟΔΟΣ", "οδος-lower"}},
	{"greek final sigma", "οδος", []string{"ΟΔΟΣ", "οδος-lower"}},
	{"greek sigma fragment", "οσ", []string{"ΟΔΟΣ", "οδος-lower"}},
	{"dotted capital I lower", "istanbul", []string{"İstanbul"}},
	{"dotted capital I upper", "İSTANBUL", []string{"İstanbul"}},
	{"underscore is literal", "prod_key", []string{"prod_KEY"}},
	{"lone underscore is literal", "_", []string{"prod_KEY"}},
	{"percent is literal", "100%d", []string{"100%done"}},
	{"lone percent is literal", "%", []string{"100%done"}},
	{"backslash is literal", `\`, []string{`back\slash`}},
	{"no match", "zzz", nil},
}

func runSecretFoldCases(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	for _, n := range foldSecretNames {
		require.NoError(t, ls.db.Create(&models.SecretNode{
			ProjectID: 1, EnvironmentID: 1, Name: n, IsSecret: true,
		}).Error)
	}
	list := func(q string) []string {
		got, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{Search: &q, PageSize: 100})
		require.NoError(t, err, "query %q", q)
		var names []string
		for _, s := range got {
			names = append(names, s.Name)
		}
		sort.Strings(names)
		return names
	}
	for _, c := range foldSecretCases {
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		assert.Equal(t, want, list(c.query), "%s (query %q)", c.name, c.query)
	}
	// Empty filter means "no filter": every secret comes back.
	assert.Len(t, list(""), len(foldSecretNames))
}

func TestListSecrets_SearchUnicodeCase_SQLite(t *testing.T) {
	runSecretFoldCases(t, newFoldSQLiteStore(t))
}

func TestListSecrets_SearchUnicodeCase_Postgres(t *testing.T) {
	runSecretFoldCases(t, newFoldPGStore(t))
}

type foldUser struct{ username, email string }

var foldUsers = []foldUser{
	{"Alpha", "Alpha@Example.COM"},
	{"Ünal", "Ünal@example.com"}, // Ünal
	{"ΟΔΟΣ", "odos@example.com"},
	{"a_b", "a_b@example.com"},
	{"aXb", "aXb@example.com"},
	{"50%off", "50%off@example.com"},
	{"plain", "plain@example.com"},
	{"Zoe\u0308", "Zoe\u0308@example.com"}, // Zoë stored decomposed (e + U+0308), not NFC
}

var foldUsernameCases = []foldCase{
	{"ascii lower finds mixed", "alpha", []string{"Alpha"}},
	{"ascii upper finds mixed", "ALPHA", []string{"Alpha"}},
	{"substring", "lph", []string{"Alpha"}},
	{"umlaut lower finds upper", "ünal", []string{"Ünal"}},
	{"umlaut upper", "ÜNAL", []string{"Ünal"}},
	{"greek final sigma", "οδος", []string{"ΟΔΟΣ"}},
	{"composed finds stored decomposed", "ZOË", []string{"Zoe\u0308"}},
	{"underscore is literal", "a_b", []string{"a_b"}},
	{"lone underscore is literal", "_", []string{"a_b"}},
	{"percent is literal", "%", []string{"50%off"}},
	{"no match", "zzz", nil},
}

var foldEmailCases = []foldCase{
	{"ascii lower finds mixed", "alpha@example.com", []string{"Alpha@Example.COM"}},
	{"ascii upper finds lower", "PLAIN@EXAMPLE", []string{"plain@example.com"}},
	{"umlaut lower finds upper", "ünal@", []string{"Ünal@example.com"}},
	{"composed finds stored decomposed", "zoë@", []string{"Zoe\u0308@example.com"}},
	{"underscore is literal", "a_b@", []string{"a_b@example.com"}},
	{"lone underscore is literal", "_", []string{"a_b@example.com"}},
	{"percent is literal", "%", []string{"50%off@example.com"}},
	{"no match", "zzz", nil},
}

func runUserFoldCases(t *testing.T, ls *LocalStorage) {
	t.Helper()
	ctx := context.Background()
	for _, u := range foldUsers {
		require.NoError(t, ls.db.Create(&models.User{Username: u.username, Email: u.email, PasswordHash: "x"}).Error)
	}
	run := func(f *storage.UserFilter, field func(*models.User) string) []string {
		f.PageSize = 100
		got, _, err := ls.ListUsers(ctx, f)
		require.NoError(t, err)
		var out []string
		for _, u := range got {
			out = append(out, field(u))
		}
		sort.Strings(out)
		return out
	}
	username := func(u *models.User) string { return u.Username }
	email := func(u *models.User) string { return u.Email }
	sorted := func(in []string) []string {
		out := append([]string(nil), in...)
		sort.Strings(out)
		return out
	}
	for _, c := range foldUsernameCases {
		q := c.query
		assert.Equal(t, sorted(c.want), run(&storage.UserFilter{Username: &q}, username), "Username: %s (query %q)", c.name, c.query)
	}
	for _, c := range foldEmailCases {
		q := c.query
		assert.Equal(t, sorted(c.want), run(&storage.UserFilter{Email: &q}, email), "Email: %s (query %q)", c.name, c.query)
	}
	// Empty filter value matches every row, as before.
	empty := ""
	assert.Len(t, run(&storage.UserFilter{Username: &empty}, username), len(foldUsers))
	assert.Len(t, run(&storage.UserFilter{Email: &empty}, email), len(foldUsers))
}

func TestListUsers_UsernameEmailUnicodeCase_SQLite(t *testing.T) {
	runUserFoldCases(t, newFoldSQLiteStore(t))
}

func TestListUsers_UsernameEmailUnicodeCase_Postgres(t *testing.T) {
	runUserFoldCases(t, newFoldPGStore(t))
}

func TestFoldedContainsClause_EscapesAfterFolding(t *testing.T) {
	cond, arg := foldedContainsClause("sqlite", "name", `A_%\B`)
	assert.Equal(t, `keyorix_fold(name) LIKE ? ESCAPE '\'`, cond)
	assert.Equal(t, `%a\_\%\\b%`, arg)

	cond, arg = foldedContainsClause("postgres", "name", "Σ")
	assert.Equal(t, "translate(LOWER(normalize(name, NFC)), 'ς', 'σ') LIKE ? ESCAPE '\\'", cond)
	assert.Equal(t, "%σ%", arg)
}

// The SQL function must be NULL-safe: nullable columns (users.email) pass NULL through.
func TestKeyorixFold_NullAndNonText(t *testing.T) {
	ls := newFoldSQLiteStore(t)
	var got struct{ A, B, C *string }
	require.NoError(t, ls.db.Raw("SELECT keyorix_fold(NULL) AS a, keyorix_fold('Ä') AS b, keyorix_fold(42) AS c").Scan(&got).Error)
	assert.Nil(t, got.A)
	require.NotNil(t, got.B)
	assert.Equal(t, "ä", *got.B)
	require.NotNil(t, got.C)
	assert.Equal(t, "42", *got.C)
}
