package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	dsnNoPwKeyword = "host=127.0.0.1 user=keyorix dbname=keyorix port=15439 sslmode=disable"
	dsnPwKeyword   = dsnNoPwKeyword + " password=in-dsn-secret"
	dsnNoPwURL     = "postgres://keyorix@127.0.0.1:15439/keyorix?sslmode=disable"
	dsnPwURL       = "postgres://keyorix:in-dsn-secret@127.0.0.1:15439/keyorix?sslmode=disable"
	dsnPwURLQuery  = dsnNoPwURL + "&password=in-dsn-secret"
)

// passwordSource sets one way of supplying the DB password and returns the
// secret value and the setting name the error is expected to mention.
type passwordSource struct {
	name  string
	apply func(t *testing.T, d *DatabaseConfig)
	want  string // setting named in a conflict error
}

func passwordSources() []passwordSource {
	return []passwordSource{
		{"env", func(t *testing.T, d *DatabaseConfig) { t.Setenv("KEYORIX_DB_PASSWORD", "other-secret") }, "KEYORIX_DB_PASSWORD"},
		{"file", func(t *testing.T, d *DatabaseConfig) {
			t.Setenv("KEYORIX_DB_PASSWORD_FILE", writeSecretFile(t, "other-secret\n"))
		}, "KEYORIX_DB_PASSWORD_FILE"},
		{"yaml", func(t *testing.T, d *DatabaseConfig) { d.Password = "other-secret" }, "storage.database.password"},
	}
}

// DSN without a password + a password source: the password is applied (the
// #3151 bug: it was silently ignored).
func TestResolvePostgresDSN_DSNWithoutPasswordGetsResolvedPassword(t *testing.T) {
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresDSN(d)
				require.NoError(t, err)
				has, err := dsnHasPassword(got)
				require.NoError(t, err)
				assert.True(t, has, "resolved password must be in the DSN")
				assert.Contains(t, got, "other-secret")
			})
		}
	}
}

func TestResolvePostgresDSN_DSNWithoutPasswordNoSourceUnchanged(t *testing.T) {
	for _, dsn := range []string{dsnNoPwKeyword, dsnNoPwURL} {
		got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assert.Equal(t, dsn, got)
	}
}

// DSN with a password and no other source: used as-is (existing behaviour).
func TestResolvePostgresDSN_DSNWithPasswordAlone(t *testing.T) {
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsn})
		require.NoError(t, err)
		assert.Equal(t, dsn, got)
	}
}

// DSN with a password AND a password source: refuse, name the setting and the
// fix, never print either password or the DSN.
func TestResolvePostgresDSN_ConflictRefused(t *testing.T) {
	for _, dsn := range []string{dsnPwKeyword, dsnPwURL, dsnPwURLQuery} {
		for _, src := range passwordSources() {
			t.Run(src.name+"/"+dsn[:8], func(t *testing.T) {
				d := &DatabaseConfig{DSN: dsn}
				src.apply(t, d)
				got, err := ResolvePostgresDSN(d)
				require.Error(t, err)
				assert.Empty(t, got)
				msg := err.Error()
				assert.Contains(t, msg, "storage.database.dsn")
				assert.Contains(t, msg, src.want)
				assert.Contains(t, msg, "remove the password from storage.database.dsn")
				assert.NotContains(t, msg, "in-dsn-secret")
				assert.NotContains(t, msg, "other-secret")
				assert.NotContains(t, msg, "127.0.0.1")
				assert.Empty(t, BuildPostgresDSN(d), "BuildPostgresDSN must fail closed")
			})
		}
	}
}

// Field-by-field form: unchanged behaviour, with quoting for awkward passwords.
func TestResolvePostgresDSN_Fields(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "p w'd\\")
	got, err := ResolvePostgresDSN(&DatabaseConfig{Host: "h", Name: "n", User: "u", SSLMode: "disable"})
	require.NoError(t, err)
	assert.Contains(t, got, `password='p w\'d\\'`)
	kv := parseKeywordDSN(got)
	var pw string
	for _, p := range kv {
		if p[0] == "password" {
			pw = p[1]
		}
	}
	assert.Equal(t, "p w'd\\", pw, "quoting must round-trip")
}

func TestResolvePostgresDSN_AppendQuotesKeywordPassword(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "has space")
	got, err := ResolvePostgresDSN(&DatabaseConfig{DSN: dsnNoPwKeyword})
	require.NoError(t, err)
	assert.Contains(t, got, "password='has space'")
}

func TestResolvePostgresDSN_InvalidURLErrorHidesDSN(t *testing.T) {
	_, err := ResolvePostgresDSN(&DatabaseConfig{DSN: "postgres://u:in-dsn-secret@h:notaport/db"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "in-dsn-secret")
	assert.Contains(t, err.Error(), "storage.database.dsn")
}

func TestDSNHasPassword(t *testing.T) {
	cases := map[string]bool{
		dsnNoPwKeyword:                 false,
		dsnPwKeyword:                   true,
		"host=h password='' user=u":    false,
		"host=h password='a b' user=u": true,
		"host=h password = x":          true,
		"host=h user=password":         false,
		"host=h user='password=x'":     false,
		dsnNoPwURL:                     false,
		dsnPwURL:                       true,
		dsnPwURLQuery:                  true,
		"postgres://u:@h/db":           false,
		"postgresql://u:p@h/db":        true,
	}
	for dsn, want := range cases {
		got, err := dsnHasPassword(dsn)
		require.NoError(t, err, dsn)
		assert.Equal(t, want, got, dsn)
	}
}

// Validate (what the server and `admin validate` run) refuses the conflict.
func TestValidate_RefusesPostgresDSNPasswordConflict(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "other-secret")
	cfg := validLocalConfig()
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsnPwKeyword
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_DB_PASSWORD")
	assert.Contains(t, err.Error(), "storage.database.dsn")
	assert.NotContains(t, err.Error(), "other-secret")
	assert.NotContains(t, err.Error(), "in-dsn-secret")
}

func TestValidate_AcceptsPostgresDSNWithEnvPassword(t *testing.T) {
	t.Setenv("KEYORIX_DB_PASSWORD", "other-secret")
	cfg := validLocalConfig()
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = dsnNoPwKeyword
	assert.NoError(t, cfg.Validate())
}
