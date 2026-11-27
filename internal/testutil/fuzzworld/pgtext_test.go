package fuzzworld

import (
	"strings"
	"testing"
	"unicode/utf8"
)

var pgTextInputs = []string{
	"",
	"plain",
	"é項目\U0001F600",
	"\xad",
	"\xff\xfe",
	"a\xc3\x28b",
	"x\x00y",
	"\x00",
	"\xad\x00\xff",
}

func TestPGText_Normalises(t *testing.T) {
	want := map[string]string{
		"":              "",
		"plain":         "plain",
		"é項目\U0001F600": "é項目\U0001F600",
		"\xad":          "�",
		"\xff\xfe":      "�",
		"a\xc3\x28b":    "a�(b",
		"x\x00y":        "xy",
		"\x00":          "",
		"\xad\x00\xff":  "��",
	}
	for in, w := range want {
		if got := PGText(in); got != w {
			t.Errorf("PGText(%q) = %q, want %q", in, got, w)
		}
	}
}

func TestPGText_ResultIsPGStorable(t *testing.T) {
	for _, in := range pgTextInputs {
		got := PGText(in)
		if !utf8.ValidString(got) || strings.ContainsRune(got, 0) {
			t.Errorf("PGText(%q) = %q is still refused by a PostgreSQL text column", in, got)
		}
		if again := PGText(got); again != got {
			t.Errorf("PGText is not idempotent on %q: %q then %q", in, got, again)
		}
	}
}

// TestPGText_PostgresAcceptsNormalisedRefusesRaw is the red/green proof on a real
// server: the raw fuzzer strings are refused with SQLSTATE 22021 (red), the
// normalised ones are stored and read back (green). It needs KEYORIX_TEST_PG_DSN
// and skips without it; the pure tests above cover the helper's own contract.
func TestPGText_PostgresAcceptsNormalisedRefusesRaw(t *testing.T) {
	db := OpenPostgres(t, "pgtext")
	if db == nil {
		t.Skip(PGDSNEnv + " not set: the server-side proof needs PostgreSQL")
	}
	if err := db.Exec("CREATE TABLE pgtext_probe (id SERIAL PRIMARY KEY, v TEXT NOT NULL)").Error; err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	for _, in := range pgTextInputs {
		raw := !utf8.ValidString(in) || strings.ContainsRune(in, 0)

		err := db.Exec("INSERT INTO pgtext_probe (v) VALUES (?)", in).Error
		switch {
		case raw && err == nil:
			t.Errorf("PostgreSQL stored %q raw: the premise that it refuses invalid UTF-8 / NUL no longer holds, so PGText is unnecessary", in)
		case raw && !strings.Contains(err.Error(), "22021"):
			t.Errorf("raw %q refused, but not with SQLSTATE 22021: %v", in, err)
		case !raw && err != nil:
			t.Errorf("valid %q refused: %v", in, err)
		}

		norm := PGText(in)
		if err := db.Exec("INSERT INTO pgtext_probe (v) VALUES (?)", norm).Error; err != nil {
			t.Errorf("PGText(%q) = %q refused by PostgreSQL: %v", in, norm, err)
			continue
		}
		var got string
		if err := db.Raw("SELECT v FROM pgtext_probe ORDER BY id DESC LIMIT 1").Scan(&got).Error; err != nil || got != norm {
			t.Errorf("read back %q, want %q (err %v)", got, norm, err)
		}
	}
}
