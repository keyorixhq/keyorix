package pgdsn

import (
	"net/url"
	"strings"
	"testing"
)

func TestWithApplicationName(t *testing.T) {
	cases := []struct {
		name, dsn, want string
	}{
		{"url, no query", "postgres://u:p@h:5432/db", "postgres://u:p@h:5432/db?application_name=kx"},
		{"url keeps other parameters", "postgres://u:p@h:5432/db?sslmode=disable", "postgres://u:p@h:5432/db?application_name=kx&sslmode=disable"},
		{"url replaces an existing name", "postgres://u:p@h/db?application_name=old", "postgres://u:p@h/db?application_name=kx"},
		{"postgresql scheme", "postgresql://u@h/db", "postgresql://u@h/db?application_name=kx"},
		{"keyword/value", "host=h user=u dbname=db", "host=h user=u dbname=db application_name=kx"},
		{"keyword/value replaces an existing name", "host=h application_name=old dbname=db", "host=h dbname=db application_name=kx"},
		{"keyword/value keeps a quoted password byte for byte", "host=h password='a b' dbname=db", "host=h password='a b' dbname=db application_name=kx"},
	}
	for _, c := range cases {
		if got := WithApplicationName(c.dsn, "kx"); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWithApplicationName_URLKeepsPassword(t *testing.T) {
	got := WithApplicationName("postgres://u:p%40ss%2Fw@h:5432/db?sslmode=disable", "kx")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if pw, _ := u.User.Password(); pw != "p@ss/w" {
		t.Errorf("password changed: %q", pw)
	}
	if u.Query().Get("application_name") != "kx" || u.Query().Get("sslmode") != "disable" {
		t.Errorf("query = %q", u.RawQuery)
	}
}

func TestUniqueApplicationName(t *testing.T) {
	a, b := UniqueApplicationName("kx"), UniqueApplicationName("kx")
	if a == b || !strings.HasPrefix(a, "kx_") {
		t.Errorf("names must be distinct and prefixed: %q %q", a, b)
	}
	// Postgres truncates application_name at 63 bytes; a prefix of ordinary
	// length must leave the pid and counter intact.
	if len(a) > 63 {
		t.Errorf("%q is longer than 63 bytes", a)
	}
}
