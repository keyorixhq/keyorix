package main

import "testing"

func TestExcludeReason(t *testing.T) {
	cited := map[string]bool{"TestCitedByLedger": true}
	for _, tc := range []struct {
		name, src string
		tests     []string
		want      string
	}{
		{"plain_test.go", "package core\nfunc TestPlain(t *testing.T) {}\n", []string{"TestPlain"}, ""},
		{"fuzz_x_test.go", "package core\nfunc FuzzX(f *testing.F) {}\n", nil, "fuzz"},
		{"seed_test.go", "package core\nvar p = \"testdata/fuzz\"\n", nil, "testdata"},
		{"race_postgres_test.go", "package core\n", nil, "postgres"},
		{"dsn_test.go", "package core\nvar d = os.Getenv(\"KEYORIX_TEST_PG_DSN\")\n", nil, "postgres"},
		{"reg_test.go", "package core\nfunc init() { register() }\n", nil, "registry"},
		{"scan_test.go", "package core\nimport \"go/parser\"\n", nil, "source-scan"},
		{"cited_test.go", "package core\n", []string{"TestCitedByLedger"}, "ledger:TestCitedByLedger"},
	} {
		if got := excludeReason(&fileInfo{name: tc.name, src: tc.src, tests: tc.tests}, cited); got != tc.want {
			t.Errorf("%s: excludeReason = %q, want %q", tc.name, got, tc.want)
		}
	}
}
