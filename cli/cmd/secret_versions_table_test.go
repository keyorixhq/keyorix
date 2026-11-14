package cmd

import (
	"regexp"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
)

// TestDisplayVersionsTable_Golden pins the customer-facing `secret versions`
// table byte-for-byte: no note about columns the API does not expose, and no
// internal reference anywhere in the output.
func TestDisplayVersionsTable_Golden(t *testing.T) {
	name := "db-password"
	id, v1, v2, r1, r2, total := 7, 1, 2, 0, 3, 5
	t1 := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 2, 10, 0, 5, 0, time.UTC)
	secret := &apiclient.Secret{Name: &name, Id: &id}
	versions := []apiclient.SecretVersion{
		{VersionNumber: &v1, ReadCount: &r1, CreatedAt: &t1},
		{VersionNumber: &v2, ReadCount: &r2, CreatedAt: &t2},
	}

	got := captureStdout(t, func() { displayVersionsTable(secret, versions, &total) })

	const want = "Secret Versions\n" +
		"==================\n" +
		"Secret: db-password (ID: 7)\n" +
		"Total Versions: 2\n" +
		"Total Reads: 5\n" +
		"\n" +
		"VERSION  READS*     CREATED (UTC)       \n" +
		"-------- ---------- --------------------\n" +
		"1        0          2026-11-01 09:30:00 \n" +
		"2        3          2026-11-02 10:00:05 \n" +
		"\n" +
		"Latest Version: 2 (Created: 2026-11-02 10:00:05)\n" +
		"* READS counts reads against a --max-reads limit only (0 when none is set); Total Reads above counts every value read of the secret; each is listed by `keyorix secret access-log`.\n"
	if got != want {
		t.Fatalf("secret versions table drifted.\n got: %q\nwant: %q", got, want)
	}

	if regexp.MustCompile(`#[0-9]{3,}|design §|ADR-|pre-#|§|not exposed by the API|omitted`).MatchString(got) {
		t.Fatalf("customer-facing output carries an internal reference or implementation note: %q", got)
	}
}
