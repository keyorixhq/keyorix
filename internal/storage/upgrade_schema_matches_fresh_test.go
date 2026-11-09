// upgrade_schema_matches_fresh_test.go -- oracle 6 of the upgrade fuzzers: an
// upgraded database has the columns and indexes a fresh install of this tree has.
//
// Compared per table: each column's name, type, NOT NULL, default and primary key
// position, and each explicitly created index's name, uniqueness, partial flag and
// columns. Not compared: column order, triggers, the partial indexes' WHERE text,
// and the automatic indexes behind PRIMARY KEY and UNIQUE.
//
// Every current difference is listed in ugExpectedSchemaDiffs. A listed difference
// that stops occurring is a finding too, so the entry cannot outlive what it records.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// ugFoldColumnType merges the two spellings a hand-written ALTER and AutoMigrate
// use for the same storage class (BIGINT/INTEGER, BOOLEAN/NUMERIC). It folds
// nothing else on purpose: SQLite would accept any type name, and a wrong one
// (TIMESTAMP WITH TIME ZONE for DATETIME, INV-STORAGE-timestamp-ddl-dialect-type)
// is exactly what this oracle must still see.
func ugFoldColumnType(typ string) string {
	switch typ {
	case "BIGINT":
		return "INTEGER"
	case "BOOLEAN":
		return "NUMERIC"
	}
	return typ
}

// ugSchemaOf lists one line per column and per index of every table, sorted.
func ugSchemaOf(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT m.name, c.name, upper(c.type), c."notnull", COALESCE(c.dflt_value,''), c.pk
		FROM sqlite_master m, pragma_table_info(m.name) c
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, fmt.Errorf("listing columns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var table, name, typ, dflt string
		var notNull, pk int
		if err := rows.Scan(&table, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("column %s.%s %s notnull=%d default=%s pk=%d", table, name, ugFoldColumnType(typ), notNull, dflt, pk))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	idx, err := db.Query(`SELECT m.name, il.name, il."unique", il.partial, COALESCE(group_concat(ii.name, ','), '')
		FROM sqlite_master m, pragma_index_list(m.name) il LEFT JOIN pragma_index_info(il.name) ii
		WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' AND il.origin = 'c'
		GROUP BY m.name, il.name`)
	if err != nil {
		return nil, fmt.Errorf("listing indexes: %w", err)
	}
	defer func() { _ = idx.Close() }()
	for idx.Next() {
		var table, name, cols string
		var unique, partial int
		if err := idx.Scan(&table, &name, &unique, &partial, &cols); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("index %s.%s unique=%d partial=%d on %s", table, name, unique, partial, cols))
	}
	if err := idx.Err(); err != nil {
		return nil, err
	}
	slices.Sort(out)
	return out, nil
}

// ugFreshSchema is the schema a fresh install of this tree creates, built once per process.
var ugFreshSchema = sync.OnceValues(func() ([]string, error) {
	dir, err := os.MkdirTemp("", "keyorix-upgrade-fresh-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	dbPath := filepath.Join(dir, "fresh.db")
	st, err := NewStorageFactory().CreateStorage(ugLocalConfig(dbPath))
	if err != nil {
		return nil, fmt.Errorf("fresh install: %w", err)
	}
	if err := ugCloseStorage(st); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	return ugSchemaOf(db)
})

// ugSchemaDiff returns one "only in upgraded:" / "only in fresh:" line per difference.
func ugSchemaDiff(fresh, upgraded []string) []string {
	inFresh := make(map[string]bool, len(fresh))
	for _, l := range fresh {
		inFresh[l] = true
	}
	inUpgraded := make(map[string]bool, len(upgraded))
	var out []string
	for _, l := range upgraded {
		inUpgraded[l] = true
		if !inFresh[l] {
			out = append(out, "only in upgraded: "+l)
		}
	}
	for _, l := range fresh {
		if !inUpgraded[l] {
			out = append(out, "only in fresh: "+l)
		}
	}
	slices.Sort(out)
	return out
}

// ugScenarioV091Stopped is the one interrupted v0.91.0 upgrade the harness runs
// (TestUpgradeInterrupted_V091_ColumnNeverAdded, stop 41). v0.91.0 is outside
// FuzzUpgradeInterrupted until that defect is fixed, and every other source's
// interrupted upgrade has to end at its own uninterrupted schema.
const ugScenarioV091Stopped = "v0.91.0 stopped"

func ugSchemaScenario(tag string, stopAfter int) string {
	if stopAfter > 0 && tag == ugSources[0] {
		return ugScenarioV091Stopped
	}
	return tag
}

const (
	ugWhyV091Defect = "known defect: an interrupted v0.91.0 upgrade never reaches the fresh-install tail (TestUpgradeInterrupted_V091_ColumnNeverAdded)"
	ugWhyFreshOnly  = "open: only the fresh-install tail creates this and no step adds it to an existing table; below the v0.93.x support floor"
	ugWhyNoIndex    = "open: an upgraded database never gets the index the model declares (no step creates it)"
	ugWhyNotNull    = "open: the upgrade's ALTER declares NOT NULL, the model does not"
	ugWhyRetained   = "by design: an upgrade does not drop a column a later release stopped using"
)

// ugExpectedSchemaDiffs is every difference between an upgraded and a fresh
// schema that exists today. Each entry is one reason and the lines it explains,
// in ugSchemaDiff's own format, for the scenarios it applies to. Fixing one of
// them makes oracle 6 fail until the entry is removed.
var ugExpectedSchemaDiffs = []struct {
	Why       string
	Scenarios []string
	Lines     []string
}{
	{ugWhyV091Defect, []string{ugScenarioV091Stopped}, []string{
		"only in fresh: column audit_events.machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column groups.name_folded TEXT notnull=1 default= pk=0",
		"only in fresh: column roles.name_folded TEXT notnull=1 default= pk=0",
		"only in fresh: column secret_nodes.owner_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column users.email_folded TEXT notnull=0 default= pk=0",
		"only in fresh: column users.username_folded TEXT notnull=1 default= pk=0",
		"only in fresh: index secret_nodes.idx_secret_nodes_owner_machine_identity_id unique=0 partial=0 on owner_machine_identity_id",
		"only in upgraded: column groups.name_folded TEXT notnull=1 default='' pk=0",
		"only in upgraded: column roles.name_folded TEXT notnull=1 default='' pk=0",
		"only in upgraded: column users.email_folded TEXT notnull=1 default='' pk=0",
		"only in upgraded: column users.username_folded TEXT notnull=1 default='' pk=0",
	}},
	{ugWhyFreshOnly, []string{"v0.91.0", ugScenarioV091Stopped}, []string{
		"only in fresh: column access_request_approvals.approver_machine_identity_id INTEGER notnull=1 default=0 pk=0",
		"only in fresh: column access_requests.resolved_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column access_review_campaigns.closed_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column access_review_campaigns.created_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column break_glass_activations.revoked_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column machine_identities.created_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column project_invitations.invited_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column project_memberships.invited_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column secret_dependencies.created_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: column setup_tokens.created_by_machine_identity_id INTEGER notnull=0 default= pk=0",
		"only in fresh: index access_request_approvals.ux_access_request_approver unique=1 partial=0 on request_id,approver_id,approver_machine_identity_id",
		"only in upgraded: index access_request_approvals.ux_access_request_approver unique=1 partial=0 on request_id,approver_id",
	}},
	{ugWhyFreshOnly, []string{"v0.91.0", ugScenarioV091Stopped, "v0.92.1"}, []string{
		"only in fresh: column sso_login_states.code_verifier TEXT notnull=0 default= pk=0",
	}},
	{ugWhyNoIndex, []string{"v0.91.0", ugScenarioV091Stopped, "v0.92.1", "v0.93.0", "v0.94.0", "v0.95.3"}, []string{
		"only in fresh: index break_glass_activations.idx_break_glass_activations_reviewed_by unique=0 partial=0 on reviewed_by",
	}},
	{ugWhyNotNull, []string{ugScenarioV091Stopped, "v0.92.1", "v0.93.0", "v0.94.0", "v0.95.3", "v0.96.3"}, []string{
		"only in fresh: column users.mfa_enrolment_required NUMERIC notnull=0 default=false pk=0",
		"only in upgraded: column users.mfa_enrolment_required NUMERIC notnull=1 default=false pk=0",
	}},
	{ugWhyRetained, []string{"v0.91.0", ugScenarioV091Stopped}, []string{
		"only in upgraded: column sessions.encrypted_session_token BLOB notnull=0 default= pk=0",
		"only in upgraded: column sessions.session_token_metadata BLOB notnull=0 default= pk=0",
	}},
	{ugWhyRetained, []string{"v0.95.3"}, []string{
		"only in upgraded: column notification_channels.url TEXT notnull=0 default= pk=0",
	}},
}

// ugStopWindowSource is the source the stop positions in ugStopWindowDiffs are for.
const ugStopWindowSource = "v0.93.0"

// ugStopWindowDiffs are the indexes a restart does not repair, each with one stop
// position (on ugStopWindowSource's bare snapshot) that shows it. Open defect, same
// shape every time: a step creates a table or column and then its index, gated on
// the table or column, so a crash between the two skips the index on every later
// boot. The lines are tolerated only after a stop, where most stop positions do not
// produce them, so a missing line cannot be judged per exec:
// TestUpgradeInterrupted_KnownIndexGaps_StillOpen pins each row and fails when one
// stops occurring. Steps appended to the end of migrateDatabase's list do not move
// these positions.
var ugStopWindowDiffs = []struct {
	Stop  int
	Lines []string
}{
	{35, []string{"only in fresh: index login_attempts.idx_login_attempt_reservation_key unique=1 partial=0 on reservation_key"}},
	{46, []string{"only in fresh: index pending_audit_events.idx_pending_audit_events_created_at unique=0 partial=0 on created_at"}},
	{54, []string{"only in fresh: index secret_templates.idx_secret_templates_name unique=1 partial=0 on name"}},
	{56, []string{"only in fresh: index alert_escalation_policies.idx_alert_escalation_policies_name unique=1 partial=0 on name"}},
	{60, []string{
		"only in fresh: index secret_version_comments.idx_secret_version_comments_secret_id unique=0 partial=0 on secret_id",
		"only in fresh: index secret_version_comments.idx_secret_version_comments_version_id unique=0 partial=0 on version_id",
	}},
	{63, []string{
		"only in fresh: index mfa_stepup_tokens.idx_mfa_stepup_tokens_expires_at unique=0 partial=0 on expires_at",
		"only in fresh: index mfa_stepup_tokens.idx_mfa_stepup_tokens_user_id unique=1 partial=0 on user_id",
	}},
	{66, []string{"only in fresh: index hygiene_trend_snapshots.idx_hygiene_trend_snapshots_snapshot_date unique=1 partial=0 on snapshot_date"}},
	{68, []string{"only in fresh: index compliance_posture_snapshots.idx_compliance_posture_snapshots_snapshot_date unique=1 partial=0 on snapshot_date"}},
	{90, []string{
		"only in fresh: index mfa_reset_requests.idx_mfa_reset_requests_expires_at unique=0 partial=0 on expires_at",
		"only in fresh: index mfa_reset_requests.idx_mfa_reset_requests_status unique=0 partial=0 on status",
		"only in fresh: index mfa_reset_requests.idx_mfa_reset_requests_target_user_id unique=0 partial=0 on target_user_id",
	}},
}

func ugStopWindowLine(line string) bool {
	for _, row := range ugStopWindowDiffs {
		if slices.Contains(row.Lines, line) {
			return true
		}
	}
	return false
}

// ugCheckFreshSchema is oracle 6. raw must be the upgraded database.
func ugCheckFreshSchema(t testing.TB, scenario string, stopped bool, raw *sql.DB) []ugFinding {
	t.Helper()
	fresh, err := ugFreshSchema()
	if err != nil {
		t.Fatalf("building the fresh-install schema: %v", err)
	}
	upgraded, err := ugSchemaOf(raw)
	if err != nil {
		t.Fatalf("reading the upgraded schema: %v", err)
	}
	diff := ugSchemaDiff(fresh, upgraded)

	expected := map[string]string{}
	for _, e := range ugExpectedSchemaDiffs {
		if !slices.Contains(e.Scenarios, scenario) {
			continue
		}
		for _, l := range e.Lines {
			expected[l] = e.Why
		}
	}
	var out []ugFinding
	for _, l := range diff {
		if _, ok := expected[l]; ok || (stopped && ugStopWindowLine(l)) {
			continue
		}
		out = append(out, ugFinding{6, fmt.Sprintf("schema after upgrading (%s) differs from a fresh install: %s", scenario, l)})
	}
	for l, why := range expected {
		if !slices.Contains(diff, l) {
			out = append(out, ugFinding{6, fmt.Sprintf("expected schema difference no longer occurs (%s), remove its entry from ugExpectedSchemaDiffs: %s [%s]", scenario, l, why)})
		}
	}
	return out
}
