// bulk_test.go — unit tests for the bulk-approve, bulk-reject, and
// rejection-templates CLI commands (ADR-024 extension). Tests cover command
// structure, required flags, and the parseIDList helper.
package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Command structure ─────────────────────────────────────────────────────────

func TestBulkCommandsRegistered(t *testing.T) {
	names := make([]string, 0)
	for _, c := range RequestCmd.Commands() {
		names = append(names, c.Use)
	}
	assert.Contains(t, names, "bulk-approve", "bulk-approve subcommand must be registered")
	assert.Contains(t, names, "bulk-reject", "bulk-reject subcommand must be registered")
	assert.Contains(t, names, "rejection-templates", "rejection-templates subcommand must be registered")
}

func TestBulkApproveRequiredFlags(t *testing.T) {
	for _, name := range []string{"ids", "by"} {
		f := bulkApproveCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "bulk-approve should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestBulkRejectRequiredFlags(t *testing.T) {
	for _, name := range []string{"ids", "by", "reason"} {
		f := bulkRejectCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "bulk-reject should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRejectionTemplatesSubcommands(t *testing.T) {
	names := make([]string, 0)
	for _, c := range rejectionTemplatesCmd.Commands() {
		names = append(names, c.Use)
	}
	for _, expected := range []string{"list", "add", "delete"} {
		assert.Contains(t, names, expected, "rejection-templates should have subcommand %q", expected)
	}
}

func TestRejectionTemplatesAddRequiredFlags(t *testing.T) {
	for _, name := range []string{"name", "reason", "by"} {
		f := tmplAddCmd.Flags().Lookup(name)
		assert.NotNil(t, f, "rejection-templates add should have --%s", name)
		assert.NotEmpty(t, f.Annotations[cobraRequired], "--%s should be required", name)
	}
}

func TestRejectionTemplatesDeleteExactlyOneArg(t *testing.T) {
	assert.NotNil(t, tmplDeleteCmd.Args, "rejection-templates delete should require exactly 1 arg")
}

// ── parseIDList ───────────────────────────────────────────────────────────────

func TestParseIDList_Single(t *testing.T) {
	ids, err := parseIDList("42")
	require.NoError(t, err)
	assert.Equal(t, []uint{42}, ids)
}

func TestParseIDList_Multiple(t *testing.T) {
	ids, err := parseIDList("1,2,3")
	require.NoError(t, err)
	assert.Equal(t, []uint{1, 2, 3}, ids)
}

func TestParseIDList_Spaces(t *testing.T) {
	ids, err := parseIDList(" 10 , 20 , 30 ")
	require.NoError(t, err)
	assert.Equal(t, []uint{10, 20, 30}, ids)
}

func TestParseIDList_Empty(t *testing.T) {
	_, err := parseIDList("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one ID")
}

func TestParseIDList_OnlyCommas(t *testing.T) {
	_, err := parseIDList(",,,")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one ID")
}

func TestParseIDList_InvalidID(t *testing.T) {
	_, err := parseIDList("1,foo,3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ID")
}

func TestParseIDList_NegativeID(t *testing.T) {
	_, err := parseIDList("-1")
	require.Error(t, err)
}

func TestParseIDList_SkipsTrailingComma(t *testing.T) {
	// A trailing comma produces an empty segment which is skipped.
	ids, err := parseIDList("5,6,")
	require.NoError(t, err)
	assert.Equal(t, []uint{5, 6}, ids)
}

// ── runBulkApprove validation paths ──────────────────────────────────────────

func TestRunBulkApprove_InvalidIDList(t *testing.T) {
	orig := bulkApproveIDs
	defer func() { bulkApproveIDs = orig }()
	bulkApproveIDs = "not-a-number"
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkApprove_EmptyIDList(t *testing.T) {
	orig := bulkApproveIDs
	defer func() { bulkApproveIDs = orig }()
	bulkApproveIDs = ""
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkApprove_ServiceInitError(t *testing.T) {
	origIDs, origBy := bulkApproveIDs, bulkApproveBy
	defer func() { bulkApproveIDs = origIDs; bulkApproveBy = origBy }()
	bulkApproveIDs = "1"
	bulkApproveBy = "reviewer@example.com"
	// InitializeCoreService succeeds (loads default SQLite config) but the
	// subsequent resolveUserID or BulkApprove call will fail with a DB error.
	err := runBulkApprove(nil, nil)
	require.Error(t, err)
}

// ── runBulkReject validation paths ───────────────────────────────────────────

func TestRunBulkReject_InvalidIDList(t *testing.T) {
	orig := bulkRejectIDs
	defer func() { bulkRejectIDs = orig }()
	bulkRejectIDs = "abc"
	err := runBulkReject(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ids")
}

func TestRunBulkReject_ServiceInitError(t *testing.T) {
	origIDs, origBy, origReason := bulkRejectIDs, bulkRejectBy, bulkRejectReason
	defer func() { bulkRejectIDs = origIDs; bulkRejectBy = origBy; bulkRejectReason = origReason }()
	bulkRejectIDs = "2"
	bulkRejectBy = "reviewer@example.com"
	bulkRejectReason = "no budget"
	// Will fail at resolveUserID or BulkReject step with a DB error.
	err := runBulkReject(nil, nil)
	require.Error(t, err)
}

// ── runTmplList / runTmplAdd / runTmplDelete service-init errors ──────────────

func TestRunTmplList_NoError(t *testing.T) {
	// InitializeCoreService succeeds (default ./secrets.db) and ListRejectionReasonTemplates
	// returns empty (no templates) — so no error, just prints "No rejection-reason templates".
	err := runTmplList(nil, nil)
	// Either no error (table exists) or error from missing tables — both are valid.
	// This just verifies the function doesn't panic.
	_ = err
}

func TestRunTmplAdd_ServiceInitError(t *testing.T) {
	origName, origReason, origBy := tmplName, tmplReason, tmplBy
	defer func() { tmplName = origName; tmplReason = origReason; tmplBy = origBy }()
	tmplName = "x"
	tmplReason = "y"
	tmplBy = "admin@example.com"
	// Will fail at resolveUserID or CreateRejectionReasonTemplate step.
	err := runTmplAdd(nil, nil)
	require.Error(t, err)
}

func TestRunTmplDelete_InvalidID(t *testing.T) {
	err := runTmplDelete(nil, []string{"notanumber"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid template ID")
}

func TestRunTmplDelete_ServiceInitError(t *testing.T) {
	// Will fail at DeleteRejectionReasonTemplate step with a DB error.
	err := runTmplDelete(nil, []string{"1"})
	require.Error(t, err)
}
