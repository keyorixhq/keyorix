// audit.go ports `keyorix audit` (docs/cli-split-inventory.md §2.5, PR 7): operator access
// to the tamper-evident audit trail (ADR-029). Same flags, output, and exit codes as the
// old CLI's internal/cli/audit package -- a pure transport port (REST only, already
// REST-only in the old CLI too), not a behavior change.
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/apiclient"
	"github.com/keyorixhq/keyorix/cli/internal/cliout"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify and export the tamper-evident audit trail",
}

func init() {
	auditCmd.AddCommand(auditVerifyCmd, auditExportCmd, auditCheckpointCmd, auditLogsCmd, auditSearchCmd, auditMigrateChainCmd)
}

// ── audit verify ─────────────────────────────────────────────────────────────

var auditVerifyJSON bool

var auditVerifyCmd = &cobra.Command{
	Use:          "verify",
	Short:        "Re-walk the audit hash chain and report integrity (non-zero exit if broken)",
	SilenceUsage: true,
	RunE:         runAuditVerify,
}

func init() {
	auditVerifyCmd.Flags().BoolVar(&auditVerifyJSON, "json", false, "Emit the raw verification result as JSON (for recording the external anchor)")
}

type verifyResult struct {
	Valid                     bool   `json:"valid"`
	ChainedEvents             int    `json:"chained_events"`
	UnchainedEvents           int    `json:"unchained_events"`
	HeadHash                  string `json:"head_hash"`
	HeadID                    uint   `json:"head_id"`
	FirstBrokenID             uint   `json:"first_broken_id"`
	Reason                    string `json:"reason"`
	Checkpointed              bool   `json:"checkpointed"`
	CheckpointReason          string `json:"checkpoint_reason"`
	AnchorToken               string `json:"anchor_token,omitempty"`
	AnchoredAt                string `json:"anchored_at,omitempty"`
	AnchorProvider            string `json:"anchor_provider,omitempty"`
	AnchorTrustRootConfigured bool   `json:"anchor_trust_root_configured,omitempty"`
}

func runAuditVerify(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.VerifyAuditChainWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("verify audit chain", resp.StatusCode(), resp.Body)
	}
	v, err := decodeData[verifyResult](resp.Body)
	if err != nil {
		return err
	}

	if auditVerifyJSON {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
	} else {
		status := "VALID"
		if !v.Valid {
			status = "BROKEN"
		}
		fmt.Printf("Audit chain: %s\n", status)
		fmt.Printf("  chained events:   %d\n", v.ChainedEvents)
		fmt.Printf("  unchained events: %d\n", v.UnchainedEvents)
		fmt.Printf("  head id:          %d\n", v.HeadID)
		fmt.Printf("  head hash:        %s\n", v.HeadHash)
		if v.Checkpointed {
			fmt.Println("  checkpoint:       checked against a signed in-DB checkpoint (on-box truncation detection)")
		} else {
			fmt.Println("  checkpoint:       none enforced (record (chained events, head hash) externally to anchor)")
		}
		if !v.Valid {
			fmt.Printf("  first broken id:  %d\n", v.FirstBrokenID)
			fmt.Printf("  reason:           %s\n", v.Reason)
		} else if v.CheckpointReason != "" {
			fmt.Printf("  note:             %s\n", v.CheckpointReason)
		}
		if v.AnchorToken != "" {
			fmt.Printf("  anchored at:      %s\n", v.AnchoredAt)
			fmt.Printf("  anchor:           %s\n", v.AnchorProvider)
			fmt.Printf("  anchor token:     %s\n", v.AnchorToken)
			if v.AnchorTrustRootConfigured {
				fmt.Println("  anchor verified:  yes (checked locally against the configured TSA trust root)")
			} else {
				fmt.Println("  anchor verified:  NO — no TSA trust root (ca_cert_path) is configured; this token was recorded but never checked against any root of trust")
			}
		}
	}

	if !v.Valid {
		return fmt.Errorf("audit chain verification FAILED (first broken id %d): %s", v.FirstBrokenID, v.Reason)
	}
	return nil
}

// ── audit export ─────────────────────────────────────────────────────────────

var (
	auditExportSince   string
	auditExportAfterID uint
	auditExportLimit   int
	auditExportAll     bool
	auditExportCSV     bool
)

var auditExportCmd = &cobra.Command{
	Use:          "export",
	Short:        "Stream the audit feed as NDJSON (one event per line) for SIEM pull",
	SilenceUsage: true,
	RunE:         runAuditExport,
}

func init() {
	auditExportCmd.Flags().StringVar(&auditExportSince, "since", "", "Only export events at/after this time (RFC3339)")
	auditExportCmd.Flags().UintVar(&auditExportAfterID, "after-id", 0, "Resume after this event id (exclusive cursor)")
	auditExportCmd.Flags().IntVar(&auditExportLimit, "limit", 100, "Events per page (1–1000)")
	auditExportCmd.Flags().BoolVar(&auditExportAll, "all", false, "Follow the cursor to the end, emitting every event")
	auditExportCmd.Flags().BoolVar(&auditExportCSV, "csv", false, "Emit CSV (header + one row per event) instead of NDJSON")
}

type exportPage struct {
	Events     []json.RawMessage `json:"events"`
	Count      int               `json:"count"`
	NextCursor *uint             `json:"next_cursor"`
}

type csvEventRow struct {
	ID          uint   `json:"id"`
	EventType   string `json:"event_type"`
	Timestamp   string `json:"timestamp"`
	Actor       string `json:"actor"`
	ActorType   string `json:"actor_type"`
	UserID      *uint  `json:"user_id"`
	ProjectID   *uint  `json:"project_id"`
	SecretID    *uint  `json:"secret_id"`
	IPAddress   string `json:"ip_address"`
	Success     bool   `json:"success"`
	Description string `json:"description"`
}

func uintPtrStr(p *uint) string {
	if p == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*p), 10)
}

func runAuditExport(cmd *cobra.Command, _ []string) error {
	if auditExportLimit < 1 || auditExportLimit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}
	var sinceTime *time.Time
	if auditExportSince != "" {
		t, err := time.Parse(time.RFC3339, auditExportSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditExportSince, err)
		}
		sinceTime = &t
	}
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}

	var cw *csv.Writer
	if auditExportCSV {
		cw = csv.NewWriter(cmd.OutOrStdout())
		_ = cw.Write([]string{
			"id", "event_time", "event_type", "actor", "actor_type",
			"user_id", "project_id", "secret_id", "ip_address", "success", "description",
		})
	}

	after := auditExportAfterID
	total := 0
	var lastCursor *uint
	for {
		limit := auditExportLimit
		params := &apiclient.ExportAuditLogsParams{Limit: &limit, Since: sinceTime}
		if after > 0 {
			afterID := int(after)
			params.AfterId = &afterID
		}
		resp, err := client.ExportAuditLogsWithResponse(ctx, params)
		if err != nil {
			return err
		}
		if resp.StatusCode() != 200 {
			return apiError("export audit logs", resp.StatusCode(), resp.Body)
		}
		page, err := decodeData[exportPage](resp.Body)
		if err != nil {
			return err
		}
		for _, e := range page.Events {
			if cw != nil {
				var row csvEventRow
				if err := json.Unmarshal(e, &row); err != nil {
					continue
				}
				_ = cw.Write([]string{
					strconv.FormatUint(uint64(row.ID), 10), row.Timestamp, cliout.CSVSafe(row.EventType),
					cliout.CSVSafe(row.Actor), cliout.CSVSafe(row.ActorType), uintPtrStr(row.UserID), uintPtrStr(row.ProjectID),
					uintPtrStr(row.SecretID), cliout.CSVSafe(row.IPAddress), strconv.FormatBool(row.Success), cliout.CSVSafe(row.Description),
				})
				continue
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(e))
		}
		total += len(page.Events)
		lastCursor = page.NextCursor

		if !auditExportAll || page.NextCursor == nil || len(page.Events) == 0 {
			break
		}
		after = *page.NextCursor
	}
	if cw != nil {
		cw.Flush()
	}

	if lastCursor != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); resume with --after-id %d\n", total, *lastCursor)
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); caught up\n", total)
	}
	return nil
}

// ── audit checkpoint ─────────────────────────────────────────────────────────

var auditCheckpointCmd = &cobra.Command{
	Use:          "checkpoint",
	Short:        "Write a signed checkpoint of the current audit-chain head (ADR-029)",
	SilenceUsage: true,
	RunE:         runAuditCheckpoint,
}

type checkpointResult struct {
	ID                        uint   `json:"id"`
	ChainedEvents             int64  `json:"chained_events"`
	HeadID                    uint   `json:"head_id"`
	HeadHash                  string `json:"head_hash"`
	KeyVersion                string `json:"key_version"`
	AnchoredAt                string `json:"anchored_at"`
	AnchorProvider            string `json:"anchor_provider"`
	AnchorToken               string `json:"anchor_token"`
	AnchorTrustRootConfigured bool   `json:"anchor_trust_root_configured"`
}

func runAuditCheckpoint(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.WriteAuditCheckpointWithResponse(ctx)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("write audit checkpoint", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[checkpointResult](resp.Body)
	if err != nil {
		return err
	}
	fmt.Println("Audit checkpoint written:")
	fmt.Printf("  id:             %d\n", out.ID)
	fmt.Printf("  chained events: %d\n", out.ChainedEvents)
	fmt.Printf("  head id:        %d\n", out.HeadID)
	fmt.Printf("  head hash:      %s\n", out.HeadHash)
	if out.AnchoredAt != "" {
		fmt.Printf("  anchored at:    %s\n", out.AnchoredAt)
		fmt.Printf("  anchor:         %s\n", out.AnchorProvider)
		fmt.Printf("  anchor token:   %s\n", out.AnchorToken)
		if !out.AnchorTrustRootConfigured {
			fmt.Println("  anchor verified: NO — no TSA trust root (ca_cert_path) is configured; this token was recorded but never checked against any root of trust")
		}
	}
	return nil
}

// ── audit migrate-chain-encoding ─────────────────────────────────────────────

var auditMigrateConfirm bool

var auditMigrateChainCmd = &cobra.Command{
	Use:          "migrate-chain-encoding",
	Short:        "One-time re-derivation of the audit hash chain under the current encoding",
	SilenceUsage: true,
	RunE:         runAuditMigrateChain,
}

func init() {
	auditMigrateChainCmd.Flags().BoolVar(&auditMigrateConfirm, "confirm", false,
		"Apply the migration for real. Without this flag, the command only previews what would change — nothing is written.")
}

type migrateChainResult struct {
	DryRun               bool   `json:"dry_run"`
	RowsMigrated         int64  `json:"rows_migrated"`
	UnchainedRowsSkipped int64  `json:"unchained_rows_skipped"`
	HeadID               uint   `json:"head_id"`
	HeadHash             string `json:"head_hash"`
	AnchorRowID          uint   `json:"anchor_row_id,omitempty"`
	AnchorNewEntryHash   string `json:"anchor_new_entry_hash,omitempty"`
}

func runAuditMigrateChain(_ *cobra.Command, _ []string) error {
	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	dryRun := apiclient.MigrateAuditChainEncodingParamsDryRun("true")
	if auditMigrateConfirm {
		dryRun = apiclient.MigrateAuditChainEncodingParamsDryRun("false")
	}
	resp, err := client.MigrateAuditChainEncodingWithResponse(ctx, &apiclient.MigrateAuditChainEncodingParams{DryRun: &dryRun})
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("migrate audit chain encoding", resp.StatusCode(), resp.Body)
	}
	out, err := decodeData[migrateChainResult](resp.Body)
	if err != nil {
		return err
	}

	if out.DryRun {
		fmt.Println("DRY RUN — nothing was written. Re-run with --confirm to apply.")
	} else {
		fmt.Println("Audit chain encoding migration applied:")
	}
	fmt.Printf("  rows migrated:          %d\n", out.RowsMigrated)
	fmt.Printf("  unchained rows skipped: %d\n", out.UnchainedRowsSkipped)
	fmt.Printf("  new head id:            %d\n", out.HeadID)
	fmt.Printf("  new head hash:          %s\n", out.HeadHash)
	if out.AnchorRowID != 0 {
		fmt.Printf("  retention anchor row:   %d (re-signed with the migrated entry_hash)\n", out.AnchorRowID)
	}
	if out.DryRun {
		fmt.Println("\nRun 'keyorix-next audit migrate-chain-encoding --confirm' to apply.")
	} else {
		fmt.Println("\nRun 'keyorix-next audit verify' to confirm the chain now verifies end to end.")
	}
	return nil
}

// ── audit logs ───────────────────────────────────────────────────────────────

var (
	auditLogEventType string
	auditLogUserID    uint
	auditLogProjectID uint
	auditLogActorType string
	auditLogSince     string
	auditLogUntil     string
	auditLogLimit     int
)

var auditLogsCmd = &cobra.Command{
	Use:          "logs",
	Short:        "Query the audit trail with filters (human-readable table)",
	SilenceUsage: true,
	RunE:         runAuditLogs,
}

func init() {
	auditLogsCmd.Flags().StringVar(&auditLogEventType, "event-type", "", "Filter by event type (e.g. secret.read, secret.deleted)")
	auditLogsCmd.Flags().UintVar(&auditLogUserID, "user-id", 0, "Filter by actor user id")
	auditLogsCmd.Flags().UintVar(&auditLogProjectID, "project-id", 0, "Filter by project id")
	auditLogsCmd.Flags().StringVar(&auditLogActorType, "actor-type", "", "Filter by actor kind: user | machine_identity | system")
	auditLogsCmd.Flags().StringVar(&auditLogSince, "since", "", "Only events at/after this time (RFC3339)")
	auditLogsCmd.Flags().StringVar(&auditLogUntil, "until", "", "Only events at/before this time (RFC3339)")
	auditLogsCmd.Flags().IntVar(&auditLogLimit, "limit", 50, "Max events to show (1–100)")
}

type logEntry struct {
	ID             uint   `json:"id"`
	EventType      string `json:"event_type"`
	Actor          string `json:"actor"`
	ActorType      string `json:"actor_type"`
	Description    string `json:"description"`
	Timestamp      string `json:"timestamp"`
	Impersonation  bool   `json:"impersonation"`
	ImpersonatedBy string `json:"impersonated_by"`
}

type logsPage struct {
	Logs  []logEntry `json:"logs"`
	Total int64      `json:"total"`
}

func runAuditLogs(_ *cobra.Command, _ []string) error {
	if auditLogLimit < 1 || auditLogLimit > 100 {
		return fmt.Errorf("--limit must be between 1 and 100")
	}
	if auditLogActorType != "" && auditLogActorType != "user" && auditLogActorType != "machine_identity" && auditLogActorType != "system" {
		return fmt.Errorf("--actor-type must be user, machine_identity, or system")
	}
	params := &apiclient.ListAuditLogsParams{}
	limit := auditLogLimit
	params.PageSize = &limit
	if auditLogEventType != "" {
		params.Action = &auditLogEventType
	}
	if auditLogUserID > 0 {
		id := int(auditLogUserID)
		params.UserId = &id
	}
	if auditLogProjectID > 0 {
		id := int(auditLogProjectID)
		params.ProjectId = &id
	}
	if auditLogActorType != "" {
		at := apiclient.ListAuditLogsParamsActorType(auditLogActorType)
		params.ActorType = &at
	}
	if auditLogSince != "" {
		t, err := time.Parse(time.RFC3339, auditLogSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditLogSince, err)
		}
		params.StartTime = &t
	}
	if auditLogUntil != "" {
		t, err := time.Parse(time.RFC3339, auditLogUntil)
		if err != nil {
			return fmt.Errorf("invalid --until %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditLogUntil, err)
		}
		params.EndTime = &t
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.ListAuditLogsWithResponse(ctx, params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("list audit logs", resp.StatusCode(), resp.Body)
	}
	page, err := decodeData[logsPage](resp.Body)
	if err != nil {
		return err
	}
	if len(page.Logs) == 0 {
		fmt.Println("No audit events match.")
		return nil
	}
	printAuditLogTable(page.Logs, page.Total)
	return nil
}

func printAuditLogTable(logs []logEntry, total int64) {
	fmt.Printf("%-6s %-20s %-16s %-9s %-22s %s\n", "ID", "TIME", "ACTOR", "KIND", "EVENT", "DESCRIPTION")
	for _, e := range logs {
		actor := e.Actor
		if e.Impersonation && e.ImpersonatedBy != "" {
			actor = e.ImpersonatedBy + "→" + e.Actor
		}
		fmt.Printf("%-6d %-20s %-16s %-9s %-22s %s\n",
			e.ID, shortTime(e.Timestamp), auditTruncate(cliout.SanitizeForTerminal(actor), 16), e.ActorType,
			auditTruncate(cliout.SanitizeForTerminal(e.EventType), 22), cliout.SanitizeForTerminal(e.Description))
	}
	fmt.Printf("\nShowing %d of %d total event(s).\n", len(logs), total)
}

func shortTime(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	return s
}

func auditTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// ── audit search ─────────────────────────────────────────────────────────────

var (
	auditSearchActor        string
	auditSearchUserID       uint
	auditSearchProjectID    uint
	auditSearchAction       string
	auditSearchResourceType string
	auditSearchResourceID   uint
	auditSearchIP           string
	auditSearchSuccess      string
	auditSearchSince        string
	auditSearchUntil        string
	auditSearchLimit        int
	auditSearchOffset       int
)

var auditSearchCmd = &cobra.Command{
	Use:          "search",
	Short:        "Search the audit trail with structured filters",
	SilenceUsage: true,
	RunE:         runAuditSearch,
}

func init() {
	auditSearchCmd.Flags().StringVar(&auditSearchActor, "actor", "", "Partial match on actor username")
	auditSearchCmd.Flags().UintVar(&auditSearchUserID, "user-id", 0, "Filter by exact actor user ID")
	auditSearchCmd.Flags().UintVar(&auditSearchProjectID, "project-id", 0, "Filter by project ID")
	auditSearchCmd.Flags().StringVar(&auditSearchAction, "action", "", "Filter by exact event type (e.g. secret.read)")
	auditSearchCmd.Flags().StringVar(&auditSearchResourceType, "resource-type", "", "Filter by resource kind (e.g. secret, user, role)")
	auditSearchCmd.Flags().UintVar(&auditSearchResourceID, "resource-id", 0, "Filter by exact resource ID (secret_node_id)")
	auditSearchCmd.Flags().StringVar(&auditSearchIP, "ip", "", "Filter by originating IP address")
	auditSearchCmd.Flags().StringVar(&auditSearchSuccess, "success", "", "Filter by outcome: true or false")
	auditSearchCmd.Flags().StringVar(&auditSearchSince, "since", "", "Only events at/after this RFC3339 time")
	auditSearchCmd.Flags().StringVar(&auditSearchUntil, "until", "", "Only events at/before this RFC3339 time")
	auditSearchCmd.Flags().IntVar(&auditSearchLimit, "limit", 100, "Max results (1–1000)")
	auditSearchCmd.Flags().IntVar(&auditSearchOffset, "offset", 0, "Pagination offset")
}

type searchEvent struct {
	ID          uint   `json:"id"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	EventTime   string `json:"event_time"`
	IPAddress   string `json:"ip_address"`
	ActorType   string `json:"actor_type"`
}

type searchPage struct {
	Events []searchEvent `json:"events"`
	Total  int64         `json:"total"`
}

func runAuditSearch(_ *cobra.Command, _ []string) error {
	if auditSearchLimit < 1 || auditSearchLimit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}
	if auditSearchSuccess != "" && auditSearchSuccess != "true" && auditSearchSuccess != "false" {
		return fmt.Errorf("--success must be true or false")
	}
	params := &apiclient.SearchAuditLogsParams{}
	limit := auditSearchLimit
	params.Limit = &limit
	if auditSearchOffset > 0 {
		offset := auditSearchOffset
		params.Offset = &offset
	}
	if auditSearchActor != "" {
		params.Actor = &auditSearchActor
	}
	if auditSearchUserID > 0 {
		id := int(auditSearchUserID)
		params.UserId = &id
	}
	if auditSearchProjectID > 0 {
		id := int(auditSearchProjectID)
		params.ProjectId = &id
	}
	if auditSearchAction != "" {
		params.Action = &auditSearchAction
	}
	if auditSearchResourceType != "" {
		params.ResourceType = &auditSearchResourceType
	}
	if auditSearchResourceID > 0 {
		id := int(auditSearchResourceID)
		params.ResourceId = &id
	}
	if auditSearchIP != "" {
		params.Ip = &auditSearchIP
	}
	if auditSearchSuccess != "" {
		s := apiclient.SearchAuditLogsParamsSuccess(auditSearchSuccess)
		params.Success = &s
	}
	if auditSearchSince != "" {
		t, err := time.Parse(time.RFC3339, auditSearchSince)
		if err != nil {
			return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditSearchSince, err)
		}
		params.Since = &t
	}
	if auditSearchUntil != "" {
		t, err := time.Parse(time.RFC3339, auditSearchUntil)
		if err != nil {
			return fmt.Errorf("invalid --until %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", auditSearchUntil, err)
		}
		params.Until = &t
	}

	ctx := context.Background()
	client, err := apiClientWithSkewCheck(ctx)
	if err != nil {
		return err
	}
	resp, err := client.SearchAuditLogsWithResponse(ctx, params)
	if err != nil {
		return err
	}
	if resp.StatusCode() != 200 {
		return apiError("search audit logs", resp.StatusCode(), resp.Body)
	}
	page, err := decodeData[searchPage](resp.Body)
	if err != nil {
		return err
	}
	if len(page.Events) == 0 {
		fmt.Println("No audit events match.")
		return nil
	}
	printAuditSearchTable(page.Events, page.Total)
	return nil
}

func printAuditSearchTable(events []searchEvent, total int64) {
	fmt.Printf("%-6s %-20s %-9s %-22s %-15s %s\n", "ID", "TIME", "KIND", "EVENT", "IP", "DESCRIPTION")
	for _, e := range events {
		fmt.Printf("%-6d %-20s %-9s %-22s %-15s %s\n",
			e.ID, shortTime(e.EventTime), auditTruncate(e.ActorType, 9),
			auditTruncate(cliout.SanitizeForTerminal(e.EventType), 22), auditTruncate(cliout.SanitizeForTerminal(e.IPAddress), 15), cliout.SanitizeForTerminal(e.Description))
	}
	fmt.Printf("\nShowing %d of %d total event(s).\n", len(events), total)
}
