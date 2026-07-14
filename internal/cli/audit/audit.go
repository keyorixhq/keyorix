// Package audit provides the `keyorix audit` CLI — operator access to the
// tamper-evident audit trail (ADR-029) from the terminal: verify the hash chain
// and capture its external anchor, and pull the full-fidelity export feed for a
// SIEM. Both commands talk to the server's REST API under /api/v1/audit (gated by
// audit.read); they are read-only.
//
// `verify` is built to run unattended: it exits non-zero when the chain does not
// verify, so a cron job (or CI) flags tampering without scraping output. Recording
// (chained_events, head_hash) from each run externally is what lets you detect the
// tail-truncation / genesis re-seed an on-box re-walk cannot catch alone (ADR-029).
package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/spf13/cobra"
)

// AuditCmd is the root `keyorix audit` command.
var AuditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Verify and export the tamper-evident audit trail",
}

var (
	flagJSON    bool
	flagSince   string
	flagAfterID uint
	flagLimit   int
	flagAll     bool
	flagCSV     bool

	// logs filters
	logEventType string
	logUserID    uint
	logProjectID uint
	logActorType string
	logUntil     string
	logLimit     int
)

func init() {
	verifyCmd.Flags().BoolVar(&flagJSON, "json", false, "Emit the raw verification result as JSON (for recording the external anchor)")

	exportCmd.Flags().StringVar(&flagSince, "since", "", "Only export events at/after this time (RFC3339)")
	exportCmd.Flags().UintVar(&flagAfterID, "after-id", 0, "Resume after this event id (exclusive cursor)")
	exportCmd.Flags().IntVar(&flagLimit, "limit", 100, "Events per page (1–1000)")
	exportCmd.Flags().BoolVar(&flagAll, "all", false, "Follow the cursor to the end, emitting every event")
	exportCmd.Flags().BoolVar(&flagCSV, "csv", false, "Emit CSV (header + one row per event) instead of NDJSON")

	logsCmd.Flags().StringVar(&logEventType, "event-type", "", "Filter by event type (e.g. secret.read, secret.deleted)")
	logsCmd.Flags().UintVar(&logUserID, "user-id", 0, "Filter by actor user id")
	logsCmd.Flags().UintVar(&logProjectID, "project-id", 0, "Filter by project id")
	logsCmd.Flags().StringVar(&logActorType, "actor-type", "", "Filter by actor kind: user | machine_identity | system")
	logsCmd.Flags().StringVar(&flagSince, "since", "", "Only events at/after this time (RFC3339)")
	logsCmd.Flags().StringVar(&logUntil, "until", "", "Only events at/before this time (RFC3339)")
	logsCmd.Flags().IntVar(&logLimit, "limit", 50, "Max events to show (1–100)")

	AuditCmd.AddCommand(verifyCmd, exportCmd, checkpointCmd, logsCmd)
}

func client() (*common.RemoteClient, error) {
	c, ok := common.NewRemoteClient()
	if !ok {
		return nil, fmt.Errorf("not connected to a server — run: keyorix connect <server>")
	}
	return c, nil
}

// verifyResult mirrors the /audit/verify payload (ADR-029).
type verifyResult struct {
	Valid            bool   `json:"valid"`
	ChainedEvents    int    `json:"chained_events"`
	UnchainedEvents  int    `json:"unchained_events"`
	HeadHash         string `json:"head_hash"`
	HeadID           uint   `json:"head_id"`
	FirstBrokenID    uint   `json:"first_broken_id"`
	Reason           string `json:"reason"`
	Checkpointed     bool   `json:"checkpointed"`
	CheckpointReason string `json:"checkpoint_reason"`
	// AnchorToken (base64) / AnchoredAt / AnchorProvider surface the latest
	// checkpoint's raw external-notary (RFC 3161) receipt, when one exists — so it
	// can be captured here and verified independently against the TSA out-of-band,
	// without trusting this server's own verification of it (#182).
	AnchorToken    string `json:"anchor_token,omitempty"`
	AnchoredAt     string `json:"anchored_at,omitempty"`
	AnchorProvider string `json:"anchor_provider,omitempty"`
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Re-walk the audit hash chain and report integrity (non-zero exit if broken)",
	// A broken chain is reported via a returned error (exit 1); don't bury that
	// signal under a usage dump.
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var v verifyResult
		if err := c.Get(context.Background(), "/api/v1/audit/verify", &v); err != nil {
			return err
		}

		if flagJSON {
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
			}
		}

		if !v.Valid {
			return fmt.Errorf("audit chain verification FAILED (first broken id %d): %s", v.FirstBrokenID, v.Reason)
		}
		return nil
	},
}

// exportPage mirrors the /audit/export payload. Events stay as raw JSON so the
// CLI emits them at full fidelity (one compact object per line — NDJSON).
type exportPage struct {
	Events     []json.RawMessage `json:"events"`
	Count      int               `json:"count"`
	NextCursor *uint             `json:"next_cursor"`
}

// csvEventRow is the subset of an exported audit event projected into CSV columns.
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

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Stream the audit feed as NDJSON (one event per line) for SIEM pull",
	Long: `Stream the full-fidelity audit feed as newline-delimited JSON (one event per
line) on stdout — pipe it to a file, jq, or a SIEM ingester. A per-run summary
(count and the cursor to resume from) is written to stderr so stdout stays clean.

Pull incrementally with --after-id (the previous run's cursor), or grab everything
since a point in time with --since --all.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if flagLimit < 1 || flagLimit > 1000 {
			return fmt.Errorf("--limit must be between 1 and 1000")
		}
		if flagSince != "" {
			if _, err := time.Parse(time.RFC3339, flagSince); err != nil {
				return fmt.Errorf("invalid --since %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", flagSince, err)
			}
		}
		c, err := client()
		if err != nil {
			return err
		}

		var cw *csv.Writer
		if flagCSV {
			cw = csv.NewWriter(cmd.OutOrStdout())
			_ = cw.Write([]string{
				"id", "event_time", "event_type", "actor", "actor_type",
				"user_id", "project_id", "secret_id", "ip_address", "success", "description",
			})
		}

		after := flagAfterID
		total := 0
		var lastCursor *uint
		for {
			q := url.Values{}
			q.Set("limit", strconv.Itoa(flagLimit))
			if after > 0 {
				q.Set("after_id", strconv.FormatUint(uint64(after), 10))
			}
			if flagSince != "" {
				q.Set("since", flagSince)
			}

			var page exportPage
			if err := c.Get(context.Background(), "/api/v1/audit/export?"+q.Encode(), &page); err != nil {
				return err
			}
			for _, e := range page.Events {
				if cw != nil {
					var row csvEventRow
					if err := json.Unmarshal(e, &row); err != nil {
						continue
					}
					_ = cw.Write([]string{
						strconv.FormatUint(uint64(row.ID), 10), row.Timestamp, common.CSVSafe(row.EventType),
						common.CSVSafe(row.Actor), row.ActorType, uintPtrStr(row.UserID), uintPtrStr(row.ProjectID),
						uintPtrStr(row.SecretID), common.CSVSafe(row.IPAddress), strconv.FormatBool(row.Success), common.CSVSafe(row.Description),
					})
					continue
				}
				// json.RawMessage from the server is already compact (no newlines) → NDJSON.
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(e))
			}
			total += len(page.Events)
			lastCursor = page.NextCursor

			if !flagAll || page.NextCursor == nil || len(page.Events) == 0 {
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
	},
}

// checkpointResult mirrors the /audit/checkpoint payload (ADR-029).
type checkpointResult struct {
	ID             uint   `json:"id"`
	ChainedEvents  int64  `json:"chained_events"`
	HeadID         uint   `json:"head_id"`
	HeadHash       string `json:"head_hash"`
	KeyVersion     string `json:"key_version"`
	AnchoredAt     string `json:"anchored_at"`
	AnchorProvider string `json:"anchor_provider"`
	// AnchorToken (base64) is the raw external-notary receipt (#182) — capture it
	// here, since checkpoints are normally written by the background scheduler and
	// this on-demand write may be the only time an operator sees this response.
	AnchorToken string `json:"anchor_token"`
}

var checkpointCmd = &cobra.Command{
	Use:   "checkpoint",
	Short: "Write a signed checkpoint of the current audit-chain head (ADR-029)",
	Long: `Sign a checkpoint of the current verified audit-chain head on demand, so
tail-truncation / genesis re-seed is detectable on-box. Checkpoints are normally
written by the server's background scheduler; run this to re-baseline immediately
— most often right after a DEK rotation, when 'audit verify' fails closed until a
fresh checkpoint is written under the new key.

Requires the server to have encryption enabled (the signing key is DEK-derived)
and the caller to hold system.write. The server refuses if the chain does not
verify (broken, or a prior signed checkpoint proves a truncation).`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error {
		c, err := client()
		if err != nil {
			return err
		}
		var out checkpointResult
		if err := c.Post(context.Background(), "/api/v1/audit/checkpoint", nil, &out); err != nil {
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
		}
		return nil
	},
}

// logEntry mirrors one row of the /audit/logs payload.
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

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Query the audit trail with filters (human-readable table)",
	Long: `Show audit events as a filtered table — for interactive investigation and
compliance spot-checks (e.g. who deleted secrets last week). For bulk/machine
consumption use 'keyorix audit export' (NDJSON) instead. Requires audit.read.`,
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, _ []string) error { return runLogsQuery() },
}

func runLogsQuery() error {
	q, err := buildAuditLogQuery()
	if err != nil {
		return err
	}
	c, err := client()
	if err != nil {
		return err
	}
	var page logsPage
	if err := c.Get(context.Background(), "/api/v1/audit/logs?"+q.Encode(), &page); err != nil {
		return err
	}
	if len(page.Logs) == 0 {
		fmt.Println("No audit events match.")
		return nil
	}
	printAuditLogTable(page.Logs, page.Total)
	return nil
}

func buildAuditLogQuery() (url.Values, error) {
	if logLimit < 1 || logLimit > 100 {
		return nil, fmt.Errorf("--limit must be between 1 and 100")
	}
	for label, v := range map[string]string{"--since": flagSince, "--until": logUntil} {
		if v != "" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return nil, fmt.Errorf("invalid %s %q (want RFC3339, e.g. 2026-06-01T00:00:00Z): %w", label, v, err)
			}
		}
	}
	if logActorType != "" && logActorType != "user" && logActorType != "machine_identity" && logActorType != "system" {
		return nil, fmt.Errorf("--actor-type must be user, machine_identity, or system")
	}
	q := url.Values{}
	q.Set("page_size", strconv.Itoa(logLimit))
	if logEventType != "" {
		q.Set("action", logEventType)
	}
	if logUserID > 0 {
		q.Set("user_id", strconv.FormatUint(uint64(logUserID), 10))
	}
	if logProjectID > 0 {
		q.Set("project_id", strconv.FormatUint(uint64(logProjectID), 10))
	}
	if logActorType != "" {
		q.Set("actor_type", logActorType)
	}
	if flagSince != "" {
		q.Set("start_time", flagSince)
	}
	if logUntil != "" {
		q.Set("end_time", logUntil)
	}
	return q, nil
}

func printAuditLogTable(logs []logEntry, total int64) {
	fmt.Printf("%-6s %-20s %-16s %-9s %-22s %s\n", "ID", "TIME", "ACTOR", "KIND", "EVENT", "DESCRIPTION")
	for _, e := range logs {
		actor := e.Actor
		if e.Impersonation && e.ImpersonatedBy != "" {
			actor = e.ImpersonatedBy + "→" + e.Actor
		}
		fmt.Printf("%-6d %-20s %-16s %-9s %-22s %s\n",
			e.ID, shortTime(e.Timestamp), truncate(actor, 16), e.ActorType, truncate(e.EventType, 22), e.Description)
	}
	fmt.Printf("\nShowing %d of %d total event(s).\n", len(logs), total)
}

// shortTime renders an RFC3339 timestamp as "2006-01-02 15:04:05" (UTC), or the
// raw string if it does not parse.
func shortTime(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
