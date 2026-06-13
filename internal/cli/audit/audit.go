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
)

func init() {
	verifyCmd.Flags().BoolVar(&flagJSON, "json", false, "Emit the raw verification result as JSON (for recording the external anchor)")

	exportCmd.Flags().StringVar(&flagSince, "since", "", "Only export events at/after this time (RFC3339)")
	exportCmd.Flags().UintVar(&flagAfterID, "after-id", 0, "Resume after this event id (exclusive cursor)")
	exportCmd.Flags().IntVar(&flagLimit, "limit", 100, "Events per page (1–1000)")
	exportCmd.Flags().BoolVar(&flagAll, "all", false, "Follow the cursor to the end, emitting every event")

	AuditCmd.AddCommand(verifyCmd, exportCmd)
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

		if lastCursor != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); resume with --after-id %d\n", total, *lastCursor)
		} else {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "exported %d event(s); caught up\n", total)
		}
		return nil
	},
}
