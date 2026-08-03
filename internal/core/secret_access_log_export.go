// secret_access_log_export.go — ExportSecretAccessLog: serialise a secret's
// access history (secret.read audit events) to CSV or JSON for download.
package core

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	ExportFormatCSV    = "csv"
	ExportFormatJSON   = "json"
	exportAccessAction = "secret.read"
	// ExportMaxRows is the hard cap on rows returned by ExportSecretAccessLog.
	// Callers needing more should use the paginated SearchAuditLogs instead.
	ExportMaxRows = 10_000
)

// AccessLogExportRow is a single row in a secret access-log export.
type AccessLogExportRow struct {
	EventID   uint      `json:"event_id"`
	SecretID  uint      `json:"secret_id"`
	UserID    *uint     `json:"user_id,omitempty"`
	ActorType string    `json:"actor_type"`
	IPAddress string    `json:"ip_address"`
	Success   bool      `json:"success"`
	EventTime time.Time `json:"event_time"`
}

// ExportSecretAccessLog fetches up to ExportMaxRows secret.read audit events
// for secretID and serialises them to the requested format (csv or json).
// Returns the encoded bytes and the MIME content-type.
// An unrecognised format or a non-existent secret returns an error.
//
// Authorization contract: callers must verify that the requesting user holds
// secrets.read permission for this secret before calling this function.
// The HTTP handler enforces this via RequireScopedPermission; other transports
// (gRPC, CLI) must enforce it independently. This function does NOT check
// per-user read permission itself.
func (k *KeyorixCore) ExportSecretAccessLog(ctx context.Context, secretID uint, format string) ([]byte, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format != ExportFormatCSV && format != ExportFormatJSON {
		return nil, "", fmt.Errorf("unsupported export format %q: must be csv or json", format)
	}

	// Verify the secret exists before querying audit events.
	if _, err := k.storage.GetSecret(ctx, secretID); err != nil {
		return nil, "", fmt.Errorf("secret not found")
	}

	action := exportAccessAction
	events, _, err := k.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		SecretID:  &secretID,
		Action:    &action,
		Page:      1,
		PageSize:  ExportMaxRows,
		Ascending: true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("ExportSecretAccessLog: %w", err)
	}

	rows := make([]AccessLogExportRow, 0, len(events))
	for _, e := range events {
		success := e.Success == nil || *e.Success
		secID := secretID
		if e.SecretNodeID != nil {
			secID = *e.SecretNodeID
		}
		rows = append(rows, AccessLogExportRow{
			EventID:   e.ID,
			SecretID:  secID,
			UserID:    e.UserID,
			ActorType: e.ActorType,
			IPAddress: e.IPAddress,
			Success:   success,
			EventTime: e.EventTime,
		})
	}

	if format == ExportFormatCSV {
		return encodeCSV(rows), "text/csv; charset=utf-8", nil
	}
	data, err := json.Marshal(rows)
	return data, "application/json; charset=utf-8", err
}

func encodeCSV(rows []AccessLogExportRow) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// bytes.Buffer.Write never returns an error; ignore return values.
	_ = w.Write([]string{"event_id", "secret_id", "user_id", "actor_type", "ip_address", "success", "event_time"})
	for _, r := range rows {
		userID := ""
		if r.UserID != nil {
			userID = fmt.Sprintf("%d", *r.UserID)
		}
		_ = w.Write([]string{
			fmt.Sprintf("%d", r.EventID),
			fmt.Sprintf("%d", r.SecretID),
			userID,
			r.ActorType,
			r.IPAddress,
			fmt.Sprintf("%t", r.Success),
			r.EventTime.UTC().Format(time.RFC3339),
		})
	}
	w.Flush()
	return buf.Bytes()
}
