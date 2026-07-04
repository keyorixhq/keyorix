// local_access_activity.go — last-secret-access timestamps per user, for
// dormant-access detection in the access review. For the remote equivalent see
// remote_access_activity.go (server-side only).
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// accessActivityEventTypes are the audit event types that count as "using" access
// to a project's secrets (so a grant whose principal never triggers one is dormant).
//
// Every secret read — whether the reader is the owner or a share recipient — is
// audited generically as "secret.read" (see LogSecretReadWithProject); there is
// currently no separate event type for a share-sourced read, so only "secret.read"
// is listed here. A prior "shared_secret_accessed" entry was removed (#418): the
// writer that would have produced it was dead code with no caller other than its
// own unit test, so the event never actually occurred and this list never matched
// it in practice.
var accessActivityEventTypes = []string{"secret.read"}

// LastUserSecretActivity returns the most recent secret-access time per user in the
// project, read from audit_events (where the read events carry user_id + project_id).
//
// It selects the typed event_time column ordered newest-first and keeps the first
// row seen per user (rather than SQL MAX(), whose result is an untyped string that
// SQLite can't scan into time.Time). No row cap — a user's only activity could be
// old, and capping would mis-report them as never-active (a silent-truncation bug).
func (ls *LocalStorage) LastUserSecretActivity(ctx context.Context, projectID uint) (map[uint]time.Time, error) {
	type row struct {
		UserID    uint
		EventTime time.Time
	}
	var rows []row
	err := ls.db.WithContext(ctx).
		Table("audit_events").
		Select("user_id, event_time").
		Where("project_id = ?", projectID).
		Where("event_type IN ?", accessActivityEventTypes).
		Where("user_id IS NOT NULL").
		Order("event_time DESC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	out := make(map[uint]time.Time)
	for _, r := range rows {
		if r.UserID == 0 {
			continue
		}
		if _, seen := out[r.UserID]; !seen { // first seen = latest (DESC order)
			out[r.UserID] = r.EventTime
		}
	}
	return out, nil
}
