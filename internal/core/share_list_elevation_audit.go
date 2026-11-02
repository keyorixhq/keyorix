// share_list_elevation_audit.go — one share_access_elevated row per share-list call
// (#3456).
//
// The share lists (GET /shares, GET /shares/owned: ListUserShareViews,
// ListOwnedShareViews) name each secret the caller may read (annotateShareViewSecrets).
// For a recipient whose role does not grant secrets.read, a share makes that read
// possible, so the decision is a share elevation. The lists run with no request
// recorder, and noteShareElevation audits a read elevation at once when there is none,
// so one list call wrote one share_access_elevated row per such secret on the page:
// a page of 500 received shares, 500 rows, every time the page was opened.
//
// The action performed is ONE list call, so it is audited as one row: the list's
// batch decision runs with a private recorder (shareListElevations), and what it
// collected is written as a single share_access_elevated event with action
// shares.list, the count, and the (secret, share) pairs up to
// shareListElevationDetailCap. Nothing changes for a real elevated use of one secret
// (a read of its value, an allowlisted write): that is still decided by
// AuthorizeSecretAction and audited per action as before. A list whose callers' roles
// already grant every read writes nothing, as before.
//
// The row is written when core returns the list, which is when the per-row rows were
// written too; a transport refusal after that (the aggregate MFA check) does not
// un-write it. The list's batch never sees the transport's own recorder, if there is
// one: the list's elevations are this row, not rows committed per secret.
package core

import (
	"context"
	"encoding/json"
	"fmt"
)

// shareListElevationAction names the action of the summary row.
const shareListElevationAction = "shares.list"

// shareListElevationDetailCap bounds how many (secret, share) pairs the summary row
// lists, so the payload stays well under auditDiffMaxLen (8 KiB; a cut Diff is no
// longer JSON). Count always carries the full number; Truncated says the list was cut.
const shareListElevationDetailCap = 50

// shareListElevationDetail is the structured payload of the summary row.
type shareListElevationDetail struct {
	Action     string                    `json:"action"`
	Permission string                    `json:"permission"`
	Count      int                       `json:"count"`
	Truncated  bool                      `json:"truncated"`
	Elevations []shareListElevationEntry `json:"elevations"`
}

type shareListElevationEntry struct {
	SecretID        uint   `json:"secret_id"`
	ShareID         uint   `json:"share_id"`
	SharePermission string `json:"share_permission"`
	Source          string `json:"source"`
}

// shareListElevations returns ctx carrying a fresh recorder for one list's batch
// decision. Unlike WithShareElevationRecorder it creates no gate read-decision memo:
// the list is not a per-secret request and has no gate decision to hand on.
func shareListElevations(ctx context.Context) (context.Context, *ShareElevationRecorder) {
	rec := &ShareElevationRecorder{}
	return context.WithValue(ctx, shareElevationRecorderKey{}, rec), rec
}

// writeShareListElevationSummary writes the one share_access_elevated row of a list
// call for the elevations rec collected, or nothing when there are none.
// Best-effort like every audit write: the list has already been built.
func (c *KeyorixCore) writeShareListElevationSummary(ctx context.Context, userID uint, perm string, rec *ShareElevationRecorder) {
	es := rec.drain()
	if len(es) == 0 {
		return
	}
	d := shareListElevationDetail{Action: shareListElevationAction, Permission: perm, Count: len(es)}
	for i, e := range es {
		if i == shareListElevationDetailCap {
			d.Truncated = true
			break
		}
		d.Elevations = append(d.Elevations, shareListElevationEntry{
			SecretID: e.secretID, ShareID: *e.grant.ShareID,
			SharePermission: string(e.grant.Level), Source: e.grant.Source,
		})
	}
	detail, _ := json.Marshal(d)
	uid := userID
	desc := fmt.Sprintf("%s: %d secret(s) on the list readable only under a share; the actor's role alone does not grant %s",
		shareListElevationAction, len(es), perm)
	c.writeAuditEventDiff(ctx, string(ShareAuditEventAccessElevated), &uid, nil, nil, "", desc, string(detail))
}
