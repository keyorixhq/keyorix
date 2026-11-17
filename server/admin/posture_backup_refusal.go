package admin

import (
	"errors"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
)

// collectBackupRefusalPosture reports, as a deviation, that `admin backup` would
// be refused because a key-rotation staging file is present (#4105). The refusal
// runs before storage is opened and writes no audit event, so under cron with
// stderr discarded backups just stop; this makes the state visible (and the
// posture exit code non-zero) until the file is gone. It calls the backup's own
// check, so the two cannot disagree. Only that local check: the database side
// of the backup gate (refuseBackupDEKBehindDatabase) needs the KEK and is not
// evaluated here.
func collectBackupRefusalPosture(cfg *config.Config, report *postureReport) {
	err := refusePendingKeyRotation(cfg)
	if err == nil {
		return
	}
	if r, ok := errors.AsType[*pendingRotationRefusal](err); ok {
		report.deviate("backup", fmt.Sprintf("backups are refused: key-rotation staging file present (%s). %s",
			strings.Join(r.paths, ", "), r.msg))
		return
	}
	report.deviate("backup", fmt.Sprintf("backups are refused: %v", err))
}
