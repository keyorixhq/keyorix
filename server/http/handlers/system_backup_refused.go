package handlers

import (
	"log"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// backupRefusedReasonCheckFailed is BackupRefusedStatus.Reason when the
// staging-file check itself failed: `admin backup` refuses then too (exit 1).
const backupRefusedReasonCheckFailed = "staging-file-check-failed"

// BackupRefusedStatus is security.backup_refused in GET /api/v1/system/info
// (#4105): `keyorix-server admin backup` against this server's key directory
// is refused, so scheduled backups have stopped until someone acts. The backup
// refuses before it opens storage and writes no audit event; this is the
// signal a monitor can poll. Omitted while backups are not refused.
//
// It reads the key directory of the replica answering the request (each
// replica has its own), with keyfiles.PendingRotationFiles, the same check the
// backup runs, so the two cannot disagree. It only stats the files: it never
// opens, moves or deletes one (a DEK's staging file can be the only copy of the
// new DEK). The database side of the backup gate needs the KEK and is not
// evaluated here.
type BackupRefusedStatus struct {
	// Reason: "key-rotation-staging-file" (keyfiles.BackupRefusedReasonStagingFile,
	// also the reason= of the backup's keyorix-backup-refused stderr line; the
	// backup exits 4) or "staging-file-check-failed" (exit 1).
	Reason string `json:"reason"`
	// Files are the staging files present, as the backup names them.
	Files []string `json:"files,omitempty"`
	// StagingSaltOnly: only the KEK salt's staging file is present. Once this
	// server has started with it in place it is unused, and moving it out of
	// the key directory (no rotate-kek running) restores backups.
	StagingSaltOnly bool `json:"staging_salt_only,omitempty"`
	// Remedy is the operator's next step, in one sentence.
	Remedy string `json:"remedy"`
}

// Remedy texts. Full steps: `keyorix-server admin validate --posture` and
// docs/operator/j6-key-rotation.md.
const (
	backupRefusedRemedySalt = "Check that no `admin encryption rotate-kek` is running, then move the staging file out of the key " +
		"directory (do not delete it yet) and back up again; `keyorix-server admin validate --posture` prints the full steps."
	backupRefusedRemedyDEK = "A key rotation is running or was interrupted: wait for it to finish, or restart the server so boot " +
		"recovery completes it, then back up again. Never delete a DEK's .pending file by hand: it can be the only copy of the new DEK."
	backupRefusedRemedyCheckFailed = "Fix the key directory so its staging files can be checked; the server log names the error."
)

// backupRefusedStatus returns this replica's BackupRefusedStatus, or nil while
// a backup would not be refused for a staging file.
func backupRefusedStatus(enc *config.EncryptionConfig) *BackupRefusedStatus {
	pending, err := keyfiles.PendingRotationFiles(enc, ".")
	if err != nil {
		// The path can name the host's layout: logged, not returned.
		log.Printf("WARNING: system info: could not check for key-rotation staging files (admin backup refuses too): error=%q", err.Error())
		return &BackupRefusedStatus{Reason: backupRefusedReasonCheckFailed, Remedy: backupRefusedRemedyCheckFailed}
	}
	if len(pending) == 0 {
		return nil
	}
	st := &BackupRefusedStatus{Reason: keyfiles.BackupRefusedReasonStagingFile, StagingSaltOnly: true, Remedy: backupRefusedRemedySalt}
	for _, p := range pending {
		st.Files = append(st.Files, p.Path)
		if !p.Salt {
			st.StagingSaltOnly = false
			st.Remedy = backupRefusedRemedyDEK
		}
	}
	return st
}
