// reconcile.go — the one place boot WRITES to the key set because of the
// manifest: finishing an interrupted operation it can finish, and recording a
// completed one whose manifest commit was lost. InspectKeySet decides;
// ReconcileKeySet acts. The caller must hold the exclusive key lock (the
// key-directory flock, or the key-initialisation advisory lock with
// key_dir_lock: database), and must call it before DEK-rotation crash recovery
// and Initialize, which then load the finished set.
package keyfiles

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// ReconcileResult reports what ReconcileKeySet found and did. Warnings are
// operator-facing sentences for the caller to log; Finished names the
// operation boot completed (non-empty only when files were renamed), for an
// audit event.
type ReconcileResult struct {
	Warnings []string
	Finished string
	Renamed  []FinishRename
	// Adopted lists the files recorded without a prior record: the whole set
	// when the manifest was missing or unparseable, otherwise the unrecorded
	// files. Non-empty means an audit event.
	Adopted []string
	// AdoptReason says why (for the audit event and the log line).
	AdoptReason string
}

// ReconcileKeySet runs InspectKeySet (returning its refusal unchanged) and
// then:
//
//   - IntentFinishable: renames each staging file into place (fsyncing the
//     directory after each) and commits the staged operation to the manifest.
//     The classification already proved each staging file holds exactly the
//     content the operation was about to write, so this is the rename the
//     operation itself would have done next.
//   - IntentCompleted: commits the staged operation (the files already have
//     the staged content; only the commit was lost).
//   - IntentAbandoned, or no intent: writes nothing, and warns about leftover
//     staging files.
//
// Whatever the intent, it first removes the staging files interrupted
// manifest writes left (removeManifestStagingFiles), with a warning each.
//
// fs is the write path (internal/encryption passes its fault-injectable one).
func ReconcileKeySet(enc *config.EncryptionConfig, baseDir string, fs ManifestFS) (*ReconcileResult, error) {
	st, err := InspectKeySet(enc, baseDir)
	if err != nil {
		return nil, err
	}
	res := &ReconcileResult{}
	if st.Fresh {
		return res, nil
	}
	if st.ManifestPath != "" {
		removeManifestStagingFiles(filepath.Dir(st.ManifestPath), res)
	}
	fs = fs.withDefaults()
	required, err := RequiredKeyFilePaths(enc, baseDir)
	if err != nil {
		return nil, err
	}
	if st.Manifest == nil {
		if err := adoptWholeSet(st, required, fs, res); err != nil {
			return nil, err
		}
		return res, nil
	}
	next := st.Manifest.Next
	switch st.Intent {
	case IntentFinishable:
		for _, r := range st.Finish {
			if err := fs.Rename(r.From, r.To); err != nil {
				return nil, fmt.Errorf("finish the interrupted %s: rename %s to %s: %w", next.Operation, r.From, r.To, err)
			}
			if err := fs.SyncDir(filepath.Dir(r.To)); err != nil {
				return nil, fmt.Errorf("finish the interrupted %s: fsync %s after renaming %s into place: %w", next.Operation, filepath.Dir(r.To), r.To, err)
			}
			res.Renamed = append(res.Renamed, r)
		}
		res.Finished = next.Operation
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"finished an interrupted %s from its staging files (generation %d in %s): the key set is now the one "+
				"that operation wrote — for rotate-kek that means the master passphrase is the NEW one given to rotate-kek",
			next.Operation, next.Generation, st.ManifestPath))
		fallthrough
	case IntentCompleted:
		files := map[string][]byte{}
		for _, f := range st.Files {
			if _, named := next.Files[f.Key]; !named {
				continue
			}
			data, rerr := readKeyFile(f.Path)
			if rerr != nil {
				return nil, fmt.Errorf("read %s to record the %s in the key-set manifest: %w", f.Path, next.Operation, rerr)
			}
			files[f.Path] = data
		}
		w := &SetWriter{manifestPath: st.ManifestPath, required: required, fs: fs}
		if err := w.CommitManifest(next.Operation, files); err != nil {
			if st.Intent == IntentFinishable {
				return nil, fmt.Errorf("finish the interrupted %s: record it in the key-set manifest: %w", next.Operation, err)
			}
			// Completed: the files are already right and the staged intent keeps
			// classifying them as completed, so the next start records it.
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"could not record the completed %s in %s (%v); the key set is coherent, the next start tries again",
				next.Operation, st.ManifestPath, err))
		}
	}

	if len(st.Unrecorded) > 0 {
		w := &SetWriter{manifestPath: st.ManifestPath, required: required, fs: fs}
		if err := w.CommitManifestFromDisk(OpAdopted, st.Unrecorded...); err != nil {
			res.Warnings = append(res.Warnings, adoptFailedWarning(strings.Join(st.Unrecorded, ", "), st.ManifestPath, err))
			return res, nil
		}
		res.Adopted = append(res.Adopted, st.Unrecorded...)
		res.AdoptReason = "not recorded in the key-set manifest (a key provider added to the configuration after the manifest was written)"
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%s were not recorded in the key-set manifest: recorded their current content in %s; from now on a "+
				"different version of them is refused",
			strings.Join(st.Unrecorded, ", "), st.ManifestPath))
	}

	dekPending := ""
	if path, err := ManifestPath(enc, baseDir); err == nil && path != "" && enc.DEKPath != "" {
		if clean, serr := SafePath("DEK", enc.DEKPath); serr == nil {
			dekPending = resolve(baseDir, clean) + ".pending"
		}
	}
	renamed := map[string]bool{}
	for _, r := range res.Renamed {
		renamed[r.From] = true
	}
	for _, l := range st.Leftovers {
		switch {
		case renamed[l]:
		case l == dekPending:
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s is left over from an interrupted DEK operation; the active key set is coherent without it, and the "+
					"DEK-rotation crash recovery that runs next promotes or discards it", l))
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s is a staging file left over from a key operation that was interrupted before it changed the active "+
					"key set; the set is coherent without it and the file can be deleted", l))
		}
	}
	return res, nil
}

// removeManifestStagingFiles deletes the staging files interrupted manifest
// writes left in dir (ManifestStagingFiles). Each write stages under its own
// name, so a leftover is never reused or overwritten by a later write and
// would otherwise stay, and keep `key-secret export` refusing, for good. No
// reader ever reads one: the manifest in place is the last committed one, and
// InspectKeySet has already classified the set against it. The caller holds
// the exclusive key lock, so no live write's staging file is among them (and
// if a broken lock let one through, that write's rename fails rather than
// committing anything torn). A file that cannot be removed (a read-only key
// directory) is reported instead.
func removeManifestStagingFiles(dir string, res *ReconcileResult) {
	staged, err := ManifestStagingFiles(dir)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("could not check for key-set manifest staging files: %v", err))
		return
	}
	for _, p := range staged {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"%s is a staging file left over from an interrupted key-set manifest write and could not be removed (%v); "+
					"the manifest in place is the last committed one, so the file can be deleted, and `key-secret export` "+
					"refuses this directory until it is", p, err))
			continue
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"removed %s, a staging file left over from an interrupted key-set manifest write; the manifest in place is "+
				"the last committed one", p))
	}
}

// adoptFailedWarning is the WARN when adoption cannot write the manifest
// (typically a read-only key directory: a Kubernetes Secret volume, or a
// read-only copy with key_dir_lock: database). Not a refusal: the set is then
// exactly as checked as it was before the manifest existed (presence only),
// which is no worse than the version being upgraded from.
func adoptFailedWarning(what, manifestPath string, err error) string {
	return fmt.Sprintf(
		"could not record %s in the key-set manifest %s (%v), so the key files are not checked for a mixed "+
			"generation on this start; on a read-only key directory, generate the manifest where the keys are "+
			"written and ship it with them",
		what, manifestPath, err)
}

// adoptWholeSet is warn-and-adopt (#2900 criterion 4) for a complete set
// whose manifest is missing — every install that predates the manifest, on
// its first start after the upgrade — or unparseable: record the current
// files as generation 1, once, and continue. The set's presence was already
// checked (a partial set never gets here). An unparseable manifest is moved
// aside, not overwritten, so it can be inspected.
//
// What adoption cannot know is whether the files it records belong together:
// it trusts the set as it is, exactly as every boot did before the manifest
// existed. The guarantee starts from this generation on.
func adoptWholeSet(st *KeySetState, required []string, fs ManifestFS, res *ReconcileResult) error {
	m, err := adoptFromDisk(filepath.Dir(st.ManifestPath), required, 1, true)
	if err != nil {
		return err
	}
	reason := "no key-set manifest (an install that predates it)"
	if !errors.Is(st.ManifestErr, ErrManifestMissing) {
		aside := fmt.Sprintf("%s.unparseable-%s", st.ManifestPath, time.Now().UTC().Format("20060102T150405Z"))
		if err := os.Rename(st.ManifestPath, aside); err != nil {
			res.Warnings = append(res.Warnings, adoptFailedWarning("the key set", st.ManifestPath, err))
			return nil
		}
		reason = fmt.Sprintf("the key-set manifest was unparseable (%v; moved aside to %s)", st.ManifestErr, aside)
	}
	if err := writeManifest(st.ManifestPath, m, fs); err != nil {
		res.Warnings = append(res.Warnings, adoptFailedWarning("the key set", st.ManifestPath, err))
		return nil
	}
	for _, f := range required {
		if _, ok := m.Files[manifestKey(filepath.Dir(st.ManifestPath), f)]; ok {
			res.Adopted = append(res.Adopted, f)
		}
	}
	res.AdoptReason = reason
	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"%s: adopted the current key files (%s) as generation 1 of %s, trusting them as they are; from now on a "+
			"key file from another generation is refused at boot",
		reason, strings.Join(res.Adopted, ", "), st.ManifestPath))
	return nil
}
