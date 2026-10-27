package keyfiles

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// manifestWriterPackages are the packages that write key material into the
// active key set (#2900 acceptance criterion 6): internal/encryption (first
// boot, rotate-kek, rotate-dek and its recovery, migrate-provider's re-wrap),
// internal/encryptionops (the testable core of the `admin encryption`
// commands: migrate-provider's rollback, shamir-split) and server/admin
// (restore).
var manifestWriterPackages = []string{"internal/encryption", "internal/encryptionops", "server/admin"}

// keyWriteForms are the call forms this guard recognises as a file write. The
// list was derived by grepping these three packages for every call that
// creates, replaces or renames a file (2026-10-23); a write through any other
// form — a helper in another package, (*os.File).Write on a handle opened
// elsewhere, io.Copy — is invisible to it.
//
// Not covered, by construction: the KEK providers in internal/crypto
// (password salt, KMS/TPM blob). They write only when their file does not
// exist yet (first run), inside Initialize, and the first-boot commit in
// ensureWrappedDEKExists records what they wrote;
// TestFirstBoot_ManifestRecordsProviderFiles in internal/encryption checks that.
var keyWriteForms = []string{
	"os.WriteFile", "os.Rename", "os.Link",
	"securefiles.SecureWriteFileSync", "securefiles.SecureCreateFileSync",
	"durableWriteSync", "durableRename", // internal/encryption's fault-injectable primitives
	"CopyFile",           // internal/encryptionops
	"commitRestoredFile", // server/admin's per-file install primitive
}

// manifestUpdateForms are the calls that count as updating the manifest. The
// names are specific to keyfiles.SetWriter and KeyManager's wrappers around
// it, so an unrelated method (a database tx.Commit) cannot satisfy the guard.
var manifestUpdateForms = []string{
	"StageManifest", "CommitManifest", "CommitManifestFromDisk",
	"stageKeySet", "commitKeySet", "commitKeySetFromDisk",
}

// manifestWriterExemptions are the functions that use a write form but do not
// write into the active key set, each with the reason. Keyed "pkg-dir:Func"
// ("Type.Method" for methods). An entry whose function no longer exists or no
// longer writes fails the guard, so this list cannot go stale silently.
var manifestWriterExemptions = map[string]string{
	// The write primitives themselves; every caller is checked instead.
	"internal/encryption:durableWriteSync": "fault-injectable write primitive",
	"internal/encryption:durableRename":    "fault-injectable rename primitive",
	"internal/encryption:manifestFS":       "the manifest's own write path (writes keyset.manifest.json, not a key file)",
	"server/admin:commitRestoredFile":      "per-file install primitive; its callers are checked",
	"server/admin:installJournalEntry":     "installs restore-journal entries only; every key-file entry of a journal is staged by prepareRestoredKeySet, which stages the key-set manifest recording them as one more entry of the same set, installed in the same step (TestPrepareRestoredKeySet_StagesTheManifestWithTheKeyFiles, TestAdminRestore_Overwrite_KillPoints)",
	// Writes that are not active key material.
	"internal/encryption:KeyManager.ensureSaltExists": "legacy no-provider salt, unreachable from production (Service always sets a provider); the first-boot commit in ensureWrappedDEKExists, which always follows in the same Initialize, records it",
	"internal/encryptionops:ShamirSplitWithConfig":    "writes new shares into an empty --out-dir with O_EXCL and never touches the active set; the shares enter it through migrate-provider, which records the target set",
	"internal/encryptionops:CreateMigrateBackup":      "creates only a new .migrate-backup copy (O_EXCL), never an active key file; migrate-provider's re-wrap and target set are recorded by RewrapDEK and the CommitManifestFromDisk at the end",
	"server/admin:writeRestoredFile":                  "the restored database file, not key material",
	"server/admin:moveAsideSQLiteDB":                  "moves the database and its WAL sidecars aside",
	"internal/encryptionops:writeKeySecret":           "writes a Kubernetes Secret manifest file (or stdout), not a file of a key directory",
	"internal/encryptionops:UnpackKeySecret":          "unpacks a Secret into an empty workspace directory (O_EXCL), never into the active set of an install; the Secret carries the key-set manifest its exporter wrote (TestKeySecret_GenerateThenUnpack_OpensWithTheSamePassphrase), and one without a manifest is adopted by the first key writer or server start there (ReconcileKeySet)",
	"server/admin:auditEventCountFromDBBytes":         "a private temporary copy of an archived database",
	"server/admin:liveKeyMaterial":                    "stages a copy of the key files in a temporary directory to unwrap the backup-manifest key",
	"server/admin:stageKeyFilesForKEKUnwrap":          "stages the archive's key files in a temporary directory to unwrap the backup-manifest key",
	"server/admin:generateAdminConfigFile":            "writes the config template",
	"server/admin:createPrivateFile":                  "writes init's secret files (passwords, tokens), not key material",
}

func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func callName(call *ast.CallExpr) (full, short string) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, fn.Name
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return id.Name + "." + fn.Sel.Name, fn.Sel.Name
		}
		return fn.Sel.Name, fn.Sel.Name
	}
	return "", ""
}

// TestEveryKeyMaterialWriterUpdatesTheManifest is #2900's structural guard:
// every function in manifestWriterPackages that calls a keyWriteForms form
// also calls a manifestUpdateForms form, or is in manifestWriterExemptions
// with the reason it does not write the active key set.
//
// What it proves: no NEW writer can appear in these packages, using a
// recognised form, without either updating the manifest or someone writing
// down why not. What it does not prove: that the update covers the same
// files as the write (the behavioural tests do that per writer), or anything
// about a write form not in keyWriteForms.
//
// It reports through guardrules.Rollout: report-only on pull requests while
// docs/guard-rollout.d/TestEveryKeyMaterialWriterUpdatesTheManifest.tsv exists
// (docs/guard-rollout-contract.md rule 2).
func TestEveryKeyMaterialWriterUpdatesTheManifest(t *testing.T) {
	g := guardrules.Rollout(t)
	root := repoRoot(t)
	seen := map[string]bool{}
	var offenders []string
	for _, pkg := range manifestWriterPackages {
		dir := filepath.Join(root, pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			g.Fatalf("read %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				g.Fatalf("parse %s/%s: %v", pkg, name, err)
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var writes []string
				updates := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					full, short := callName(call)
					if slices.Contains(keyWriteForms, full) || slices.Contains(keyWriteForms, short) && !strings.Contains(full, ".") {
						writes = append(writes, full)
					}
					if slices.Contains(manifestUpdateForms, short) {
						updates = true
					}
					return true
				})
				if len(writes) == 0 {
					continue
				}
				key := pkg + ":" + funcKey(fd)
				seen[key] = true
				if updates {
					continue
				}
				if _, ok := manifestWriterExemptions[key]; ok {
					continue
				}
				offenders = append(offenders, key+" ("+strings.Join(writes, ", ")+")")
			}
		}
	}
	for _, o := range offenders {
		g.Errorf("%s writes a file but never updates the key-set manifest: call SetWriter.StageManifest before replacing an active key file and CommitManifest after (internal/keyfiles/manifest.go), or add it to manifestWriterExemptions with the reason it does not touch the active key set", o)
	}
	for key := range manifestWriterExemptions {
		if !seen[key] {
			g.Errorf("manifestWriterExemptions has %q, which no longer exists or no longer uses a recognised write form: remove the entry", key)
		}
	}
}
