package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1: --force lets an admin command run without
// the exclusive database lock, beside a live server. That fact was printed to
// stdout only; the audit event the command wrote read exactly like a guarded
// run. A forced, unguarded run must say so in its own audit event, and a run
// that got the lock despite --force must not.
func TestForcedRunWithoutTheLock_IsRecordedInItsAuditEvent(t *testing.T) {
	for _, tc := range []struct {
		name         string
		serverHolds  bool
		wantBypassed bool
	}{
		{"server holds the presence lock", true, true},
		{"lock free, --force unused", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "secrets.db")
			cfgPath := writeAdminFuzzConfig(t, dir, "keyorix.yaml", dbPath, true)
			t.Chdir(dir)
			t.Setenv("KEYORIX_MASTER_PASSWORD", "force-bypass-audit-test-passphrase")
			oldCfg, oldForce := configPathFlag, forceFlag
			t.Cleanup(func() { configPathFlag, forceFlag = oldCfg, oldForce })
			configPathFlag, forceFlag = cfgPath, true

			if tc.serverHolds {
				p, err := serverguard.AcquirePresence(probeCfg(dbPath))
				if err != nil {
					t.Fatalf("AcquirePresence: %v", err)
				}
				defer p.Release() //nolint:errcheck
			}
			if err := runAdminMigrate(migrateCmd, nil); err != nil {
				t.Fatalf("admin migrate --force: %v", err)
			}

			db, err := storage.OpenGormDB(probeCfg(dbPath))
			if err != nil {
				t.Fatal(err)
			}
			defer closeGormDB(db)
			var ev models.AuditEvent
			if err := db.Where("event_type = ?", "admin.migrate").Last(&ev).Error; err != nil {
				t.Fatalf("read the admin.migrate audit event: %v", err)
			}
			bypassed := strings.Contains(ev.Description, "--force") && strings.Contains(ev.Description, "WITHOUT the exclusive database lock")
			if bypassed != tc.wantBypassed {
				t.Fatalf("audit event %q: records a --force lock bypass = %v, want %v", ev.Description, bypassed, tc.wantBypassed)
			}
		})
	}
}

// TestEveryAdminAuditEventCarriesTheLockBypassNote: the family guard for the
// test above. Every models.AuditEvent composite literal (with or without &) in
// this package's non-test files sets Description to withLockBypassNote(...),
// and no file assigns an event's Description afterwards. Recognised shapes:
// those two only; an event built by another package's helper from here would
// not be seen (none exists today: every write is store.LogAuditEvent on a
// literal in this package).
func TestEveryAdminAuditEventCarriesTheLockBypassNote(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	literals := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				sel, ok := n.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "AuditEvent" {
					return true
				}
				literals++
				wrapped := false
				for _, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Description" {
						if call, ok := kv.Value.(*ast.CallExpr); ok {
							if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "withLockBypassNote" {
								wrapped = true
							}
						}
					}
				}
				if !wrapped {
					t.Errorf("%s: models.AuditEvent literal without Description: withLockBypassNote(...)", fset.Position(n.Pos()))
				}
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Description" {
						t.Errorf("%s: assigns .Description after the literal (not recognised by this guard)", fset.Position(n.Pos()))
					}
				}
			}
			return true
		})
	}
	if literals == 0 {
		t.Fatal("found no models.AuditEvent literal: the guard is looking in the wrong place")
	}
}
