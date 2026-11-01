//go:build ignore

// scalegen is the data-set generator of scripts/migrate/scale-check.sh (SCALE-OPS-1).
// Like scripts/migrate/migratecheck it is a fixture tool, not part of any shipped
// binary or `go build ./...` target (the //go:build ignore tag).
//
//	scalegen seed --config keyorix.yaml [--audit N] [--secrets N] [--versions V] [--access-logs N]
//	              [--users N] [--shares N] [--projects N]
//
// It fills an initialised, migrated instance (`admin init`, `admin encryption init`,
// `admin migrate` already run, server NOT running) in bulk through the store's own
// models: projects with one environment each, users, secret nodes with V versions
// each (random ciphertext of a realistic size: the data set exercises row volume,
// not decryption), shares, secret access-log rows and a chained audit log. The
// audit chain is built with the exported store.ComputeAuditEntryHash, linked onto
// the current head in id order, so `admin verify-audit` accepts it exactly as it
// accepts rows written by the server (the check script runs verify-audit on the
// seeded source before it measures anything).
//
// Re-running appends: names carry the run's tag so they stay unique.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	insertBatch = 500
)

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "scalegen: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "seed" {
		fatalf("usage: scalegen seed --config <file> [--audit N] [--secrets N] [--versions V] [--access-logs N] [--users N] [--shares N] [--projects N]")
	}
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	cfgPath := fs.String("config", "keyorix.yaml", "config file")
	audit := fs.Int("audit", 0, "audit events to append (chained)")
	secrets := fs.Int("secrets", 0, "secret nodes")
	versions := fs.Int("versions", 3, "versions per secret")
	accessLogs := fs.Int("access-logs", 0, "secret_access_logs rows")
	users := fs.Int("users", 0, "users")
	shares := fs.Int("shares", 0, "share records")
	projects := fs.Int("projects", 10, "projects (each with one environment)")
	valueBytes := fs.Int("value-bytes", 256, "size of each version's ciphertext")
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	if cfg.Storage.Type == "" {
		cfg.Storage.Type = "local"
	}
	if err := i18n.Initialize(cfg); err != nil {
		fatalf("i18n: %v", err)
	}
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		fatalf("open db: %v", err)
	}
	tag := fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff)
	start := time.Now()
	progress := func(what string, done, total int) {
		if total >= 10*insertBatch && done%(20*insertBatch) == 0 && done > 0 {
			fmt.Fprintf(os.Stderr, "scalegen: %s %d/%d (%s)\n", what, done, total, time.Since(start).Round(time.Second))
		}
	}

	projectIDs, envIDs := seedProjects(gdb, *projects, tag)
	userIDs := seedUsers(gdb, *users, tag, progress)
	nodeIDs := seedSecrets(gdb, *secrets, *versions, *valueBytes, projectIDs, envIDs, tag, progress)
	seedShares(gdb, *shares, nodeIDs, userIDs, progress)
	seedAccessLogs(gdb, *accessLogs, nodeIDs, progress)
	seedAudit(gdb, *audit, projectIDs, userIDs, nodeIDs, tag, progress)
	fmt.Printf("scalegen: seeded projects=%d users=%d secrets=%d versions/secret=%d shares=%d access_logs=%d audit=%d in %s\n",
		len(projectIDs), len(userIDs), len(nodeIDs), *versions, *shares, *accessLogs, *audit, time.Since(start).Round(time.Second))
}

func batches(n int, fn func(from, to int) error) {
	for from := 0; from < n; from += insertBatch {
		to := min(from+insertBatch, n)
		if err := fn(from, to); err != nil {
			fatalf("insert rows %d-%d: %v", from, to, err)
		}
	}
}

func seedProjects(gdb *gorm.DB, n int, tag string) (projectIDs, envIDs []uint) {
	for i := 0; i < n; i++ {
		p := &models.Project{Name: fmt.Sprintf("scale-%s-%d", tag, i)}
		if err := gdb.Create(p).Error; err != nil {
			fatalf("project: %v", err)
		}
		e := &models.Environment{ProjectID: p.ID, Name: "prod"}
		if err := gdb.Create(e).Error; err != nil {
			fatalf("environment: %v", err)
		}
		projectIDs = append(projectIDs, p.ID)
		envIDs = append(envIDs, e.ID)
	}
	return projectIDs, envIDs
}

func seedUsers(gdb *gorm.DB, n int, tag string, progress func(string, int, int)) []uint {
	rows := make([]models.User, n)
	for i := range rows {
		name := fmt.Sprintf("scale-%s-user-%d", tag, i)
		rows[i] = models.User{Username: name, UsernameFolded: name, Email: name + "@example.invalid", EmailFolded: name + "@example.invalid",
			DisplayName: name, IsActive: true}
	}
	batches(n, func(from, to int) error {
		progress("users", from, n)
		return gdb.Create(rows[from:to]).Error
	})
	ids := make([]uint, n)
	for i := range rows {
		ids[i] = rows[i].ID
	}
	return ids
}

func seedSecrets(gdb *gorm.DB, n, versions, valueBytes int, projectIDs, envIDs []uint, tag string, progress func(string, int, int)) []uint {
	if n > 0 && len(projectIDs) == 0 {
		fatalf("--secrets needs --projects > 0")
	}
	ids := make([]uint, 0, n)
	now := time.Now().UTC()
	blob := make([]byte, valueBytes)
	for from := 0; from < n; from += insertBatch {
		to := min(from+insertBatch, n)
		nodes := make([]models.SecretNode, 0, to-from)
		for i := from; i < to; i++ {
			nodes = append(nodes, models.SecretNode{ProjectID: projectIDs[i%len(projectIDs)], EnvironmentID: envIDs[i%len(projectIDs)],
				Name: fmt.Sprintf("secret-%s-%d", tag, i), IsSecret: true, Type: "password", Status: "active", CreatedBy: "scalegen"})
		}
		if err := gdb.Create(&nodes).Error; err != nil {
			fatalf("secret nodes: %v", err)
		}
		vers := make([]models.SecretVersion, 0, len(nodes)*versions)
		for _, nd := range nodes {
			ids = append(ids, nd.ID)
			for v := 1; v <= versions; v++ {
				_, _ = rand.Read(blob)
				vers = append(vers, models.SecretVersion{SecretNodeID: nd.ID, VersionNumber: v, EncryptedValue: append([]byte(nil), blob...),
					EncryptionMetadata: models.JSON(`{"scalegen":true}`), CreatedAt: now})
			}
		}
		for i := 0; i < len(vers); i += insertBatch {
			if err := gdb.Create(vers[i:min(i+insertBatch, len(vers))]).Error; err != nil {
				fatalf("secret versions: %v", err)
			}
		}
		progress("secrets", to, n)
	}
	return ids
}

func seedShares(gdb *gorm.DB, n int, nodeIDs, userIDs []uint, progress func(string, int, int)) {
	if n == 0 {
		return
	}
	if len(nodeIDs) == 0 || len(userIDs) == 0 {
		fatalf("--shares needs --secrets > 0 and --users > 0")
	}
	rows := make([]models.ShareRecord, n)
	for i := range rows {
		rows[i] = models.ShareRecord{SecretID: nodeIDs[i%len(nodeIDs)], OwnerID: userIDs[i%len(userIDs)],
			RecipientID: userIDs[(i+1)%len(userIDs)], Permission: "read"}
	}
	batches(n, func(from, to int) error {
		progress("shares", from, n)
		return gdb.Create(rows[from:to]).Error
	})
}

func seedAccessLogs(gdb *gorm.DB, n int, nodeIDs []uint, progress func(string, int, int)) {
	if n == 0 {
		return
	}
	if len(nodeIDs) == 0 {
		fatalf("--access-logs needs --secrets > 0")
	}
	base := time.Now().UTC().Add(-time.Duration(n) * time.Second)
	batches(n, func(from, to int) error {
		progress("access logs", from, n)
		rows := make([]models.SecretAccessLog, 0, to-from)
		for i := from; i < to; i++ {
			rows = append(rows, models.SecretAccessLog{SecretNodeID: nodeIDs[i%len(nodeIDs)], SecretVersionID: 1, AccessedBy: "scalegen",
				AccessTime: base.Add(time.Duration(i) * time.Second), Action: "read", IPAddress: "10.0.0.1", UserAgent: "scalegen"})
		}
		return gdb.Create(rows).Error
	})
}

// seedAudit links n events onto the chain head in id order.
func seedAudit(gdb *gorm.DB, n int, projectIDs, userIDs, nodeIDs []uint, tag string, progress func(string, int, int)) {
	if n == 0 {
		return
	}
	var head models.AuditEvent
	prev := genesisHash
	if err := gdb.Where("entry_hash != ''").Order("id DESC").Limit(1).Find(&head).Error; err != nil {
		fatalf("audit head: %v", err)
	}
	if head.ID != 0 {
		prev = head.EntryHash
	}
	types := []string{"secret.read", "secret.updated", "auth.login", "share.created", "rbac.role_assigned", "project.created"}
	// events are older than "now" so the instance's own later events sort after them
	base := time.Now().UTC().Add(-time.Duration(n+60) * time.Second).Truncate(time.Microsecond)
	ok := true
	batches(n, func(from, to int) error {
		progress("audit events", from, n)
		rows := make([]models.AuditEvent, 0, to-from)
		for i := from; i < to; i++ {
			ev := models.AuditEvent{EventType: types[i%len(types)], IPAddress: "10.0.0.1", Description: fmt.Sprintf("scalegen %s event %d", tag, i),
				Success: &ok, EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user"}
			if len(projectIDs) > 0 {
				pid := projectIDs[i%len(projectIDs)]
				ev.ProjectID = &pid
			}
			if len(userIDs) > 0 {
				uid := userIDs[i%len(userIDs)]
				ev.UserID = &uid
			}
			if len(nodeIDs) > 0 && i%len(types) < 2 {
				nid := nodeIDs[i%len(nodeIDs)]
				ev.SecretNodeID = &nid
			}
			ev.PrevHash = prev
			ev.EntryHash = store.ComputeAuditEntryHash(&ev, prev)
			prev = ev.EntryHash
			rows = append(rows, ev)
		}
		return gdb.Create(rows).Error
	})
}
