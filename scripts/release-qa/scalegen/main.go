// Command scalegen fills a migrated, empty keyorix database with a large,
// restore-valid dataset for the restore/migrate scale scenario
// (scripts/release-qa/scenario_restore_scale.sh, #3462): one project and
// environment, -secrets secret nodes, -versions secret versions spread
// across them (random bytes: nothing decrypts them) and -audit audit events
// written through the storage layer so the hash chain stays valid.
//
// Usage: go run ./scripts/release-qa/scalegen -config keyorix.yaml \
//
//	-secrets 1000 -versions 300000 -audit 300000
//
// Progress goes to stderr every 10%. It refuses a database that already has
// secret versions, so it is never run against real data by accident.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func main() {
	cfgPath := flag.String("config", "keyorix.yaml", "keyorix config of the (empty) target database")
	secrets := flag.Int("secrets", 1000, "secret nodes")
	versions := flag.Int("versions", 300000, "secret versions, spread over the secret nodes")
	audits := flag.Int("audit", 300000, "audit events (chained through the storage layer)")
	valueBytes := flag.Int("value-bytes", 256, "size of each version's random value")
	flag.Parse()
	if err := run(*cfgPath, *secrets, *versions, *audits, *valueBytes); err != nil {
		log.Fatalf("scalegen: %v", err)
	}
}

func progress(what string, done, total int, start time.Time) {
	if total >= 10 && done%(total/10) != 0 && done != total {
		return
	}
	fmt.Fprintf(os.Stderr, "scalegen: %s %d/%d (%s)\n", what, done, total, time.Since(start).Round(time.Second))
}

func run(cfgPath string, secrets, versions, audits, valueBytes int) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	st, err := storage.NewStorageFactory().CreateStorage(cfg) // migrates
	if err != nil {
		return err
	}
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return err
	}
	var existing int64
	if err := db.Model(&models.SecretVersion{}).Count(&existing).Error; err != nil {
		return err
	}
	if existing > 0 {
		return fmt.Errorf("target already has %d secret versions; scalegen only fills an empty database", existing)
	}

	start := time.Now()
	project := &models.Project{Name: "scalegen"}
	if err := db.Create(project).Error; err != nil {
		return err
	}
	env := &models.Environment{ProjectID: project.ID, Name: "scalegen"}
	if err := db.Create(env).Error; err != nil {
		return err
	}
	nodes := make([]models.SecretNode, secrets)
	for i := range nodes {
		nodes[i] = models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: fmt.Sprintf("scale-%06d", i)}
	}
	if err := db.CreateInBatches(nodes, 500).Error; err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "scalegen: %d secret nodes\n", secrets)

	const batch = 1000
	perNode := make([]int, secrets)
	for done := 0; done < versions; {
		n := min(batch, versions-done)
		rows := make([]models.SecretVersion, n)
		for i := range rows {
			k := (done + i) % secrets
			perNode[k]++
			v := make([]byte, valueBytes)
			if _, err := rand.Read(v); err != nil {
				return err
			}
			rows[i] = models.SecretVersion{SecretNodeID: nodes[k].ID, VersionNumber: perNode[k], EncryptedValue: v}
		}
		if err := db.CreateInBatches(rows, 200).Error; err != nil {
			return err
		}
		done += n
		progress("secret versions", done, versions, start)
	}

	ctx := context.Background()
	for i := 1; i <= audits; i++ {
		ev := &models.AuditEvent{
			EventType:    "secret.read",
			SecretNodeID: &nodes[i%secrets].ID,
			ProjectID:    &project.ID,
			Description:  fmt.Sprintf("scalegen read %d", i),
			EventTime:    time.Now().UTC(),
		}
		if err := st.LogAuditEvent(ctx, ev); err != nil {
			return fmt.Errorf("audit event %d: %w", i, err)
		}
		progress("audit events", i, audits, start)
	}
	if c, ok := st.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "scalegen: done in %s\n", time.Since(start).Round(time.Second))
	return nil
}
