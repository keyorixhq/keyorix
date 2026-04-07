package main

import (
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/di"
	"github.com/keyorixhq/keyorix/internal/storage/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	msg, err := di.InitializeApp()
	if err != nil {
		log.Fatalf("❌ Application initialization error: %v", err)
	}
	fmt.Println(msg)

	db, err := gorm.Open(sqlite.Open("keyorix.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ Database connection error: %v", err)
	}

	err = db.AutoMigrate(
		&models.Namespace{},
		&models.Zone{},
		&models.Environment{},
		&models.User{},
		&models.Role{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretAccessLog{},
		&models.SecretMetadataHistory{},
		&models.Session{},
		&models.PasswordReset{},
		&models.Tag{},
		&models.SecretTag{},
		&models.Notification{},
		&models.AuditEvent{},
		&models.Setting{},
		&models.SystemMetadata{},
		&models.APIClient{},
		&models.APIToken{},
		&models.RateLimit{},
		&models.APICallLog{},
		&models.GRPCService{},
		&models.IdentityProvider{},
		&models.ExternalIdentity{},
	)
	if err != nil {
		log.Fatalf("❌ Migration error: %v", err)
	}

	fmt.Println("✅ Keyorix app initialized. DB migrated.")
}
