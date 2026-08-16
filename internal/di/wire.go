package di

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
)

func InitializeApp() (string, error) {
	fmt.Println("InitializeApp() called")
	_, err := config.Load("keyorix.yaml")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return "", err
	}
	// Do not log the loaded *config.Config value: it embeds live secrets
	// (DB password, remote/SIEM/webhook API tokens, SMTP password, KMS/Shamir
	// key material, etc. — see internal/config.Config) that would otherwise
	// leak into stdout, which is commonly captured by container/systemd/CI log
	// pipelines with far broader read access than the config file itself.
	fmt.Println("Config successfully loaded")
	return "✅ Keyorix app initialized. DB migrated.", nil
}
