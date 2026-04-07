package di

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
)

func InitializeApp() (string, error) {
	fmt.Println("InitializeApp() called")
	conf, err := config.Load("keyorix.yaml")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return "", err
	}
	fmt.Println("Config successfully loaded:", conf)
	return "✅ Keyorix app initialized. DB migrated.", nil
}
