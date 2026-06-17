/*
Keyorix Kubernetes sync agent — materialises selected Keyorix secrets into
Kubernetes Secrets and keeps them current as upstream values rotate.

Runs in-cluster: it authenticates to Keyorix with a machine-identity token
(KEYORIX_TOKEN) and writes Secrets via the Kubernetes API using its mounted
service-account credentials. Configure the mappings in a YAML file (default
/etc/keyorix/k8s-sync.yaml, or -config / KEYORIX_K8S_SYNC_CONFIG).

Copyright (C) 2025 Keyorix Contributors. Licensed under the AGPL-3.0-or-later.
*/
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/keyorixhq/keyorix/internal/k8ssync"
)

func main() {
	configPath := flag.String("config", envOr("KEYORIX_K8S_SYNC_CONFIG", "/etc/keyorix/k8s-sync.yaml"),
		"path to the sync config (YAML)")
	flag.Parse()

	cfg, err := k8ssync.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("k8s-sync: config: %v", err)
	}

	token := strings.TrimSpace(os.Getenv("KEYORIX_TOKEN"))
	if token == "" {
		log.Fatalf("k8s-sync: KEYORIX_TOKEN is required (the Keyorix machine-identity token)")
	}

	sink, err := k8ssync.NewInClusterSink()
	if err != nil {
		log.Fatalf("k8s-sync: kubernetes: %v", err)
	}

	engine := k8ssync.NewEngine(k8ssync.NewKeyorixFetcher(cfg.KeyorixURL, token), sink)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("k8s-sync: shutdown signal received")
		cancel()
	}()

	log.Printf("k8s-sync: syncing %d mapping(s) from %s every %s",
		len(cfg.Mappings), cfg.KeyorixURL, cfg.GetInterval())
	k8ssync.Run(ctx, engine, cfg.Mappings, cfg.GetInterval(), log.Printf)
	log.Println("k8s-sync: stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
