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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	// Health/readiness server for Kubernetes probes (/healthz, /readyz, /status).
	status := k8ssync.NewStatus()
	healthSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.GetHealthPort()),
		Handler:           status.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("k8s-sync: health server error: %v", err)
		}
	}()
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = healthSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("k8s-sync: syncing %d mapping(s) from %s every %s (health :%d)",
		len(cfg.Mappings), cfg.KeyorixURL, cfg.GetInterval(), cfg.GetHealthPort())
	k8ssync.Run(ctx, engine, cfg.Mappings, cfg.GetInterval(), log.Printf, status)
	log.Println("k8s-sync: stopped")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
