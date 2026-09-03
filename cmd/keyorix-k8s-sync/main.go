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
	once := flag.Bool("once", false, "run a single reconcile pass and exit (for CI / one-shot Jobs)")
	dryRun := flag.Bool("dry-run", false, "report what would change without writing any Secret")
	cleanup := flag.Bool("cleanup", false, "delete orphaned Secrets the agent owns whose mapping was removed")
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
	fetcher := k8ssync.NewKeyorixFetcher(cfg.KeyorixURL, token, cfg.ProjectID)
	os.Exit(runAgent(cfg, fetcher, sink, *once, *dryRun, *cleanup))
}

// runAgent holds everything that happens once a Fetcher and Sink exist: engine
// wiring, the one-shot/loop split, and (loop mode only) the health server. Split out
// from main so tests can drive it with a fake Fetcher/Sink instead of the real
// in-cluster ones (which need a live Kubernetes API and mounted service-account
// files main() can't fake). Returns the process exit code instead of calling
// os.Exit directly, so deferred cleanup (context cancel, signal.Stop, health server
// shutdown) always runs.
func runAgent(cfg *k8ssync.Config, fetcher k8ssync.Fetcher, sink k8ssync.Sink, once, dryRun, cleanup bool) int {
	var engineOpts []k8ssync.Option
	if dryRun {
		engineOpts = append(engineOpts, k8ssync.WithDryRun())
	}
	// Cleanup is enabled by either the config file or the -cleanup flag; the flag lets a
	// one-shot run preview/perform a reap without editing the mounted config.
	if cfg.Cleanup || cleanup {
		engineOpts = append(engineOpts, k8ssync.WithCleanup())
	}
	engine := k8ssync.NewEngine(fetcher, sink, engineOpts...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		log.Println("k8s-sync: shutdown signal received")
		cancel()
	}()

	// One-shot mode: a single reconcile, then exit non-zero if anything failed (handy
	// as a CI gate or a Kubernetes Job). No health server / loop.
	if once {
		mode := ""
		if dryRun {
			mode = " (dry-run)"
		}
		log.Printf("k8s-sync: one-shot reconcile of %d mapping(s) from %s%s",
			len(cfg.Mappings), cfg.KeyorixURL, mode)
		res := k8ssync.Sync(ctx, engine, cfg.Mappings, log.Printf)
		if res.Failed > 0 {
			return 1
		}
		return 0
	}

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

	loopMode := ""
	if dryRun {
		loopMode = " (dry-run)"
	}
	log.Printf("k8s-sync: syncing %d mapping(s) from %s every %s (health :%d)%s",
		len(cfg.Mappings), cfg.KeyorixURL, cfg.GetInterval(), cfg.GetHealthPort(), loopMode)
	k8ssync.Run(ctx, engine, cfg.Mappings, cfg.GetInterval(), log.Printf, status)
	log.Println("k8s-sync: stopped")
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
