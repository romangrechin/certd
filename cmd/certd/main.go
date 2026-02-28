package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"certd/pkg/certmanager"
	"certd/pkg/config"
	"certd/pkg/logger"
)

func main() {
	configPath := flag.String("config", "/etc/certd/config.yaml", "Path to config file")
	flag.Parse()

	log := logger.New()
	log.Infof("Starting certd %s - Universal Let's Encrypt certificate daemon", Version)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Infof("Config loaded: %d domain(s), ACME account: %s, check interval: %s",
		len(cfg.Domains), cfg.ACME.Email, cfg.ACME.CheckInterval)
	for i, d := range cfg.Domains {
		log.Infof("  [%d] %s | key: %s | cert: %s | ca: %s | key_file: %s",
			i+1, d.Domain, d.KeyType, d.CertFile, d.CAFile, d.KeyFile)
	}

	manager := certmanager.New(cfg, log)

	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start certificate manager: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	received := <-sig

	log.Infof("Received signal %s, shutting down...", received)
	manager.Stop()
	log.Info("certd stopped gracefully")
}
