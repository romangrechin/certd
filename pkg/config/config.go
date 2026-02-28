package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	ACME    ACMEConfig     `yaml:"acme"`
	Domains []DomainConfig `yaml:"domains"`
}

// ACMEConfig holds settings shared across all domains.
type ACMEConfig struct {
	// Email is used for Let's Encrypt account registration and expiry notices.
	Email string `yaml:"email"`

	// Staging enables the Let's Encrypt staging environment.
	// Use it to test your setup without hitting production rate limits.
	Staging bool `yaml:"staging"`

	// AccountStorageDir is the directory where the ACME account key and
	// registration resource are persisted between daemon restarts.
	// Default: /var/lib/certd
	AccountStorageDir string `yaml:"account_storage_dir"`

	// CheckInterval controls how often all certificates are inspected.
	// Default: 12h
	CheckInterval time.Duration `yaml:"check_interval"`
}

// DomainConfig describes a single certificate to obtain and maintain.
type DomainConfig struct {
	// Domain is the primary domain name (CN). Required.
	Domain string `yaml:"domain"`

	// KeyType sets the certificate private key algorithm and size.
	// Supported values: RSA2048, RSA4096, ECDSA.
	// Default: RSA2048.
	// Note: RSA2048 or RSA4096 are required for Android native IKEv2/IPSec clients.
	// ECDSA is suitable for modern TLS workloads (nginx, Caddy, etc.).
	KeyType string `yaml:"key_type"`

	// Absolute paths to the three output files. All are required.
	CertFile string `yaml:"cert_file"` // leaf (server) certificate only
	CAFile   string `yaml:"ca_file"`   // CA / intermediate chain
	KeyFile  string `yaml:"key_file"`  // private key

	// PostRenewHook is an optional shell command executed after successful
	// renewal. Leave empty to skip.
	PostRenewHook string `yaml:"post_renew_hook"`

	// HookTimeout is the maximum execution time allowed for PostRenewHook.
	// Default: 60s
	HookTimeout time.Duration `yaml:"hook_timeout"`
}

// Load reads, parses, and validates the YAML configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.ACME.CheckInterval == 0 {
		c.ACME.CheckInterval = 12 * time.Hour
	}
	if c.ACME.AccountStorageDir == "" {
		c.ACME.AccountStorageDir = "/var/lib/certd"
	}
	for i := range c.Domains {
		d := &c.Domains[i]
		if d.KeyType == "" {
			d.KeyType = "ECDSA"
		}
		if d.HookTimeout == 0 {
			d.HookTimeout = 60 * time.Second
		}
	}
}

func (c *Config) validate() error {
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain must be configured under 'domains'")
	}

	seen := make(map[string]bool)
	for i, d := range c.Domains {
		prefix := fmt.Sprintf("domains[%d]", i)

		if d.Domain == "" {
			return fmt.Errorf("%s: domain is required", prefix)
		}
		if seen[d.Domain] {
			return fmt.Errorf("%s: duplicate domain %q", prefix, d.Domain)
		}
		seen[d.Domain] = true

		if d.CertFile == "" {
			return fmt.Errorf("%s (%s): cert_file is required", prefix, d.Domain)
		}
		if d.CAFile == "" {
			return fmt.Errorf("%s (%s): ca_file is required", prefix, d.Domain)
		}
		if d.KeyFile == "" {
			return fmt.Errorf("%s (%s): key_file is required", prefix, d.Domain)
		}

		for _, p := range []string{d.CertFile, d.CAFile, d.KeyFile} {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("%s (%s): path %q must be absolute", prefix, d.Domain, p)
			}
		}

		switch d.KeyType {
		case "RSA2048", "RSA4096", "ECDSA":
			// valid
		default:
			return fmt.Errorf(
				"%s (%s): unsupported key_type %q — must be one of: RSA2048, RSA4096, ECDSA",
				prefix, d.Domain, d.KeyType,
			)
		}
	}
	return nil
}
