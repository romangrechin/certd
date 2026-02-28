package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"certd/pkg/config"
	"certd/pkg/logger"
)

const renewThreshold = 0.10

// Manager owns the shared ACME account and runs a single periodic worker that
// checks all configured domains, renews those that need it (starting the
// HTTP-01 server once for the whole batch), and then executes per-domain hooks.
type Manager struct {
	cfg    *config.Config
	log    *logger.Logger
	stopCh chan struct{}
}

// New creates a Manager. Call Start to begin background operation.
func New(cfg *config.Config, log *logger.Logger) *Manager {
	return &Manager{cfg: cfg, log: log, stopCh: make(chan struct{})}
}

// Start performs the initial check cycle synchronously, then launches the
// background loop. A failure in one domain never blocks the others.
func (m *Manager) Start() error {
	m.log.Infof("Certificate manager starting — %d domain(s) configured", len(m.cfg.Domains))

	if err := m.ensureOutputDirs(); err != nil {
		return fmt.Errorf("creating output directories: %w", err)
	}

	if err := m.checkCycle(); err != nil {
		m.log.Errorf("Initial check cycle finished with errors: %v", err)
	}

	go m.loop()
	return nil
}

// Stop signals the background loop to exit cleanly.
func (m *Manager) Stop() {
	m.log.Info("Certificate manager stopping")
	close(m.stopCh)
}

func (m *Manager) loop() {
	m.log.Infof("Background loop started (check interval: %s)", m.cfg.ACME.CheckInterval)
	ticker := time.NewTicker(m.cfg.ACME.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.log.Info("Periodic check triggered")
			if err := m.checkCycle(); err != nil {
				m.log.Errorf("Periodic check cycle finished with errors: %v", err)
			}
		case <-m.stopCh:
			m.log.Info("Background loop stopped")
			return
		}
	}
}

// checkCycle is the single unit of work executed on every tick:
//
//  1. Inspect every domain; collect those that require renewal.
//  2. If any need renewal — start the HTTP-01 server once, renew all of them,
//     then stop the server.
//  3. Run each successfully renewed domain's hook sequentially.
func (m *Manager) checkCycle() error {
	m.log.Info("--- check cycle start ---")

	user, err := m.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("loading ACME account: %w", err)
	}

	// Phase 1 — determine which domains need renewal.
	type item struct {
		domain config.DomainConfig
		reason string
	}
	var toRenew []item

	for _, d := range m.cfg.Domains {
		reason, err := m.needsRenewal(d)
		if err != nil {
			m.log.Errorf("[%s] cannot read certificate (%v) — queuing for renewal", d.Domain, err)
			toRenew = append(toRenew, item{d, fmt.Sprintf("unreadable: %v", err)})
			continue
		}
		if reason != "" {
			m.log.Warnf("[%s] renewal required: %s", d.Domain, reason)
			toRenew = append(toRenew, item{d, reason})
		} else {
			m.log.Infof("[%s] certificate is valid, skipping", d.Domain)
		}
	}

	if len(toRenew) == 0 {
		m.log.Info("--- check cycle end: nothing to renew ---")
		return nil
	}

	// Phase 2 — start the HTTP-01 server once and renew all queued domains.
	m.log.Infof("%d domain(s) queued for renewal — starting HTTP-01 server",
		len(toRenew))

	httpProvider := http01.NewProviderServer("", "80")

	var renewErrors []error
	var renewed []config.DomainConfig

	for _, it := range toRenew {
		m.log.Infof("[%s] renewing (reason: %s)", it.domain.Domain, it.reason)
		if err := m.renewDomain(it.domain, user, httpProvider); err != nil {
			m.log.Errorf("[%s] renewal failed: %v", it.domain.Domain, err)
			renewErrors = append(renewErrors, fmt.Errorf("%s: %w", it.domain.Domain, err))
		} else {
			m.log.Infof("[%s] certificate renewed and saved", it.domain.Domain)
			renewed = append(renewed, it.domain)
		}
	}

	// Phase 3 — run post-renew hooks after the HTTP server is no longer needed.
	for _, d := range renewed {
		if d.PostRenewHook == "" {
			m.log.Infof("[%s] no post_renew_hook configured, skipping", d.Domain)
			continue
		}
		m.runHook(d)
	}

	m.log.Info("--- check cycle end ---")

	if len(renewErrors) > 0 {
		return joinErrors(renewErrors)
	}
	return nil
}

// needsRenewal returns a non-empty reason string when the domain's certificate
// must be renewed, or an empty string when it is still valid.
// A non-nil error indicates that the certificate file could not be read or parsed.
func (m *Manager) needsRenewal(d config.DomainConfig) (string, error) {
	cert, err := loadCert(d.CertFile)
	if err != nil {
		return "", err
	}

	m.log.Infof("[%s] found certificate: algorithm=%s, valid_until=%s",
		d.Domain, certKeyDesc(cert), cert.NotAfter.Format(time.RFC3339))

	// Key type must match the configured value.
	if reason := keyTypeMismatch(cert, d.KeyType); reason != "" {
		return reason, nil
	}

	// The certificate must cover the configured domain name.
	if err := cert.VerifyHostname(d.Domain); err != nil {
		return fmt.Sprintf("does not cover domain: %v", err), nil
	}

	// Renew when less than 10 % of the lifetime remains.
	remaining := time.Until(cert.NotAfter)
	total := cert.NotAfter.Sub(cert.NotBefore)
	fraction := float64(remaining) / float64(total)

	m.log.Infof("[%s] lifetime remaining: %.1f%% (%s)",
		d.Domain, fraction*100, remaining.Round(time.Hour))

	if fraction < renewThreshold {
		return fmt.Sprintf("lifetime below %.0f%% threshold (%.1f%% remaining)",
			renewThreshold*100, fraction*100), nil
	}

	return "", nil
}

// renewDomain obtains a new certificate for d using the shared ACME account
// and the already-running HTTP-01 provider.
func (m *Manager) renewDomain(
	d config.DomainConfig,
	user *acmeUser,
	httpProvider *http01.ProviderServer,
) error {
	legoConfig := lego.NewConfig(user)
	if m.cfg.ACME.Staging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	} else {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	}

	kt := legoKeyType(d.KeyType)
	legoConfig.Certificate.KeyType = kt
	m.log.Infof("[%s] key type: %s", d.Domain, d.KeyType)

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("creating ACME client: %w", err)
	}

	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return fmt.Errorf("setting HTTP-01 provider: %w", err)
	}

	// Register the account on first use.
	if user.Registration == nil {
		m.log.Infof("[%s] registering ACME account for %s", d.Domain, user.Email)
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("ACME registration: %w", err)
		}
		user.mu.Lock()
		user.Registration = reg
		user.mu.Unlock()
		m.log.Infof("[%s] ACME account registered, URI: %s", d.Domain, reg.URI)
		if err := m.saveUser(user); err != nil {
			m.log.Warnf("[%s] failed to persist ACME account: %v", d.Domain, err)
		}
	}

	m.log.Infof("[%s] requesting certificate from Let's Encrypt", d.Domain)
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{d.Domain},
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtaining certificate: %w", err)
	}

	return m.saveCertFiles(d, res)
}

// saveCertFiles splits the PEM bundle returned by lego and writes the three
// output files. The bundle always contains the leaf cert first, followed by
// the CA / intermediate chain (guaranteed by Bundle: true).
func (m *Manager) saveCertFiles(d config.DomainConfig, res *certificate.Resource) error {
	serverCert, caChain, err := splitCertBundle(res.Certificate)
	if err != nil {
		return fmt.Errorf("splitting certificate bundle: %w", err)
	}

	m.log.Infof("[%s] bundle: leaf + %d CA/intermediate block(s)",
		d.Domain, countPEMBlocks(caChain))

	files := []struct {
		path string
		data []byte
		desc string
		mode os.FileMode
	}{
		{d.CertFile, serverCert, "server certificate", 0644},
		{d.CAFile, caChain, "CA chain", 0644},
		{d.KeyFile, res.PrivateKey, "private key", 0600},
	}

	for _, f := range files {
		m.log.Infof("[%s] writing %s -> %s (%d bytes)", d.Domain, f.desc, f.path, len(f.data))
		if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
			return fmt.Errorf("writing %s to %s: %w", f.desc, f.path, err)
		}
	}
	return nil
}

// ensureOutputDirs creates the parent directories of all configured output
// files so that writes never fail due to missing directories.
func (m *Manager) ensureOutputDirs() error {
	seen := make(map[string]bool)
	for _, d := range m.cfg.Domains {
		for _, p := range []string{d.CertFile, d.CAFile, d.KeyFile} {
			dir := filepath.Dir(p)
			if seen[dir] {
				continue
			}
			seen[dir] = true
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dir, err)
			}
			m.log.Debugf("ensured directory: %s", dir)
		}
	}
	if err := os.MkdirAll(m.cfg.ACME.AccountStorageDir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", m.cfg.ACME.AccountStorageDir, err)
	}
	return nil
}

// loadCert reads and parses the first PEM certificate block from path.
func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate in %s: %w", path, err)
	}
	return cert, nil
}

// splitCertBundle separates the first PEM block (leaf cert) from the rest
// (CA / intermediate chain). Both parts are returned as PEM-encoded bytes.
func splitCertBundle(bundle []byte) (leaf, chain []byte, err error) {
	rest := bundle
	first := true
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		encoded := pem.EncodeToMemory(block)
		if first {
			leaf = encoded
			first = false
		} else {
			chain = append(chain, encoded...)
		}
	}
	if first {
		return nil, nil, errors.New("certificate bundle contains no PEM blocks")
	}
	if len(chain) == 0 {
		return nil, nil, errors.New("certificate bundle has no CA chain (expected Bundle:true response)")
	}
	return leaf, chain, nil
}

func countPEMBlocks(data []byte) int {
	n := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		n++
	}
	return n
}

// runHook executes d.PostRenewHook via sh with the configured timeout.
// Errors are logged but never propagate — a failed hook must not block other
// domains.
func (m *Manager) runHook(d config.DomainConfig) {
	m.log.Infof("[%s] running post_renew_hook: %s", d.Domain, d.PostRenewHook)

	ctx, cancel := context.WithTimeout(context.Background(), d.HookTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", d.PostRenewHook)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			m.log.Errorf("[%s] post_renew_hook timed out after %s", d.Domain, d.HookTimeout)
		} else {
			m.log.Errorf("[%s] post_renew_hook failed: %v", d.Domain, err)
		}
		return
	}
	m.log.Infof("[%s] post_renew_hook completed successfully", d.Domain)
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
	mu           sync.Mutex // guards Registration field
}

func (u *acmeUser) GetEmail() string { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.Registration
}
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey { return u.key }

type savedAccount struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`
	PrivateKey   []byte                 `json:"private_key"` // PKCS8 DER
}

func (m *Manager) accountPath() string {
	return filepath.Join(m.cfg.ACME.AccountStorageDir, "account.json")
}

// loadOrCreateUser loads the persisted ACME account or generates a fresh one.
// The account key is always ECDSA P-256 — suitable for all ACME providers and
// independent from the certificate key type chosen for each domain.
func (m *Manager) loadOrCreateUser() (*acmeUser, error) {
	path := m.accountPath()

	data, err := os.ReadFile(path)
	if err == nil {
		var sa savedAccount
		if jsonErr := json.Unmarshal(data, &sa); jsonErr == nil {
			key, keyErr := x509.ParsePKCS8PrivateKey(sa.PrivateKey)
			if keyErr == nil {
				m.log.Infof("loaded ACME account from %s (email: %s)", path, sa.Email)
				return &acmeUser{
					Email:        sa.Email,
					Registration: sa.Registration,
					key:          key,
				}, nil
			}
			m.log.Warnf("cannot parse stored account key (%v) — generating new one", keyErr)
		}
	}

	m.log.Info("generating new ACME account key (ECDSA P-256)")
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}
	return &acmeUser{Email: m.cfg.ACME.Email, key: privKey}, nil
}

func (m *Manager) saveUser(user *acmeUser) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(user.key)
	if err != nil {
		return fmt.Errorf("marshalling account key: %w", err)
	}

	user.mu.Lock()
	sa := savedAccount{
		Email:        user.Email,
		Registration: user.Registration,
		PrivateKey:   keyBytes,
	}
	user.mu.Unlock()

	data, err := json.MarshalIndent(sa, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling account JSON: %w", err)
	}
	path := m.accountPath()
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing account to %s: %w", path, err)
	}
	m.log.Infof("ACME account saved to %s", path)
	return nil
}

// legoKeyType maps the config key_type string to lego's certcrypto.KeyType.
func legoKeyType(kt string) certcrypto.KeyType {
	switch kt {
	case "RSA4096":
		return certcrypto.RSA4096
	case "ECDSA":
		return certcrypto.EC256
	default: // RSA2048
		return certcrypto.RSA2048
	}
}

// keyTypeMismatch returns a human-readable reason when the certificate's public
// key algorithm does not match the desired keyType, or an empty string when
// they agree.
func keyTypeMismatch(cert *x509.Certificate, keyType string) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.Size() * 8
		switch keyType {
		case "RSA2048":
			if bits != 2048 {
				return fmt.Sprintf("key type mismatch: have RSA-%d, want RSA-2048", bits)
			}
		case "RSA4096":
			if bits != 4096 {
				return fmt.Sprintf("key type mismatch: have RSA-%d, want RSA-4096", bits)
			}
		case "ECDSA":
			return fmt.Sprintf("key type mismatch: have RSA-%d, want ECDSA", bits)
		}
	case *ecdsa.PublicKey:
		if keyType != "ECDSA" {
			return fmt.Sprintf("key type mismatch: have ECDSA, want %s", keyType)
		}
	}
	return ""
}

// certKeyDesc returns a short human-readable description of a certificate's
// public key algorithm, used in log messages.
func certKeyDesc(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.Size()*8)
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-%s", pub.Curve.Params().Name)
	default:
		return fmt.Sprintf("unknown(%T)", pub)
	}
}

// joinErrors combines a slice of errors into a single descriptive error.
func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msg := fmt.Sprintf("%d error(s) occurred during the renewal cycle:", len(errs))
	for _, e := range errs {
		msg += "\n  - " + e.Error()
	}
	return errors.New(msg)
}
