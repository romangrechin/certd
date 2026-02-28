# certd

**certd** is a lightweight daemon that automatically obtains and renews
[Let's Encrypt](https://letsencrypt.org) TLS certificates for any number of
domains and delivers each certificate to exactly the files your service expects.

## What it does

When started, certd reads a list of domains from a single YAML configuration
file. For each domain it checks whether a valid certificate already exists on
disk. If a certificate is missing, expired, or about to expire (less than 10%
of its lifetime remains), certd automatically requests a new one from
Let's Encrypt using the HTTP-01 challenge protocol and saves the result as
three separate PEM files:

| File | Contents |
|------|----------|
| `cert_file` | Server (leaf) certificate only |
| `ca_file`   | CA / intermediate chain |
| `key_file`  | Private key |

After all renewals are complete, certd runs a configurable shell command
(`post_renew_hook`) for each renewed domain, so your service picks up the new
certificate immediately — no manual restarts required.

The check repeats on a configurable interval (default: every 12 hours).

## Supported key types

| Value | Use case |
|-------|----------|
| `RSA2048` | VPN servers, legacy clients, Android native IKEv2/IPSec (**default**) |
| `RSA4096`  | Environments with a stricter security policy |
| `ECDSA`  | Modern TLS workloads (nginx, Caddy, HAProxy, etc.) |

## Typical use cases

- **IPSec / strongSwan VPN** — renew the server certificate and reload
  strongSwan without dropping active tunnels.
- **Web servers** — deliver renewed certificates to nginx, Apache, or Caddy
  and reload them in place.
- **Mail servers** — keep Postfix and Dovecot certificates current.
- **Any TLS-enabled service** — if it reads a PEM file and can be reloaded
  with a shell command, certd can manage its certificate.

A single certd instance handles all your domains under one Let's Encrypt
account with one configuration file.

## Quick start

### 1. Prerequisites

- Go 1.21 or later
- Port **80** accessible from the internet on every domain you want to manage
  (required for HTTP-01 challenge)

### 2. Build

```bash
git clone https://github.com/romangrechin/certd
cd certd
make build
# binary: ./build/certd
```

### 3. Install as a systemd service

```bash
# Install binary and default files
sudo make install

# Edit the configuration
sudo nano /etc/certd/config.yaml

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now certd

# Follow logs
sudo journalctl -u certd -f
```

`make install` performs the following steps:

| Action | Path |
|--------|------|
| Copy binary | `/usr/local/bin/certd` |
| Copy systemd unit | `/etc/systemd/system/certd.service` |
| Copy example config | `/etc/certd/config.yaml` (only if absent) |
| Create account storage | `/var/lib/certd/` |

### 4. Configuration

```yaml
acme:
  email: "admin@example.com"
  staging: false               # set true to test without rate limits
  check_interval: "12h"
  account_storage_dir: "/var/lib/certd"

domains:
  - domain: "vpn.example.com"
    key_type: "RSA2048"        # required for Android IKEv2/IPSec clients
    cert_file: "/etc/ipsec.d/certs/vpn.cert.pem"
    ca_file:   "/etc/ipsec.d/cacerts/vpn.ca.pem"
    key_file:  "/etc/ipsec.d/private/vpn.key.pem"
    post_renew_hook: |
      ipsec rereadall
      ipsec reload

  - domain: "www.example.com"
    key_type: "ECDSA"
    cert_file: "/etc/nginx/ssl/www.cert.pem"
    ca_file:   "/etc/nginx/ssl/www.ca.pem"
    key_file:  "/etc/nginx/ssl/www.key.pem"
    post_renew_hook: "nginx -s reload"
```

## License

MIT
