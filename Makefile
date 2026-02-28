BINARY    := certd
CMD_PATH  := ./cmd/certd
BUILD_DIR := ./build

# Embed version from git tag if available, fall back to "dev".
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.Version=$(VERSION)

.PHONY: all build clean install uninstall deps tidy

all: build

## deps: download and tidy Go modules
deps:
	go mod download
	go mod tidy

## build: compile a static binary into ./build/certd
build: deps
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)
	@echo "Built: $(BUILD_DIR)/$(BINARY)  (version: $(VERSION))"

## install: build, then install binary + systemd unit + example config
install: build
	# Binary
	install -Dm755 $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)

	# systemd unit
	install -Dm644 certd.service /etc/systemd/system/certd.service

	# Config — do NOT overwrite an existing installation
	mkdir -p /etc/certd
	@if [ ! -f /etc/certd/config.yaml ]; then \
		install -Dm600 config.example.yaml /etc/certd/config.yaml; \
		echo "Created /etc/certd/config.yaml from example — please edit it before starting the service."; \
	else \
		echo "Kept existing /etc/certd/config.yaml"; \
	fi

	# Account storage
	mkdir -p /var/lib/certd
	chmod 700 /var/lib/certd

	@echo ""
	@echo "Installation complete. Next steps:"
	@echo "  1. Edit /etc/certd/config.yaml"
	@echo "  2. systemctl daemon-reload"
	@echo "  3. systemctl enable --now certd"

## uninstall: remove all installed files (does not touch /etc/certd or /var/lib/certd)
uninstall:
	rm -f /usr/local/bin/$(BINARY)
	rm -f /etc/systemd/system/certd.service
	systemctl daemon-reload 2>/dev/null || true
	@echo "Uninstalled. Config and data directories were left intact."

## clean: remove build artefacts
clean:
	rm -rf $(BUILD_DIR)

## tidy: tidy Go modules only
tidy:
	go mod tidy
