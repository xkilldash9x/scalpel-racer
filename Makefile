# -- Project Variables --
BINARY_NAME := scalpel-racer
CMD_PATH := cmd/scalpel-racer/main.go
CERT_DIR := $(HOME)/.scalpel-racer/certs
CA_FILE := $(CERT_DIR)/ca.pem

# -- Cert Management Variables --
NSSDB := sql:$(HOME)/.pki/nssdb
CERT_NAME := "Scalpel Racer CA"

# -- Go Toolchain --
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet

# -- Phony Targets --
.PHONY: all build clean test fuzz fuzz-packet fuzz-ui fuzz-engine harden trust-certs untrust-certs check-tools fmt vet help

# Default target: Format, Vet, Test, and Build
all: fmt vet test build

# ==========================================
# Build Lifecycle
# ==========================================

build:
	@echo "--- Building $(BINARY_NAME) ---"
	$(GOBUILD) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "Build complete. Run with ./$(BINARY_NAME)"

clean:
	@echo "--- Cleaning Artifacts ---"
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f racer.log debug.log
	rm -f scalpel-body-*.bin

test:
	@echo "--- Running Unit Tests ---"
	$(GOTEST) -v ./...

fmt:
	@echo "--- Formatting Code ---"
	$(GOFMT) ./...

vet:
	@echo "--- Vetting Code ---"
	$(GOVET) ./...

# ==========================================
# Fuzzing & Hardening
# ==========================================

harden: fuzz build
	@echo "--- Hardened Build Complete ---"

fuzz: fuzz-packet fuzz-ui fuzz-engine

fuzz-packet:
	@echo "--- Fuzzing Packet Controller (30s) ---"
	$(GOTEST) ./internal/packet -fuzz=FuzzEvaluatePacket -fuzztime=30s

fuzz-ui:
	@echo "--- Fuzzing UI Parser (30s) ---"
	$(GOTEST) ./internal/ui -fuzz=FuzzTextToRequest -fuzztime=30s

fuzz-engine:
	@echo "--- Fuzzing Attack Planner (30s) ---"
	$(GOTEST) ./internal/engine -fuzz=FuzzPlanH1Attack -fuzztime=30s

# ==========================================
# Certificate Management
# ==========================================

check-tools:
	@which certutil > /dev/null || (echo "Error: 'certutil' not found. Install it with: sudo apt install libnss3-tools" && exit 1)
	@test -f $(CA_FILE) || (echo "Error: CA file not found at $(CA_FILE). Run '$(BINARY_NAME)' once to generate it." && exit 1)

trust-certs: check-tools
	@echo "--- Trusting Certificates ---"
	@echo "[1/2] Installing to System Store (requires sudo)..."
	sudo cp $(CA_FILE) /usr/local/share/ca-certificates/scalpel-racer.crt
	sudo update-ca-certificates

	@echo "[2/2] Installing to Chrome/NSS Database..."
	# "C,," = Trust for SSL/TLS, but not email or object signing
	certutil -d $(NSSDB) -A -t "C,," -n $(CERT_NAME) -i $(CA_FILE)
	@echo "Done! You may need to restart Chrome."

untrust-certs: check-tools
	@echo "--- Removing Certificates ---"
	@echo "[1/2] Removing from System Store (requires sudo)..."
	sudo rm -f /usr/local/share/ca-certificates/scalpel-racer.crt
	sudo update-ca-certificates --fresh

	@echo "[2/2] Removing from Chrome/NSS Database..."
	certutil -d $(NSSDB) -D -n $(CERT_NAME) || echo "Cert not found in NSSDB, skipping..."
	@echo "Done!"

help:
	@echo "Scalpel Racer Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make            - Run fmt, vet, test, and build"
	@echo "  make build      - Compile the binary"
	@echo "  make test       - Run unit tests"
	@echo "  make fuzz       - Run all fuzzers (90s total)"
	@echo "  make harden     - Run fuzzers then build"
	@echo "  make trust-certs   - Install CA to Linux System and Chrome"
	@echo "  make untrust-certs - Remove CA from Linux System and Chrome"
	@echo "  make clean      - Remove binary and logs"
