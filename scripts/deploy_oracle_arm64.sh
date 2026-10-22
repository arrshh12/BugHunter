#!/usr/bin/env bash
# ==============================================================================
# AutoBugHunter 24/7 - Oracle Cloud ARM64 Deployment Script
# Target: Ubuntu 24.04 LTS on Ampere A1 (VM.Standard.A1.Flex, 4 OCPU, 24 GB RAM)
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo "  Deploying AutoBugHunter 24/7 on Oracle Cloud ARM64 Infrastructure"
echo "======================================================================"

# 1. Architecture Check
ARCH=$(uname -m)
if [ "$ARCH" != "aarch64" ]; then
    echo "[!] Warning: System architecture is $ARCH (expected aarch64 / ARM64)."
    echo "    Continuing in multi-arch compatibility mode..."
else
    echo "[✓] Verified target architecture: $ARCH (Native ARM64)"
fi

# 2. Update and install prerequisite packages
echo "[*] Updating apt package indices..."
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    git \
    iptables-persistent \
    netfilter-persistent

# 3. Install Docker Engine and Docker Compose Plugin
if ! command -v docker &> /dev/null; then
    echo "[*] Installing official Docker Engine..."
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER" || true
    echo "[✓] Docker Engine installed successfully."
else
    echo "[✓] Docker Engine already present: $(docker --version)"
fi

# 4. Configure Oracle Cloud Ubuntu Host Firewall (Port 8080)
echo "[*] Configuring host iptables firewall for port 8080..."
if sudo iptables -C INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null; then
    echo "[✓] Port 8080 already allowed in iptables."
else
    sudo iptables -I INPUT 1 -m state --state NEW -p tcp --dport 8080 -j ACCEPT
    sudo netfilter-persistent save
    echo "[✓] Port 8080 opened and rules saved persistently."
fi

# 5. Prepare workspace directories and .env
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p workspace/state workspace/repos

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        echo "[*] Copying .env.example to .env..."
        cp .env.example .env
        echo "[!] NOTICE: Please configure GITHUB_TOKEN and LLM_KEYS_POOL in .env before running."
    else
        echo "[!] Error: No .env or .env.example found in $ROOT_DIR."
        exit 1
    fi
fi

# 6. Build and launch container
echo "[*] Launching AutoBugHunter daemon via Docker Compose..."
docker compose up -d --build

echo "======================================================================"
echo "  Deployment Complete! AutoBugHunter 24/7 Daemon is Active"
echo "  Mission Control UI: http://$(curl -s ifconfig.me || echo 'localhost'):8080"
echo "  View container logs: docker compose logs -f"
echo "======================================================================"
