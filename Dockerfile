# AutoBugHunter 24/7 Container Packaging
# Multi-Arch ARM64 / AMD64 deployment image for Oracle Cloud Free Tier Ampere A1
FROM python:3.12-slim-bookworm

# Prevent interactive prompts during apt install
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install base toolchain: Git, curl, build essentials, and GitHub CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    build-essential \
    ca-certificates \
    gnupg \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications and install Python packages
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy source tree and assets
COPY src/ /app/src/
COPY prompts/ /app/prompts/
COPY scripts/ /app/scripts/
COPY main.py /app/main.py

# Create persistent state and workspace directories
RUN mkdir -p /workspace/state /workspace/repos

# Expose Mission Control dashboard port
EXPOSE 8080

ENTRYPOINT ["python", "main.py"]
