# AutoBugHunter 24/7 Container Packaging
# Multi-Arch ARM64 / AMD64 deployment image compatible with Hugging Face Spaces & Cloud VMs
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PORT=7860
ENV DASHBOARD_PORT=7860
ENV DASHBOARD_HOST=0.0.0.0
ENV WORKSPACE_DIR=/workspace
ENV STATE_DIR=/workspace/state
ENV REPOS_DIR=/workspace/repos

# 1. Install base toolchain: Git, curl, build essentials, and GitHub CLI
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

# 2. Setup non-root user (UID 1000) for Hugging Face Spaces
RUN useradd -m -u 1000 user
WORKDIR /app

# 3. Copy dependency specifications and install Python packages
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy source tree and assets
COPY src/ /app/src/
COPY prompts/ /app/prompts/
COPY scripts/ /app/scripts/
COPY main.py /app/main.py

# 5. Create persistent state and workspace directories and set ownership for user 1000
RUN mkdir -p /workspace/state /workspace/repos \
    && chown -R user:user /app /workspace

# 6. Configure git bot identity for non-root user
USER user
RUN git config --global user.name "AutoBugHunter[bot]" \
    && git config --global user.email "autobughunter[bot]@users.noreply.github.com" \
    && git config --global init.defaultBranch main

# 7. Expose Hugging Face Space dashboard port
EXPOSE 7860

ENTRYPOINT ["python", "main.py"]
