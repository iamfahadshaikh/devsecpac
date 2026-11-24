# Universal Autonomous DevSecOps Platform Container
# Packaging all 16 Security Engines, Deduplication, Remediation & ASPM Exporter
FROM python:3.12-slim-bookworm

# Prevent python buffering and non-interactive debian prompts
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    GIT_TERMINAL_PROMPT=0 \
    PATH="/usr/local/bin:/home/devsecuser/.local/bin:/home/devsecuser/.local/opt/dependency-check/bin:$PATH"

# Install system dependencies: JRE (Dependency-Check), Node.js (CodeQL JS/TS), Nmap, and core utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    tar \
    gzip \
    unzip \
    ca-certificates \
    default-jre-headless \
    nodejs \
    nmap \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged devsecuser (UID 10001) for strict least-privilege runtime security
RUN useradd -u 10001 -m -s /bin/bash devsecuser && \
    mkdir -p /workspace /home/devsecuser/.local/bin /home/devsecuser/.local/opt && \
    chown -R devsecuser:devsecuser /workspace /home/devsecuser

# Switch to devsecuser for setup and runtime
USER devsecuser
ENV HOME=/home/devsecuser

# Set working directory for devsec package installation
WORKDIR /app

# Copy source repository
COPY --chown=devsecuser:devsecuser pyproject.toml README.md ./
COPY --chown=devsecuser:devsecuser src/ ./src/

# Install devsecpac package and dependencies
RUN pip install --no-cache-dir --user .

# Run autonomous setup to install all missing binary engines into user bin
RUN /home/devsecuser/.local/bin/devsec setup || true

# Set workspace directory for scan targets
WORKDIR /workspace

# Verify non-root user
USER devsecuser

# Default entrypoint
ENTRYPOINT ["/home/devsecuser/.local/bin/devsec"]
CMD ["scan", "--help"]
