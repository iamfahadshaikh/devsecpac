# Multi-stage production container for devsecpac / devsec-cli
FROM python:3.12-slim-bookworm

# Prevent python from buffering stdout/stderr & interactive debian prompts
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    GIT_TERMINAL_PROMPT=0 \
    PATH="/root/.local/bin:/root/.local/opt/dependency-check/bin:$PATH"

# Install core system utilities, git, curl, openjdk, nodejs (needed for CodeQL TypeScript AST), and nmap
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
    && rm -rf /var/lib/apt/lists/*

# Set working directory for app
WORKDIR /app

# Copy package source files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the Python package and its dependencies
RUN pip install --no-cache-dir .

# Pre-populate and install toolchains using devsec's built-in autonomous installer
RUN devsec setup || true

# Pre-download standard CodeQL query packs for JavaScript, Python, and Go so they are pre-baked
RUN codeql pack download codeql/javascript-queries codeql/python-queries || true

# Set workspace directory for targets
WORKDIR /workspace

# Default entrypoint to devsec CLI
ENTRYPOINT ["devsec"]
CMD ["scan", "--help"]
