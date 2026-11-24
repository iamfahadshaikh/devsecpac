# devsecpac: Universal Autonomous DevSecOps Scanner Orchestrator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](#)

A cross-platform DevSecOps orchestrator that runs static, container, IaC, supply chain, and API security checks across your repository with a single command:

```bash
devsecpac scan .
# or
devsec scan .
```

---

## Key Features

- **Full-Spectrum Autonomous Pipeline:** Orchestrates 16 industry-standard security engines (SAST, DAST, SCA, Secrets, Containers, Kubernetes, IaC, Supply Chain, and API security).
- **Graceful Tool Degradation:** Missing tools or non-applicable stacks (e.g., no Dockerfiles or no Kubernetes manifests) are gracefully marked as `SKIPPED` or `NOT_APPLICABLE` without crashing the pipeline.
- **Embedded Kubernetes Security Inspector:** Built-in Python inspection for Pod Security Standards (detects root user, privileged mode, `hostPath` mounts, and resource limit omissions) without external binary dependencies.
- **Cross-Scanner Deduplication:** Finds duplicate alerts across multiple engines (e.g., Trivy vs. Dependency-Check vs. Semgrep) and collapses them to eliminate alert fatigue.
- **Automated Remediation Engine (`devsec fix`):** Generates and applies automated fixes for detected issues (e.g., unpinned package versions, missing user directives).
- **Interactive PR Commenting (`devsec pr-comment`):** Formats unified scan findings into rich, collapsible GitHub/GitLab PR comments with dynamic quality gate badges.
- **ASPM Integration (OWASP DefectDojo):** Pushes consolidated scan results directly to an active DefectDojo instance for enterprise vulnerability lifecycle tracking.
- **Real-Time Telemetry & Progress:** Live progress indicators showing engine execution, scannable file count, elapsed runtime, and remaining ETA.

---

## Installation

### Option 1: Editable Mode (Development)
```bash
pip install -e .
```

### Option 2: Build & Install Wheel
```bash
python -m pip install --upgrade build
python -m build
pip install dist/*.whl
```

---

## Command Reference

### 1. Host Binary Discovery
Check installed security engines and discover missing tools:
```bash
devsec info
```

### 2. Auto-Install Missing Tools
Automatically download and configure missing binaries into your user environment:
```bash
devsec setup
```

### 3. Scanning Targets

#### Local Repository
```bash
# Full scan of current directory
devsec scan .

# Run specific scanners
devsec scan . -t semgrep,hadolint,trivy

# Exclude slow scanners
devsec scan . --exclude codeql,sonar

# Fail pipeline on Medium severity (strict mode)
devsec scan . --strict
```

#### Remote Git Repositories
Scans remote repositories with full commit history across all branches:
```bash
# Public repository
devsec scan -r https://github.com/octocat/Hello-World.git

# Private repository with authentication token
devsec scan -r https://github.com/org/repo.git --token $GITHUB_TOKEN --branch main
```

#### ASPM / DefectDojo Export
Push findings to an active OWASP DefectDojo instance:
```bash
devsec scan . --defectdojo-push \
  --defectdojo-url http://localhost:8080 \
  --defectdojo-key <YOUR_API_KEY> \
  --defectdojo-engagement 1
```

### 4. Automated Remediation (`devsec fix`)
Generate remediation patches or apply fixes automatically:
```bash
# Preview remediation patches
devsec fix --json devsec-report.json --patch-output fixes.patch

# Apply fixes directly to codebase
devsec fix --json devsec-report.json --apply
```

### 5. Pull Request Commenting (`devsec pr-comment`)
Generate an interactive Markdown comment for GitHub Actions or GitLab CI:
```bash
devsec pr-comment --json devsec-report.json --output reports/github-pr-comment.md
```

---

## Supported Security Engines

| Security Dimension | Engine / Tool | Capability |
| :--- | :--- | :--- |
| **Secret Detection** | Gitleaks, TruffleHog | Hardcoded credentials, private keys, API tokens |
| **Fast SAST** | Semgrep | High-speed AST rules and security guardrails |
| **Deep SAST** | GitHub CodeQL | Semantic data-flow and taint tracking |
| **Code Quality & SAST**| SonarQube | Maintainability, security hotspots, code smells |
| **Container Security** | Hadolint | Dockerfile best practices and security linting |
| **IaC Security** | Checkov | Terraform, Bicep, ARM, and CloudFormation auditing |
| **Kubernetes Schema** | Kubeconform | Kubernetes API schema validation |
| **Policy-as-Code** | Kyverno CLI | Kubernetes policy validation |
| **K8s Hardening Audit**| Native Python Engine | Embedded Pod Security Standards inspector |
| **SCA / CVE Scanning** | Aqua Trivy, OWASP Dependency-Check | Open-source dependency vulnerability analysis |
| **SBOM Generation** | Syft | CycloneDX & SPDX software bill of materials |
| **Supply Chain Security**| Cosign (Sigstore) | Cryptographic signature and attestation verification |
| **DAST & Service Probe**| OWASP ZAP, Nmap | Headless baseline scan & active port scanning |
| **API Contract Security**| Schemathesis | Property-based OpenAPI / Swagger contract fuzzer |
| **Mobile Security** | MobSF | Mobile application static analysis |

---

## CI/CD Pipeline Integration (GitHub Actions Example)

```yaml
name: DevSecOps Autonomous Pipeline

on:
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install DevSecPac
        run: pip install -e .

      - name: Run Security Scan
        run: devsec scan . --json devsec-report.json --md devsec-summary.md

      - name: Generate PR Comment
        if: always()
        run: devsec pr-comment --json devsec-report.json --output pr-comment.md

      - name: Post Comment to PR
        if: always() && github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: pr-comment.md
```

---

## License
MIT (c) Fahad Shaikh
