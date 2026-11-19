# 🛡️ devsecpac: Universal Autonomous DevSecOps Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows | Linux | macOS](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](#)

A cross-platform Python CLI package that scans any codebase, container, and infrastructure configuration across 14 security dimensions with a single command:

```bash
devsecpac scan .
# or
devsec scan .
```

---

## 🌟 Features

- **One-Command Full Spectrum Scan:** Scans secrets, Dockerfiles, IaC, Kubernetes manifests, package dependencies (SCA), and generates SBOMs.
- **Graceful Tool Degradation:** Missing tools or non-applicable technologies (e.g. no Dockerfiles) are automatically marked as `SKIPPED` or `NOT_APPLICABLE` without breaking your build or pipeline.
- **Embedded Kubernetes Security Inspector:** Native Python inspection for Pod Security Standards (detects root user, privileged mode, `hostPath` mounts, and resource limit omissions) without external binary dependencies.
- **Standardized Contract (`status.json`):** Emits unified JSON and executive Markdown summaries ready for terminal view, GitHub summary tabs, or Azure DevOps Pipeline Summary.
- **Cross-Platform:** Runs natively on **Windows**, **Linux**, and **macOS**, seamlessly locating system binaries with `.exe` / PATH resolution.

---

## 📦 Installation

### Option 1: Install Locally in Editable Mode
```bash
pip install -e .
```

### Option 2: Install Direct from Git Repository
```bash
pip install git+https://github.com/<your-username>/devsec-cli.git
```

### Option 3: Build & Install Wheel
```bash
python -m pip install --upgrade build
python -m build
pip install dist/*.whl
```

---

## 🚀 Quick Usage

### 1. Check Tool Availability on Your System
```bash
devsec info
```
Outputs which scanners are installed on your PATH and ready to run.

### 2. Scan the Current Directory
```bash
devsecpac scan .
```

### 3. Scan Any Remote Git Repository (GitHub, GitLab, Azure DevOps, Bitbucket)
```bash
# Public repository via HTTPS (Full Git history across all branches)
devsecpac scan -r https://github.com/octocat/Hello-World.git

# Enterprise / Private repo via SSH
devsecpac scan -r git@gitlab.com:org/payment-service.git

# Azure DevOps / Private repo with PAT (zero process-table leakage)
devsecpac scan -r https://dev.azure.com/org/proj/_git/repo --token $AZURE_PAT --branch main
```

### 4. Scan with Custom Report Outputs
```bash
devsecpac scan /path/to/repo --json my-report.json --md executive-summary.md
```

### 5. Strict Quality Gate (Fail on Medium issues too)
```bash
devsecpac scan -r https://github.com/org/repo.git --strict
```

---

## 🛠️ Supported Scanners & Capabilities

| Security Dimension | Scanner / Engine | Missing Tool Behavior |
| :--- | :--- | :--- |
| **Secret Detection** | Gitleaks + TruffleHog | `SKIPPED` if not installed |
| **Container Linting** | Hadolint | `NOT_APPLICABLE` if no Dockerfiles |
| **IaC & Manifests** | Checkov | `NOT_APPLICABLE` if no IaC files |
| **K8s Schema** | Kubeconform | `NOT_APPLICABLE` if no K8s manifests |
| **SCA & Filesystem** | Aqua Trivy + OWASP Dependency-Check | `SKIPPED` if not installed |
| **SBOM Generation** | Syft (CycloneDX & SPDX) | `SKIPPED` if not installed |
| **K8s Hardening Audit**| **Native Embedded Python Engine** | Always runs (zero dependencies) |

---

## 📄 License
MIT © Fahad Shaikh
